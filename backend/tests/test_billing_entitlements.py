from datetime import datetime, timedelta, timezone

import pytest
from django.core.management import call_command
from django.utils import timezone as djtz

from apps.billing import entitlements as E
from apps.billing.models import (EntitlementOverride, FeatureDefinition, Plan, PlanFeature, PlanPrice, Subscription)
from apps.billing.seed import CATALOGUE
from apps.billing.timeutil import add_interval
from apps.core.entitlements import feature_enabled, get_limit
from apps.core.models import AppConfiguration
from tests.conftest import make_plan, make_qr

pytestmark = pytest.mark.django_db
S = Subscription.Status


def sub_for(user, plan, status=S.ACTIVE, **kw):
    now = djtz.now()
    defaults = dict(plan=plan, status=status, current_period_start=now - timedelta(days=5), current_period_end=now + timedelta(days=25))
    defaults.update(kw)
    return Subscription.objects.create(user=user, **defaults)


# ---- defaults / seeding -------------------------------------------------------------------------------------------------
def test_catalogue_free_plan_and_pricing_switch_are_seeded_without_commercial_values():
    assert {k for k, *_ in CATALOGUE} <= set(FeatureDefinition.objects.values_list("key", flat=True))
    assert FeatureDefinition.objects.count() == len(CATALOGUE)
    free = Plan.objects.get(slug="free")
    assert free.is_free and free.prices.count() == 0 and free.features.count() == 0       # no hardcoded limits
    cfg = AppConfiguration.objects.get(key="pricing_enabled")
    assert cfg.value is False and cfg.is_public is True                                   # pricing starts OFF


def test_with_nothing_configured_behaviour_is_unchanged(user):
    assert get_limit(user, "qr.dynamic.active_limit") is None and feature_enabled(user, "qr.svg_export") is True
    assert feature_enabled(user, "ads.remove") is False and feature_enabled(user, "api.access") is False   # off-by-default features
    assert feature_enabled(user, "some.unknown.key") is True and get_limit(user, "some.unknown.key") is None


def test_every_catalogue_feature_resolves_for_anonymous_users_too():
    ents = E.resolve_all(None)
    assert set(ents) >= {k for k, *_ in CATALOGUE}


def test_example_plans_command_is_idempotent_and_leaves_pricing_off(capsys):
    call_command("seed_example_plans")
    assert "Created 3 example plan(s)" in capsys.readouterr().out
    call_command("seed_example_plans")
    assert "Created 0 example plan(s)" in capsys.readouterr().out
    pro = Plan.objects.get(slug="pro")
    assert pro.prices.count() == 2 and "EXAMPLE" in pro.description
    assert AppConfiguration.objects.get(key="pricing_enabled").value is False


# ---- plans drive enforcement ------------------------------------------------------------------------------------------------
def test_free_plan_limits_are_enforced_by_the_backend(plans, auth_client):
    for _ in range(3):
        assert make_qr(auth_client).status_code == 201
    r = make_qr(auth_client)
    assert r.status_code == 403 and r.data["error"]["code"] == "limit_reached"


def test_a_paid_plan_raises_the_limit_and_losing_it_lowers_it_again(plans, user, auth_client):
    sub = sub_for(user, plans.pro)
    for _ in range(5):
        assert make_qr(auth_client).status_code == 201
    Subscription.objects.filter(pk=sub.pk).update(current_period_end=djtz.now() - timedelta(days=10))   # lapsed beyond grace
    assert get_limit(user, "qr.dynamic.active_limit") == 3
    assert make_qr(auth_client).status_code == 403


def test_plan_feature_flags_gate_features(plans, user, auth_client):
    qr = make_qr(auth_client, code_mode="static").data["id"]
    PlanFeature.objects.create(plan=plans.free, feature=FeatureDefinition.objects.get(key="qr.pdf_export"), enabled=False)
    assert auth_client.get(f"/api/v1/qr/{qr}/image/pdf/").status_code == 403
    sub_for(user, plans.pro)                                                # Pro enables pdf_export
    assert auth_client.get(f"/api/v1/qr/{qr}/image/pdf/").status_code == 200


def test_disabled_numeric_feature_means_zero_allowed(plans, user, auth_client):
    PlanFeature.objects.filter(plan=plans.free, feature__key="qr.dynamic.active_limit").update(enabled=False)
    assert get_limit(user, "qr.dynamic.active_limit") == 0 and make_qr(auth_client).status_code == 403


def test_ad_free_is_a_plan_entitlement(plans, user):
    assert feature_enabled(user, "ads.remove") is False
    sub_for(user, plans.pro)
    assert feature_enabled(user, "ads.remove") is True and E.resolve(user, "ads.remove").source == "plan:pro"


# ---- time-based access -------------------------------------------------------------------------------------------------------------
NOW = djtz.now()


@pytest.mark.parametrize("status,end_delta,trial_delta,grace,has", [
    (S.ACTIVE, +10, None, 0, True), (S.ACTIVE, -1, None, 0, False), (S.ACTIVE, -1, None, 3, True), (S.ACTIVE, -4, None, 3, False),
    (S.PAST_DUE, +5, None, 0, True), (S.PAST_DUE, -2, None, 3, True), (S.GRACE_PERIOD, -2, None, 3, True), (S.GRACE_PERIOD, -5, None, 3, False),
    (S.CANCELLED, +10, None, 3, True), (S.CANCELLED, -1, None, 3, False),          # cancelled: until period end, no grace
    (S.TRIALING, +10, +5, 3, True), (S.TRIALING, +10, -1, 3, False),
    (S.PENDING_PAYMENT, +10, None, 0, False), (S.EXPIRED, +10, None, 0, False), (S.SUSPENDED, +10, None, 0, False),
])
def test_access_rules(user, status, end_delta, trial_delta, grace, has):
    plan = make_plan("p", "P", ngn="1000", grace=grace)
    sub = Subscription(user=user, plan=plan, status=status, current_period_end=NOW + timedelta(days=end_delta),
                       trial_ends_at=(NOW + timedelta(days=trial_delta)) if trial_delta is not None else None)
    assert E.has_access(sub, NOW) is has


def test_cancelling_never_removes_paid_access_early(plans, user):
    sub_for(user, plans.pro, status=S.CANCELLED, cancel_at_period_end=True)
    assert E.effective_plan(user)[0].slug == "pro" and get_limit(user, "qr.dynamic.active_limit") == 100


def test_access_does_not_depend_on_the_lifecycle_job_having_run(plans, user, pricing):
    sub_for(user, plans.pro, status=S.ACTIVE, current_period_end=djtz.now() - timedelta(days=30))     # long past, job never ran
    assert E.effective_plan(user)[2] == "free_plan" and get_limit(user, "qr.dynamic.active_limit") == 3


# ---- layers / overrides ---------------------------------------------------------------------------------------------------------------
def test_legacy_baseline_is_overridden_by_plans_and_overrides(plans, user):
    AppConfiguration.objects.create(key="default_entitlements", value={"qr.dynamic.active_limit": 50, "qr.svg_export": False})
    assert get_limit(user, "qr.dynamic.active_limit") == 3            # the free plan outranks the global baseline
    assert feature_enabled(user, "qr.svg_export") is False and E.resolve(user, "qr.svg_export").source == "global_baseline"


def mk_override(user, admin_user=None, **kw):
    base = dict(user=user, kind="feature", note="support case 123", created_by=admin_user)
    base.update(kw)
    return EntitlementOverride.objects.create(**base)


def test_feature_overrides_win_over_the_plan_and_can_revoke(plans, user, other_user):
    f = FeatureDefinition.objects.get(key="qr.dynamic.active_limit")
    mk_override(user, feature=f, enabled=True, limit_value=500)
    assert get_limit(user, "qr.dynamic.active_limit") == 500 and E.resolve(user, "qr.dynamic.active_limit").source == "override:feature"
    assert get_limit(other_user, "qr.dynamic.active_limit") == 3          # other users unaffected
    mk_override(user, feature=FeatureDefinition.objects.get(key="qr.svg_export"), enabled=False)
    assert feature_enabled(user, "qr.svg_export") is False and feature_enabled(other_user, "qr.svg_export") is True


def test_expired_and_revoked_overrides_are_ignored(plans, user):
    f = FeatureDefinition.objects.get(key="qr.dynamic.active_limit")
    mk_override(user, feature=f, limit_value=500, expires_at=djtz.now() - timedelta(seconds=1))
    o = mk_override(user, feature=f, limit_value=700)
    assert get_limit(user, "qr.dynamic.active_limit") == 700
    EntitlementOverride.objects.filter(pk=o.pk).update(revoked_at=djtz.now())
    assert get_limit(user, "qr.dynamic.active_limit") == 3


def test_latest_override_for_a_feature_wins(plans, user):
    f = FeatureDefinition.objects.get(key="qr.dynamic.active_limit")
    mk_override(user, feature=f, limit_value=10)
    mk_override(user, feature=f, limit_value=20)
    assert get_limit(user, "qr.dynamic.active_limit") == 20


def test_temporary_premium_plan_access_overlays_the_plan_until_it_expires(plans, user):
    o = mk_override(user, kind="plan_trial", plan=plans.pro, expires_at=djtz.now() + timedelta(days=3))
    assert get_limit(user, "qr.dynamic.active_limit") == 100 and feature_enabled(user, "ads.remove") is True
    EntitlementOverride.objects.filter(pk=o.pk).update(expires_at=djtz.now() - timedelta(seconds=1))
    assert get_limit(user, "qr.dynamic.active_limit") == 3 and feature_enabled(user, "ads.remove") is False


def test_specific_grants_beat_a_premium_trial(plans, user):
    mk_override(user, kind="plan_trial", plan=plans.pro, expires_at=djtz.now() + timedelta(days=3))
    mk_override(user, feature=FeatureDefinition.objects.get(key="qr.dynamic.active_limit"), limit_value=7)
    assert get_limit(user, "qr.dynamic.active_limit") == 7 and feature_enabled(user, "ads.remove") is True


# ---- pricing switch policy ---------------------------------------------------------------------------------------------------------------------
def test_switching_pricing_off_keeps_paid_access_for_existing_subscribers(plans, user, other_user, pricing):
    sub_for(user, plans.pro)
    AppConfiguration.objects.filter(key="pricing_enabled").update(value=False)
    assert get_limit(user, "qr.dynamic.active_limit") == 100                      # paid access is never taken away
    assert E.effective_plan(user)[2] == "subscription"
    assert get_limit(other_user, "qr.dynamic.active_limit") == 3                  # everyone else: the configured fallback (free)


def test_pricing_disabled_fallback_can_be_a_promotional_plan(plans, user, other_user):
    promo = make_plan("promo", "Launch promo", order=9, features={"qr.dynamic.active_limit": (True, 50), "ads.remove": (True, None)}, is_free=True)
    AppConfiguration.objects.create(key="billing.pricing_disabled_plan_slug", value="promo")
    assert get_limit(other_user, "qr.dynamic.active_limit") == 50 and E.effective_plan(other_user)[2] == "pricing_disabled_policy"
    AppConfiguration.objects.update_or_create(key="pricing_enabled", defaults={"value": True})
    assert get_limit(other_user, "qr.dynamic.active_limit") == 3                  # promo only applies while pricing is off


def test_missing_free_plan_degrades_to_catalogue_defaults(user):
    Plan.objects.filter(slug="free").delete()
    assert E.effective_plan(user)[0] is None and get_limit(user, "qr.dynamic.active_limit") is None


# ---- the entitlements endpoint (same decision for web and Android) ----------------------------------------------------------------------------------
def test_entitlements_endpoint_reports_the_effective_decision(plans, user, auth_client):
    r = auth_client.get("/api/v1/billing/entitlements/")
    assert r.status_code == 200 and r.data["plan"] == "free" and r.data["reason"] == "pricing_disabled_policy"
    assert r.data["entitlements"]["qr.dynamic.active_limit"] == {"enabled": True, "limit": 3, "source": "plan:free"}
    assert r.data["entitlements"]["ads.remove"]["enabled"] is False
    sub_for(user, plans.pro)
    r = auth_client.get("/api/v1/billing/entitlements/")
    assert r.data["plan"] == "pro" and r.data["entitlements"]["ads.remove"]["enabled"] is True


def test_entitlements_require_authentication(api):
    assert api.get("/api/v1/billing/entitlements/").status_code == 401


# ---- public plans page -------------------------------------------------------------------------------------------------------------------------------------
def test_pricing_off_offers_nothing_for_purchase(api, plans):
    r = api.get("/api/v1/plans/")
    assert r.status_code == 200 and r.data == {"pricing_enabled": False, "purchase_enabled": False, "plans": []}


def test_pricing_on_lists_only_active_public_plans_with_prices_and_features(api, plans, pricing):
    make_plan("hidden", "Hidden", ngn="999", is_public=False)
    make_plan("old", "Old", ngn="999", status="inactive")
    r = api.get("/api/v1/plans/")
    assert r.data["pricing_enabled"] and [p["slug"] for p in r.data["plans"]] == ["free", "starter", "pro"]
    pro = next(p for p in r.data["plans"] if p["slug"] == "pro")
    assert pro["prices"] == [{"currency": "NGN", "amount": "5000.00"}, {"currency": "USD", "amount": "5.00"}]
    assert {"key": "qr.dynamic.active_limit", "name": "Active dynamic QR codes", "enabled": True, "limit": 100} in pro["features"]
    assert pro["trial_days"] == 7 and pro["billing_interval"] == "month" and "provider_refs" not in pro


def test_currency_filter_and_inactive_prices(api, plans, pricing):
    PlanPrice.objects.filter(plan=plans.pro, currency="USD").update(active=False)
    ngn = api.get("/api/v1/plans/?currency=NGN").data["plans"]
    assert {p["slug"] for p in ngn} >= {"starter", "pro"}
    usd = api.get("/api/v1/plans/?currency=USD").data["plans"]
    assert "pro" not in {p["slug"] for p in usd} and "starter" in {p["slug"] for p in usd}
    assert all(c["currency"] == "USD" for p in usd for c in p["prices"])


def test_prices_come_from_the_database_not_the_frontend(api, plans, pricing):
    PlanPrice.objects.filter(plan=plans.pro, currency="NGN").update(amount="6500.00")
    assert next(p for p in api.get("/api/v1/plans/").data["plans"] if p["slug"] == "pro")["prices"][0]["amount"] == "6500.00"


# ---- period arithmetic ------------------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("start,interval,expected", [
    (datetime(2026, 1, 31, tzinfo=timezone.utc), "month", datetime(2026, 2, 28, tzinfo=timezone.utc)),
    (datetime(2028, 1, 31, tzinfo=timezone.utc), "month", datetime(2028, 2, 29, tzinfo=timezone.utc)),
    (datetime(2026, 12, 15, tzinfo=timezone.utc), "month", datetime(2027, 1, 15, tzinfo=timezone.utc)),
    (datetime(2026, 11, 30, tzinfo=timezone.utc), "quarter", datetime(2027, 2, 28, tzinfo=timezone.utc)),
    (datetime(2028, 2, 29, tzinfo=timezone.utc), "year", datetime(2029, 2, 28, tzinfo=timezone.utc)),
    (datetime(2026, 11, 9, tzinfo=timezone.utc), "week", datetime(2026, 11, 16, tzinfo=timezone.utc)),
])
def test_add_interval(start, interval, expected):
    assert add_interval(start, interval) == expected
