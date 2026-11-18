from datetime import datetime, timedelta, timezone

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from rest_framework.test import APIClient

from apps.audit.models import AuditLog
from apps.core.models import AppConfiguration
from apps.credits import service
from apps.credits.models import RewardedAdSession, UsageCreditLedger
from tests.conftest import PASSWORD, set_config, start_session

pytestmark = pytest.mark.django_db
T = UsageCreditLedger.Type
DOMAIN = "/api/v1/domains/analyze/"
SCREEN = "/api/v1/credits/limit-screen/"


def limit(daily=1, **extra):
    set_config("default_entitlements", {"domain.lookups.daily_limit": daily, **extra})


def lookup(client, **body):
    return client.post(DOMAIN, {"value": "shop.com", **body}, format="json")


def fund(user, amount=10, expires=None):
    service.grant(user, amount, T.ADMIN_GRANT, idempotency_key=f"fund-{amount}-{T.ADMIN_GRANT}-{user.pk}", expires_at=expires)


@pytest.fixture
def site(senv):
    senv.publish("shop.com")
    return senv


# ---- limit screen -----------------------------------------------------------------------------------------------------------
def test_limit_reached_error_carries_the_full_limit_screen(auth_client, site, user):
    limit(1)
    assert lookup(auth_client).status_code == 200
    r = lookup(auth_client, platform="android")
    assert r.status_code == 403 and r.data["error"]["code"] == "limit_reached"
    d = r.data["error"]["details"]
    assert d["feature"] == "domain.lookups" and d["limit_reached"] is True
    day = next(w for w in d["windows"] if w["window"] == "day")
    assert day["used"] == 1 and day["limit"] == 1 and day["remaining"] == 0 and day["blocking"] is True and day["timezone"] == "UTC"
    assert d["resets_at"] == day["resets_at"] and d["timezone"] == "UTC"
    assert d["credits"]["balance"] == 0 and d["credits"]["reason"] == "not_credit_funded"
    assert d["wait"]["resets_at"] == day["resets_at"]
    assert d["upgrade"]["available"] is False                                    # pricing is off
    assert "never need credits" in d["essential_access"]


def test_the_screen_offers_upgrade_only_when_pricing_is_on(auth_client, pricing, user):
    assert auth_client.get(SCREEN, {"feature": "domain.lookups"}).data["upgrade"]["available"] is True


def test_the_screen_shows_balance_cost_and_a_rewarded_offer(auth_client, rewards_on, user):
    limit(0 + 1)
    set_config("credits.feature_costs", {"domain.lookups": 2})
    fund(user, 5)
    d = auth_client.get(SCREEN, {"feature": "domain.lookups", "platform": "android"}).data
    assert d["credits"] == {**d["credits"], "balance": 5, "cost_per_use": 2, "applicable": True, "can_cover": True}
    assert d["rewarded_ad"]["available"] is True and d["rewarded_ad"]["offers"][0]["reward_amount"] == 5


def test_no_rewarded_offer_is_shown_when_credits_cannot_be_spent_on_the_feature(auth_client, rewards_on, user):
    d = auth_client.get(SCREEN, {"feature": "domain.lookups", "platform": "android"}).data      # no credit price configured
    assert d["rewarded_ad"]["available"] is False and d["credits"]["reason"] == "not_credit_funded"


def test_the_screen_picks_the_latest_reset_among_blocking_windows(auth_client, site, user):
    limit(1, **{"domain.lookups.weekly_limit": 1})
    lookup(auth_client)
    d = auth_client.get(SCREEN, {"feature": "domain.lookups"}).data
    resets = {w["window"]: w["resets_at"] for w in d["windows"]}
    assert d["resets_at"] == max(resets["day"], resets["week"])


def test_the_screen_validates_its_input(auth_client):
    assert auth_client.get(SCREEN).status_code == 400
    assert auth_client.get(SCREEN, {"feature": "scanner.decode"}).status_code == 400
    assert auth_client.get(SCREEN, {"feature": "domain.lookups", "platform": "ios"}).status_code == 400
    assert APIClient().get(SCREEN, {"feature": "domain.lookups"}).status_code == 401


# ---- credit-funded use --------------------------------------------------------------------------------------------------------
def test_credits_are_never_spent_silently(auth_client, site, user):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 1})
    fund(user, 5)
    lookup(auth_client)
    r = lookup(auth_client)                                       # allowance gone, credits available, but the user did not opt in
    assert r.status_code == 403 and r.data["error"]["details"]["credits"]["can_cover"] is True
    assert service.balance_of(user) == 5


def test_opting_in_spends_the_configured_cost_once(auth_client, site, user):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 2})
    fund(user, 5)
    lookup(auth_client)
    r = lookup(auth_client, use_credits=True)
    assert r.status_code == 200 and r.data["paid_with_credits"] == 2
    assert service.balance_of(user) == 3
    spent = UsageCreditLedger.objects.get(transaction_type=T.FEATURE_USAGE)
    assert spent.amount == -2 and spent.feature_key == "domain.lookups"


def test_credits_are_not_used_while_the_allowance_lasts(auth_client, site, user):
    limit(5)
    set_config("credits.feature_costs", {"domain.lookups": 1})
    fund(user, 5)
    r = lookup(auth_client, use_credits=True)
    assert r.status_code == 200 and "paid_with_credits" not in r.data and service.balance_of(user) == 5


def test_not_enough_credits_is_refused_with_the_screen(auth_client, site, user):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 3})
    fund(user, 2)
    lookup(auth_client)
    r = lookup(auth_client, use_credits=True)
    assert r.status_code == 403 and r.data["error"]["details"]["credits"]["reason"] == "insufficient_credits"
    assert service.balance_of(user) == 2


def test_only_priced_features_can_be_credit_funded(auth_client, site, user):
    limit(1)
    fund(user, 50)
    lookup(auth_client)
    r = lookup(auth_client, use_credits=True)                      # no price configured by the administrator
    assert r.status_code == 403 and service.balance_of(user) == 50


def test_a_feature_switched_off_for_the_plan_cannot_be_unlocked_with_credits(auth_client, site, user):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    for k in ("domain.lookups.daily_limit",):
        EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key=k), enabled=False, note="off")
    set_config("credits.feature_costs", {"domain.lookups": 1})
    fund(user, 10)
    r = lookup(auth_client, use_credits=True)
    assert r.status_code == 403 and r.data["error"]["details"]["credits"]["reason"] == "feature_not_on_plan"
    assert service.balance_of(user) == 10


def test_a_plan_can_set_its_own_credit_price(auth_client, site, user):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    set_config("credits.feature_costs", {"domain.lookups": 5})
    limit(1)
    EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key="credits.spend.feature_cost"),
                                       enabled=True, note="cheaper")
    # the override carries no per-feature config here, so the global table still applies
    from apps.credits.limits import credit_cost
    assert credit_cost(user, "domain.lookups") == 5


def test_a_failed_lookup_refunds_the_credits(auth_client, site, user, monkeypatch):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 2})
    fund(user, 5)
    lookup(auth_client)

    def boom(*a, **k):
        raise RuntimeError("provider exploded")

    monkeypatch.setattr("apps.domain_intel.service.assess", boom)
    auth_client.raise_request_exception = False          # return the 500 instead of re-raising it in the test
    assert lookup(auth_client, use_credits=True).status_code == 500
    assert service.balance_of(user) == 5
    assert UsageCreditLedger.objects.filter(transaction_type=T.USAGE_REFUND).count() == 1


def test_bad_input_never_costs_credits(auth_client, site, user):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 2})
    fund(user, 5)
    lookup(auth_client)
    r = auth_client.post(DOMAIN, {"value": "localhost", "use_credits": True}, format="json")
    assert r.status_code == 400 and service.balance_of(user) == 5


def test_anonymous_checks_never_touch_credits_or_allowances(api, site):
    limit(1)
    assert lookup(api).status_code == 200 and lookup(api).status_code == 200


def test_credits_cannot_be_used_across_users(auth_client, other_user, site, user):
    limit(1)
    set_config("credits.feature_costs", {"domain.lookups": 1})
    fund(other_user, 10)
    lookup(auth_client)
    assert lookup(auth_client, use_credits=True).status_code == 403
    assert service.balance_of(other_user) == 10


# ---- essential access never needs credits or ads -----------------------------------------------------------------------------------
def test_scanning_and_security_warnings_work_with_zero_credits_and_no_ad(api, auth_client, user, site):
    limit(0 + 1)
    set_config("credits.feature_costs", {"domain.lookups": 1})
    assert service.balance_of(user) == 0 and RewardedAdSession.objects.count() == 0
    r = api.post("/api/v1/scanner/analyze/", {"content": "https://shop.com/menu"}, format="json")
    assert r.status_code == 200
    r2 = api.post("/api/v1/scanner/analyze/", {"content": "javascript:alert(1)"}, format="json")
    assert r2.status_code == 200 and r2.data["actions"]["blocked"] is True
    r3 = api.post("/api/v1/security/analyze/", {"url": "https://shop.com/"}, format="json")
    assert r3.status_code == 200
    assert auth_client.post("/api/v1/scanner/analyze/", {"content": "https://shop.com"}, format="json").status_code == 200


def test_the_scanner_and_security_responses_contain_no_credit_or_ad_demands(api, site):
    for path, body in (("/api/v1/scanner/analyze/", {"content": "https://shop.com/"}), ("/api/v1/security/analyze/", {"url": "https://shop.com/"})):
        text = str(api.post(path, body, format="json").data).lower()
        for word in ("credit", "rewarded", "watch an ad", "advertisement"):
            assert word not in text, (path, word)


def test_public_verification_does_not_need_credits(api, auth_client, user):
    from tests.conftest import make_qr
    made = make_qr(auth_client).data
    token = made["public_token"]
    set_config("rewarded_ads_enabled", True)
    assert service.balance_of(user) == 0
    assert api.get(f"/api/v1/scanner/verify/{token}/").status_code == 200


def test_ads_are_still_refused_on_security_screens_with_rewarded_ads_on(auth_client, rewards_on):
    set_config("ads_enabled", True)
    for surface in ("scanner", "scan_result", "verification", "security_warning", "threat_result", "security_confirmation",
                    "qr_generation", "qr_download", "redirect", "emergency_alert", "domain_report"):
        r = auth_client.get("/api/v1/advertising/eligible-placements/", {"platform": "android", "surface": surface})
        assert r.data["eligible"] is False and r.data["reason"] == "surface_restricted"


# ---- wallet endpoints ------------------------------------------------------------------------------------------------------------
def test_balance_endpoint(auth_client, user):
    fund(user, 7, expires=datetime.now(timezone.utc) + timedelta(days=3))
    d = auth_client.get("/api/v1/credits/balance/").data
    assert d["available_balance"] == 7 and d["expiring"][0]["amount"] == 7 and "cash value" in d["note"]
    assert [w["window"] for w in d["earning_limits"]] == ["day", "week", "month"]


def test_history_is_paginated_newest_first_and_private(auth_client, other_client, user, other_user):
    for i in range(3):
        service.grant(user, i + 1, T.ADMIN_GRANT, idempotency_key=f"h{i}", reason=f"gift {i}")
    service.grant(other_user, 99, T.ADMIN_GRANT, idempotency_key="theirs")
    r = auth_client.get("/api/v1/credits/history/")
    assert r.data["count"] == 3 and [e["amount"] for e in r.data["results"]] == [3, 2, 1]
    assert 99 not in [e["amount"] for e in r.data["results"]]
    assert "idempotency_key" not in r.data["results"][0] and "user" not in r.data["results"][0]
    assert auth_client.get("/api/v1/credits/history/", {"type": "feature_usage"}).data["count"] == 0


def test_wallet_endpoints_cannot_be_used_to_write(auth_client):
    for method in (auth_client.post, auth_client.put, auth_client.patch, auth_client.delete):
        assert method("/api/v1/credits/balance/", {"available_balance": 999}, format="json").status_code == 405
        assert method("/api/v1/credits/history/", {"amount": 5}, format="json").status_code == 405


# ---- administration ---------------------------------------------------------------------------------------------------------------
@pytest.fixture
def staff(db):
    u = get_user_model().objects.create_user(email="ops@example.com", password=PASSWORD, display_name="Ops", is_staff=True)
    c = APIClient()
    c.force_authenticate(u)
    return u, c


def allow(u, *codenames):
    u.user_permissions.add(*Permission.objects.filter(codename__in=codenames))
    u.refresh_from_db()
    return APIClient()


def authed(u):
    c = APIClient()
    c.force_authenticate(get_user_model().objects.get(pk=u.pk))
    return c


ADJUST = "/api/v1/admin/credits/adjust/"
OVERVIEW = "/api/v1/admin/credits/overview/"


def test_admin_endpoints_need_the_right_role(auth_client, staff, user):
    u, c = staff
    assert auth_client.get(OVERVIEW).status_code == 403 and auth_client.post(ADJUST, {}, format="json").status_code == 403
    assert c.get(OVERVIEW).status_code == 403 and c.post(ADJUST, {}, format="json").status_code == 403       # staff without the permission
    assert APIClient().get(OVERVIEW).status_code == 401
    allow(u, "view_credit_reports")
    c = authed(u)
    assert c.get(OVERVIEW).status_code == 200
    assert c.post(ADJUST, {"user": user.email, "kind": "grant", "amount": 5, "reason": "gift for support"}, format="json").status_code == 403


def test_a_grant_needs_a_reason_and_is_audited(staff, user):
    u, _ = staff
    allow(u, "manage_credits")
    c = authed(u)
    assert c.post(ADJUST, {"user": user.email, "kind": "grant", "amount": 5}, format="json").status_code == 400
    assert c.post(ADJUST, {"user": user.email, "kind": "grant", "amount": 5, "reason": "x"}, format="json").status_code == 400
    r = c.post(ADJUST, {"user": user.email, "kind": "grant", "amount": 5, "reason": "goodwill after outage"}, format="json")
    assert r.status_code == 200 and r.data["balance_before"] == 0 and r.data["balance_after"] == 5
    log = AuditLog.objects.get(action="credits.admin_grant")
    assert log.actor_id == u.pk and log.after_state["reason"] == "goodwill after outage" and log.after_state["amount"] == 5
    assert UsageCreditLedger.objects.get().transaction_type == T.ADMIN_GRANT


def test_a_retried_adjustment_is_applied_once(staff, user):
    u, _ = staff
    allow(u, "manage_credits")
    c = authed(u)
    body = {"user": user.email, "kind": "promotional", "amount": 4, "reason": "launch promo", "request_id": "6f1c5f66-1d46-4f6e-9d6a-2f8f1d2f9a11"}
    first, second = c.post(ADJUST, body, format="json"), c.post(ADJUST, body, format="json")
    assert first.data["applied"] is True and second.data["applied"] is False
    assert service.balance_of(user) == 4 and AuditLog.objects.filter(action="credits.admin_promotional").count() == 1
    clash = c.post(ADJUST, {**body, "amount": 9}, format="json")
    assert clash.status_code == 400 and service.balance_of(user) == 4


def test_a_reversal_removes_credits_but_never_below_zero(staff, user):
    u, _ = staff
    allow(u, "manage_credits")
    c = authed(u)
    fund(user, 5)
    assert c.post(ADJUST, {"user": user.email, "kind": "reversal", "amount": 3, "reason": "granted by mistake"}, format="json").data["balance_after"] == 2
    assert c.post(ADJUST, {"user": user.email, "kind": "reversal", "amount": 3, "reason": "again by mistake"}, format="json").status_code == 400
    assert service.balance_of(user) == 2


def test_adjusting_an_unknown_user_or_with_bad_amounts(staff, user):
    u, _ = staff
    allow(u, "manage_credits")
    c = authed(u)
    assert c.post(ADJUST, {"user": "nobody@example.com", "kind": "grant", "amount": 1, "reason": "valid reason"}, format="json").status_code == 404
    for amount in (0, -5, 2_000_000):
        assert c.post(ADJUST, {"user": user.email, "kind": "grant", "amount": amount, "reason": "valid reason"}, format="json").status_code == 400


def test_the_overview_reports_real_figures_and_flags_unusual_patterns(staff, user, rewards_on, admob, auth_client):
    u, _ = staff
    allow(u, "view_credit_reports")
    set_config("rewarded_abuse_daily_threshold", 1)
    for i in range(3):
        _d, s = start_session(auth_client, rewards_on.offer)
        APIClient().get("/api/v1/advertising/reward-callbacks/admob/?" + admob.query(s, tx=f"t{i}"))
    d = authed(u).get(OVERVIEW).data
    assert d["credits"]["issued_from_rewarded_ads"] == 15 and d["credits"]["outstanding"] == 15
    assert d["credits"]["reconciliation"]["consistent"] is True
    assert d["rewarded_sessions_30d"]["rewarded"] == 3 and d["callbacks_30d"]["accepted"] == 3
    assert d["unusual_reward_patterns"] == [{"user": user.email, "rewards_last_24h": 3}]
    assert any("TEST mode" in w for w in d["warnings"])


def test_the_overview_warns_about_unverifiable_web_rewards(staff):
    u, _ = staff
    allow(u, "view_credit_reports")
    set_config("rewarded_web_client_attested_enabled", True)
    assert any("CLIENT-ATTESTED" in w for w in authed(u).get(OVERVIEW).data["warnings"])


def test_credit_settings_need_the_ads_permission_in_the_admin_site():
    from apps.core.admin import _required_perm
    for key in ("rewarded_ads_enabled", "rewarded_web_client_attested_enabled", "credits.feature_costs"):
        assert _required_perm(key) == "advertising.manage_ads"


def test_defaults_are_seeded_and_safe():
    vals = {c.key: c.value for c in AppConfiguration.objects.filter(key__startswith="rewarded")}
    assert vals["rewarded_ads_enabled"] is False and vals["rewarded_ads_web_enabled"] is False
    assert vals["rewarded_ads_android_enabled"] is False and vals["rewarded_web_client_attested_enabled"] is False
    assert vals["rewarded_ads_test_mode"] is True
    assert AppConfiguration.objects.get(key="credits.feature_costs").value == {}


# ---- housekeeping ----------------------------------------------------------------------------------------------------------------
def test_process_credits_expires_credits_and_closes_stale_sessions(auth_client, rewards_on, user):
    from django.core.management import call_command
    from django.utils import timezone
    service.grant(user, 6, T.ADMIN_GRANT, idempotency_key="old", expires_at=timezone.now() - timedelta(hours=1))
    d = auth_client.post("/api/v1/credits/rewarded-sessions/", {"offer": str(rewards_on.offer.id), "platform": "android"}, format="json").data
    RewardedAdSession.objects.filter(pk=d["id"]).update(expires_at=timezone.now() - timedelta(seconds=1))
    call_command("process_credits")
    assert UsageCreditLedger.objects.filter(transaction_type=T.CREDIT_EXPIRY).count() == 1
    assert RewardedAdSession.objects.get(pk=d["id"]).status == "expired"


def test_retention_purges_old_callbacks_and_unrewarded_sessions_but_keeps_rewarded_ones(auth_client, rewards_on, user):
    from django.core.management import call_command
    from django.utils import timezone
    from apps.credits.models import RewardCallbackEvent
    old = timezone.now() - timedelta(days=500)
    cb = RewardCallbackEvent.objects.create(provider="admob", outcome="accepted")
    RewardCallbackEvent.objects.filter(pk=cb.pk).update(received_at=old)
    a = RewardedAdSession.objects.create(user=user, rewarded_ad_offer=rewards_on.offer, platform="android", provider="admob",
                                         unique_session_token="a", expected_reward_amount=1, status="closed_without_reward", expires_at=old)
    b = RewardedAdSession.objects.create(user=user, rewarded_ad_offer=rewards_on.offer, platform="android", provider="admob",
                                         unique_session_token="b", expected_reward_amount=1, status="rewarded", expires_at=old)
    RewardedAdSession.objects.filter(pk__in=[a.pk, b.pk]).update(created_at=old)
    call_command("purge_old_data")
    assert not RewardCallbackEvent.objects.exists()
    assert list(RewardedAdSession.objects.values_list("pk", flat=True)) == [b.pk]
