import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.utils import timezone as djtz
from rest_framework.test import APIClient

from apps.audit.models import AuditLog
from apps.billing.models import (EntitlementOverride, FeatureDefinition, PaymentTransaction, PaymentWebhookEvent, Plan, PlanFeature,
                                 PlanPrice, Subscription, SubscriptionEvent)
from apps.core.entitlements import feature_enabled, get_limit
from apps.core.models import AppConfiguration
from apps.notifications.models import Notification
from tests.conftest import PASSWORD, make_plan, make_qr

pytestmark = pytest.mark.django_db
S = Subscription.Status
User = get_user_model()


def staff(email, perms=(), superuser=False):
    u = User.objects.create_user(email, PASSWORD, is_staff=True, is_superuser=superuser, email_verified=True)
    for code in perms:
        u.user_permissions.add(Permission.objects.get(codename=code))
    c = APIClient()
    tok = c.post("/api/v1/auth/login/", {"email": email, "password": PASSWORD}).data["access"]
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {tok}")
    c.user = u
    return c


def sub_for(user, plan, status=S.ACTIVE, **kw):
    now = djtz.now()
    d = dict(plan=plan, status=status, current_period_start=now - timedelta(days=5), current_period_end=now + timedelta(days=25))
    d.update(kw)
    return Subscription.objects.create(user=user, **d)


OVERRIDES = "/api/v1/admin/billing/overrides/"
NOTE = "approved by support ticket 481"

ENDPOINTS = [  # (method, path, perm)
    ("get", "/api/v1/admin/billing/overview/", "view_payments"),
    ("get", "/api/v1/admin/billing/webhook-events/", "view_payments"),
    ("post", OVERRIDES, "grant_entitlements"),
    ("post", "/api/v1/admin/billing/overrides/1/revoke/", "grant_entitlements"),
    ("post", "/api/v1/admin/billing/subscriptions/extend/", "manage_subscriptions"),
    ("post", "/api/v1/admin/billing/subscriptions/suspend/", "manage_subscriptions"),
    ("post", "/api/v1/admin/billing/subscriptions/restore/", "manage_subscriptions"),
]


# ---- role-based permissions ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("method,path,perm", ENDPOINTS)
def test_admin_endpoints_enforce_roles(api, auth_client, method, path, perm):
    call = lambda c: getattr(c, method)(path, {} if method == "post" else None, format="json")
    assert call(api).status_code == 401                                                     # anonymous
    assert call(auth_client).status_code == 403                                             # ordinary user
    assert call(staff("nobody@example.com")).status_code == 403                             # staff without any billing permission
    others = [p for p in ("view_payments", "grant_entitlements", "manage_subscriptions", "manage_pricing") if p != perm]
    assert call(staff("wrong@example.com", others)).status_code == 403                      # every OTHER permission is not enough
    assert call(staff("right@example.com", [perm])).status_code != 403                      # the right one passes the gate
    assert call(staff("root@example.com", superuser=True)).status_code != 403


def test_a_non_staff_user_with_the_permission_is_still_refused(auth_client, user):
    user.user_permissions.add(Permission.objects.get(codename="grant_entitlements"))
    assert auth_client.post(OVERRIDES, {}, format="json").status_code == 403


def test_inactive_staff_are_refused(plans):
    c = staff("gone@example.com", ["view_payments"])
    User.objects.filter(email="gone@example.com").update(is_active=False)
    assert c.get("/api/v1/admin/billing/overview/").status_code in (401, 403)


# ---- notes and audit -----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("note", ["", "   ", "abc", None])
def test_every_administrative_change_requires_an_internal_note(user, plans, note):
    sub_for(user, plans.pro)
    admin = staff("root@example.com", superuser=True)
    body = {"user": user.email, "note": note} if note is not None else {"user": user.email}
    cases = [(OVERRIDES, {**body, "feature": "qr.pdf_export"}), (OVERRIDES, {**body, "kind": "plan_trial", "plan": "pro", "days": 5}),
             ("/api/v1/admin/billing/subscriptions/extend/", {**body, "days": 5}),
             ("/api/v1/admin/billing/subscriptions/suspend/", body)]
    for path, payload in cases:
        r = admin.post(path, payload, format="json")
        assert r.status_code == 400 and "note" in json.dumps(r.data), (path, note)
    assert EntitlementOverride.objects.count() == 0 and Subscription.objects.get().status == S.ACTIVE
    assert not AuditLog.objects.filter(action__startswith="billing.").exists()


def test_grants_are_audited_with_actor_and_note_and_recorded_in_history(user, plans):
    admin = staff("root@example.com", superuser=True)
    r = admin.post(OVERRIDES, {"user": user.email, "feature": "qr.dynamic.active_limit", "limit": 250, "note": NOTE}, format="json")
    assert r.status_code == 201
    a = AuditLog.objects.get(action="billing.override_granted")
    assert a.actor_id == admin.user.id and a.after_state["note"] == NOTE and a.after_state["limit"] == 250
    h = SubscriptionEvent.objects.get(event_type="override_granted")
    assert h.actor_id == admin.user.id and h.user_id == user.id and h.detail["feature"] == "qr.dynamic.active_limit"
    o = EntitlementOverride.objects.get()
    assert o.note == NOTE and o.created_by_id == admin.user.id


# ---- overrides ---------------------------------------------------------------------------------------------------------------------
def test_feature_grant_promotion_and_revocation_change_what_the_user_can_do(user, other_user, plans, auth_client):
    admin = staff("root@example.com", ["grant_entitlements"])
    assert get_limit(user, "qr.dynamic.active_limit") == 3
    r = admin.post(OVERRIDES, {"user": str(user.pk), "feature": "qr.dynamic.active_limit", "limit": 250, "note": NOTE,
                               "expires_at": (djtz.now() + timedelta(days=30)).isoformat()}, format="json")
    oid = r.data["id"]
    assert get_limit(user, "qr.dynamic.active_limit") == 250 and get_limit(other_user, "qr.dynamic.active_limit") == 3
    for _ in range(5):
        assert make_qr(auth_client).status_code == 201                                       # past the plan's limit of 3
    promo = admin.post(OVERRIDES, {"user": user.email, "kind": "promotion", "feature": "ads.remove", "note": "launch promo"}, format="json")
    assert promo.status_code == 201 and feature_enabled(user, "ads.remove")
    assert admin.post(OVERRIDES, {"user": user.email, "feature": "qr.svg_export", "enabled": False, "note": "abuse review"}, format="json").status_code == 201
    assert feature_enabled(user, "qr.svg_export") is False
    rv = admin.post(f"/api/v1/admin/billing/overrides/{oid}/revoke/", {"note": "support case closed"}, format="json")
    assert rv.status_code == 200 and get_limit(user, "qr.dynamic.active_limit") == 3
    o = EntitlementOverride.objects.get(pk=oid)
    assert o.revoked_at and o.revoked_by_id == admin.user.id and o.revoke_note == "support case closed"
    assert admin.post(f"/api/v1/admin/billing/overrides/{oid}/revoke/", {"note": "again please"}, format="json").status_code == 409
    assert admin.post("/api/v1/admin/billing/overrides/99999/revoke/", {"note": "does not exist"}, format="json").status_code == 404
    assert AuditLog.objects.filter(action="billing.override_revoked").count() == 1


def test_temporary_premium_plan_access(user, plans):
    admin = staff("root@example.com", ["grant_entitlements"])
    r = admin.post(OVERRIDES, {"user": user.email, "kind": "plan_trial", "plan": "pro", "days": 14, "note": "partner pilot"}, format="json")
    assert r.status_code == 201 and get_limit(user, "qr.dynamic.active_limit") == 100 and feature_enabled(user, "ads.remove")
    assert 13 <= (EntitlementOverride.objects.get().expires_at - djtz.now()).days <= 14
    assert Notification.objects.filter(user=user, title="You have been given Pro access").exists()
    assert AuditLog.objects.filter(action="billing.plan_access_granted").exists()


@pytest.mark.parametrize("payload,field", [
    ({"feature": "no.such.feature"}, "feature"), ({}, "feature"),
    ({"feature": "qr.pdf_export", "expires_at": "2020-01-01T00:00:00Z"}, "expires_at"),
    ({"feature": "qr.dynamic.active_limit", "limit": -3}, "limit"),
    ({"kind": "plan_trial", "plan": "nope", "days": 5}, "plan"), ({"kind": "plan_trial", "plan": "pro"}, "plan"),
    ({"kind": "plan_trial", "plan": "pro", "days": 0}, "days"), ({"kind": "bogus", "feature": "qr.pdf_export"}, "kind"),
])
def test_invalid_grants_are_rejected(user, plans, payload, field):
    admin = staff("root@example.com", superuser=True)
    r = admin.post(OVERRIDES, {"user": user.email, "note": NOTE, **payload}, format="json")
    assert r.status_code == 400 and field in json.dumps(r.data) and EntitlementOverride.objects.count() == 0


def test_unknown_users_are_404(plans):
    admin = staff("root@example.com", superuser=True)
    for who in ("ghost@example.com", "00000000-0000-0000-0000-000000000000", "not-a-uuid"):
        assert admin.post(OVERRIDES, {"user": who, "feature": "qr.pdf_export", "note": NOTE}, format="json").status_code == 404


# ---- extend / suspend / restore --------------------------------------------------------------------------------------------------------
def act(admin, what, user, **kw):
    return admin.post(f"/api/v1/admin/billing/subscriptions/{what}/", {"user": user.email, "note": NOTE, **kw}, format="json")


def test_extending_an_active_subscription_adds_time_from_its_end(user, plans):
    sub = sub_for(user, plans.pro)
    end = sub.current_period_end
    r = act(staff("m@example.com", ["manage_subscriptions"]), "extend", user, days=30)
    assert r.status_code == 200 and (Subscription.objects.get().current_period_end - end) == timedelta(days=30)
    e = SubscriptionEvent.objects.get(event_type="extended")
    assert e.actor.email == "m@example.com" and e.detail["days"] == 30
    a = AuditLog.objects.get(action="billing.subscription_extended")
    assert a.after_state["note"] == NOTE and a.before_state["status"] == "active"


def test_extending_an_expired_subscription_reactivates_it_from_now(user, plans):
    sub_for(user, plans.pro, status=S.EXPIRED, current_period_end=djtz.now() - timedelta(days=60))
    act(staff("root@example.com", superuser=True), "extend", user, days=10)
    sub = Subscription.objects.get()
    assert sub.status == S.ACTIVE and 9 <= (sub.current_period_end - djtz.now()).days <= 10 and feature_enabled(user, "ads.remove")


def test_extending_past_due_and_trial_subscriptions(user, plans):
    sub_for(user, plans.pro, status=S.PAST_DUE)
    act(staff("root@example.com", superuser=True), "extend", user, days=5)
    assert Subscription.objects.get().status == S.ACTIVE
    Subscription.objects.update(status=S.TRIALING, trial_ends_at=djtz.now() + timedelta(days=2), current_period_end=djtz.now() + timedelta(days=2))
    act(staff("root2@example.com", superuser=True), "extend", user, days=7)
    sub = Subscription.objects.get()
    assert sub.trial_ends_at == sub.current_period_end and (sub.trial_ends_at - djtz.now()).days >= 8


def test_extend_needs_a_subscription_and_valid_days(user, plans):
    admin = staff("root@example.com", superuser=True)
    assert act(admin, "extend", user, days=5).status_code == 404                       # nothing to extend: grant access instead
    sub_for(user, plans.pro)
    assert act(admin, "extend", user).status_code == 400
    assert act(admin, "extend", user, days=0).status_code == 400 and act(admin, "extend", user, days=4000).status_code == 400


def test_suspend_removes_access_and_restore_returns_it(user, plans):
    sub_for(user, plans.pro)
    admin = staff("root@example.com", ["manage_subscriptions"])
    assert feature_enabled(user, "ads.remove")
    assert act(admin, "suspend", user).data["status"] == "suspended" and not feature_enabled(user, "ads.remove")
    assert act(admin, "restore", user).data["status"] == "active" and feature_enabled(user, "ads.remove")
    assert act(admin, "restore", user).status_code == 409                                # not suspended any more
    Subscription.objects.update(status=S.SUSPENDED, current_period_end=djtz.now() - timedelta(days=1))
    assert act(admin, "restore", user).data["status"] == "expired"                      # cannot resurrect a lapsed period
    assert AuditLog.objects.filter(action="billing.subscription_suspended").count() == 1
    assert act(admin, "suspend", User.objects.create_user("n@example.com", PASSWORD)).status_code == 404


# ---- reporting -------------------------------------------------------------------------------------------------------------------------
def test_overview_reports_verified_revenue_and_provider_status(user, other_user, plans, pricing, pay_settings):
    sub_for(user, plans.pro)
    sub_for(other_user, plans.starter, status=S.GRACE_PERIOD)
    now = djtz.now()
    mk = lambda st, amt, cur, days=1: PaymentTransaction.objects.create(
        user=user, plan=plans.pro, provider="paystack", provider_reference=f"r{PaymentTransaction.objects.count()}", amount=amt, currency=cur,
        status=st, paid_at=now - timedelta(days=days))
    mk("success", "5000.00", "NGN"); mk("success", "5000.00", "NGN", days=60); mk("success", "5.00", "USD")
    mk("refunded", "5000.00", "NGN"); mk("failed", "5000.00", "NGN"); mk("pending", "5000.00", "NGN")
    PaymentWebhookEvent.objects.create(provider="paystack", provider_event_id="e1", processing_status="failed")
    PaymentWebhookEvent.objects.create(provider="paystack", provider_event_id="e2", processing_status="processed")
    r = staff("fin@example.com", ["view_payments"]).get("/api/v1/admin/billing/overview/")
    d = r.data
    assert d["pricing_enabled"] is True and d["subscriptions_by_status"] == {"active": 1, "grace_period": 1}
    assert d["revenue_all_time"] == {"NGN": "10000.00", "USD": "5.00"} and d["revenue_last_30_days"] == {"NGN": "5000.00", "USD": "5.00"}
    assert d["refunded_transactions"] == 1 and d["webhook_events_failed"] == 1
    prov = {p["key"]: p for p in d["providers"]}
    assert prov["paystack"]["configured"] and prov["paystack"]["enabled"] and "NGN" in prov["paystack"]["currencies"]
    assert prov["flutterwave"]["enabled"] is False and prov["stripe"]["implemented"] is False and "Google Play Billing" in prov["google_play"]["note"]
    assert "sk_test_secret" not in json.dumps(d)


def test_webhook_event_review_endpoint(plans):
    PaymentWebhookEvent.objects.create(provider="paystack", provider_event_id="e1", event_type="charge.success", processing_status="failed", error_message="mismatch")
    PaymentWebhookEvent.objects.create(provider="paystack", provider_event_id="e2", event_type="charge.success", processing_status="processed")
    c = staff("fin@example.com", ["view_payments"])
    assert c.get("/api/v1/admin/billing/webhook-events/").data["count"] == 2
    r = c.get("/api/v1/admin/billing/webhook-events/?status=failed")
    assert r.data["count"] == 1 and r.data["results"][0]["error_message"] == "mismatch" and "payload" not in r.data["results"][0]


# ---- Django admin (role-based) -------------------------------------------------------------------------------------------------------------
def admin_client(client, user):
    client.force_login(user)
    return client


def test_admin_pages_load_for_superusers(client, plans, user):
    sub_for(user, plans.pro)
    su = User.objects.create_superuser("root@example.com", PASSWORD)
    admin_client(client, su)
    for model in ("plan", "featuredefinition", "subscription", "subscriptionevent", "paymenttransaction", "paymentwebhookevent", "entitlementoverride"):
        assert client.get(f"/admin/billing/{model}/").status_code == 200, model
    assert client.get(f"/admin/billing/plan/{plans.pro.pk}/change/").status_code == 200
    assert client.get("/admin/billing/subscription/add/").status_code == 403         # read-only: changes go through the audited service
    assert client.get(f"/admin/billing/subscription/{Subscription.objects.get().pk}/change/").status_code in (200, 403)


def grant(user, *codenames, app=None):
    for c in codenames:
        user.user_permissions.add(Permission.objects.get(codename=c))


def test_plan_administration_needs_the_pricing_permission_not_just_model_rights(client, plans):
    u = User.objects.create_user("ops@example.com", PASSWORD, is_staff=True)
    grant(u, "view_plan", "change_plan", "add_plan")
    admin_client(client, u)
    url = f"/admin/billing/plan/{plans.pro.pk}/change/"
    page = client.get(url)
    assert b'name="_save"' not in page.content                                                  # shown read-only: no save button
    assert client.post(url, {"name": "Hacked", "slug": "pro"}).status_code == 403              # and saving is refused
    assert Plan.objects.get(slug="pro").name == "Pro"
    grant(u, "manage_pricing")
    admin_client(client, User.objects.get(pk=u.pk))
    assert b'name="_save"' in client.get(url).content


def test_pricing_switches_are_protected_and_every_config_change_is_audited(client, plans, pricing):
    u = User.objects.create_user("ops@example.com", PASSWORD, is_staff=True)
    grant(u, "view_appconfiguration", "change_appconfiguration")
    admin_client(client, u)
    pricing_row = AppConfiguration.objects.get(key="pricing_enabled")
    other_row = AppConfiguration.objects.create(key="brand_color", value="#000", is_public=True)
    prow_url = f"/admin/core/appconfiguration/{pricing_row.pk}/change/"
    assert client.post(prow_url, {"key": "pricing_enabled", "value": "false", "description": "", "is_public": "on"}).status_code == 403
    assert AppConfiguration.objects.get(key="pricing_enabled").value is True                    # the pricing switch did not move
    assert client.get(f"/admin/core/appconfiguration/{other_row.pk}/change/").status_code == 200
    r = client.post(f"/admin/core/appconfiguration/{other_row.pk}/change/", {"key": "brand_color", "value": '"#111"', "description": "", "is_public": "on"})
    assert r.status_code == 302
    a = AuditLog.objects.get(action="config.changed")
    assert a.actor_id == u.id and '#111' in a.after_state["value"] and '#000' in a.before_state["value"]
    grant(u, "manage_pricing")
    admin_client(client, User.objects.get(pk=u.pk))
    r2 = client.post(prow_url, {"key": "pricing_enabled", "value": "false", "description": "", "is_public": "on"})
    assert r2.status_code == 302 and AppConfiguration.objects.get(key="pricing_enabled").value is False


def test_entitlement_grants_in_the_admin_need_a_note_and_are_audited(client, user, plans):
    su = User.objects.create_superuser("root@example.com", PASSWORD)
    admin_client(client, su)
    feat = FeatureDefinition.objects.get(key="qr.pdf_export")
    base = {"user": user.pk, "kind": "feature", "feature": feat.pk, "enabled": "on", "limit_value": ""}
    bad = client.post("/admin/billing/entitlementoverride/add/", {**base, "note": "abc"})
    assert bad.status_code == 200 and b"internal note of at least 5 characters" in bad.content and EntitlementOverride.objects.count() == 0
    ok = client.post("/admin/billing/entitlementoverride/add/", {**base, "note": "goodwill gesture, ticket 77"})
    assert ok.status_code == 302
    o = EntitlementOverride.objects.get()
    assert o.created_by_id == su.id and AuditLog.objects.filter(action="billing.override_saved", actor=su).exists()


def test_plan_changes_in_the_admin_are_audited(client, db):
    su = User.objects.create_superuser("root@example.com", PASSWORD)
    admin_client(client, su)
    plan = make_plan("promo", "Promo", is_free=True)
    r = client.post(f"/admin/billing/plan/{plan.pk}/change/", {
        "name": "Promo", "slug": "promo", "description": "New description", "status": "active", "is_public": "on", "is_free": "on",
        "billing_interval": "month", "trial_days": 0, "grace_period_days": 0, "display_order": 4, "provider_refs": "{}",
        "prices-TOTAL_FORMS": 0, "prices-INITIAL_FORMS": 0, "features-TOTAL_FORMS": 0, "features-INITIAL_FORMS": 0})
    assert r.status_code == 302
    assert Plan.objects.get(slug="promo").description == "New description"
    a = AuditLog.objects.get(action="billing.plan_saved")
    assert a.actor_id == su.id and "description" in a.after_state


# ---- acceptance scenarios 9 and 10: no code change needed -----------------------------------------------------------------------------------------
def test_scenario_9_an_administrator_launches_pricing_without_a_deployment(api, auth_client, user, ps, pay_settings):
    assert api.get("/api/v1/plans/").data["plans"] == []                                  # fresh install: nothing for sale
    # the product owner, in the admin: switch pricing on, create a plan, a price and its entitlements
    AppConfiguration.objects.filter(key="pricing_enabled").update(value=True)
    plan = make_plan("growth", "Growth", ngn="7500.00", usd="7.50", order=5, features={"qr.dynamic.active_limit": (True, 40), "ads.remove": (True, None)})
    page = api.get("/api/v1/plans/")
    growth = next(p for p in page.data["plans"] if p["slug"] == "growth")
    assert growth["prices"][0] == {"currency": "NGN", "amount": "7500.00"} and page.data["purchase_enabled"]
    r = auth_client.post("/api/v1/billing/checkout/", {"plan": "growth", "currency": "NGN"}, format="json")
    assert r.status_code == 200 and r.data["amount"] == "7500.00" and ps.initialized[0]["amount"] == 750000
    ps.result(r.data["reference"], "7500.00")
    auth_client.post("/api/v1/billing/checkout/verify/", {"reference": r.data["reference"]}, format="json")
    assert get_limit(user, "qr.dynamic.active_limit") == 40 and feature_enabled(user, "ads.remove")
    # the owner edits the plan: the new limit applies immediately, enforced by the backend
    PlanFeature.objects.filter(plan=plan, feature__key="qr.dynamic.active_limit").update(limit_value=2)
    assert get_limit(user, "qr.dynamic.active_limit") == 2
    assert make_qr(auth_client).status_code == 201 and make_qr(auth_client).status_code == 201
    assert make_qr(auth_client).status_code == 403


def test_scenario_10_switching_pricing_off_hides_purchasing_but_preserves_everything(api, auth_client, other_client, user, other_user, ps, pay_settings):
    AppConfiguration.objects.filter(key="pricing_enabled").update(value=True)
    make_plan("growth", "Growth", ngn="7500.00", order=5, features={"qr.dynamic.active_limit": (True, 40)})
    free = Plan.objects.get(slug="free")
    PlanFeature.objects.create(plan=free, feature=FeatureDefinition.objects.get(key="qr.dynamic.active_limit"), limit_value=3)
    r = auth_client.post("/api/v1/billing/checkout/", {"plan": "growth", "currency": "NGN"}, format="json")
    ps.result(r.data["reference"], "7500.00")
    auth_client.post("/api/v1/billing/checkout/verify/", {"reference": r.data["reference"]}, format="json")
    # switch off
    AppConfiguration.objects.filter(key="pricing_enabled").update(value=False)
    assert api.get("/api/v1/plans/").data == {"pricing_enabled": False, "purchase_enabled": False, "plans": []}
    assert other_client.post("/api/v1/billing/checkout/", {"plan": "growth", "currency": "NGN"}, format="json").status_code == 403
    assert auth_client.post("/api/v1/billing/checkout/", {"plan": "growth", "currency": "NGN"}, format="json").status_code == 403
    assert get_limit(user, "qr.dynamic.active_limit") == 40                                # the paying customer keeps what they bought
    assert get_limit(other_user, "qr.dynamic.active_limit") == 3                            # everyone else gets the configured fallback
    assert PaymentTransaction.objects.filter(status="success").count() == 1 and Subscription.objects.count() == 1      # nothing deleted
    assert auth_client.get("/api/v1/billing/transactions/").data["count"] == 1
    assert auth_client.get("/api/v1/billing/subscription/").data["subscription"]["status"] == "active"
    assert api.get("/api/v1/config/").data["pricing_enabled"] is False                       # clients can hide purchase controls
