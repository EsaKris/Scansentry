import json
from datetime import timedelta
from decimal import Decimal

import pytest
from django.utils import timezone as djtz
from rest_framework.test import APIClient

from apps.audit.models import AuditLog
from apps.billing.models import PaymentTransaction, PaymentWebhookEvent, Subscription, SubscriptionEvent
from apps.core.entitlements import feature_enabled, get_limit
from apps.core.models import AppConfiguration
from apps.notifications.models import Notification
from tests.billing_sim import FlutterwaveSim, post_webhook, ps_event, sign_paystack

pytestmark = pytest.mark.django_db
S = Subscription.Status
CHECKOUT = "/api/v1/billing/checkout/"


@pytest.fixture
def shop(plans, pricing, ps):
    return ps


def start(client, plan="pro", currency="NGN"):
    return client.post(CHECKOUT, {"plan": plan, "currency": currency}, format="json").data["reference"]


def charge(ref, ident=1001, **over):
    data = dict(id=ident, reference=ref, status="success", amount=500000, currency="NGN",
                customer={"customer_code": "CUS_abc", "email": "ada@example.com"},
                authorization={"last4": "4081", "bin": "408408", "signature": "SIG_x", "card_type": "visa"})
    data.update(over)
    return ps_event("charge.success", **data)


def wh(client, payload, **kw):
    return post_webhook(client, "paystack", payload, **kw)


def events():
    return PaymentWebhookEvent.objects.all()


# ---- authenticity --------------------------------------------------------------------------------------------------------
def test_requests_with_a_bad_or_missing_signature_are_rejected_and_leave_no_trace(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    good = json.dumps(charge(ref)).encode()
    cases = [dict(signature="0" * 128), dict(signature=""), dict(signature=sign_paystack(b"other body", "sk_test_secret")),
             dict(secret="sk_test_WRONG")]
    for c in cases:
        r = wh(api, None, raw=good, **c)
        assert r.status_code == 401, c
    r = api.post("/api/v1/billing/webhooks/paystack/", data=good, content_type="application/json")        # header absent
    assert r.status_code == 401
    assert events().count() == 0 and PaymentTransaction.objects.get().status == "pending" and not feature_enabled(user, "ads.remove")
    assert shop.requests[-1][1].startswith("/transaction/initialize")                                       # provider never even asked


def test_valid_signature_is_accepted(api, auth_client, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    assert wh(api, charge(ref)).status_code == 200


def test_unknown_and_unconfigured_providers(api, auth_client, shop, settings):
    assert post_webhook(api, "stripe", {"event": "x"}).status_code == 404
    assert post_webhook(api, "nonsense", {"event": "x"}).status_code == 404
    settings.PAYSTACK_SECRET_KEY = ""
    assert wh(api, charge("r"), secret="anything").status_code == 404          # no secret configured: nothing can be trusted
    assert api.get("/api/v1/billing/webhooks/paystack/").status_code == 405


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'"str"', b'{"data": {}}', b'{"event": "charge.success"}', b'{"event": "", "data": {}}'])
def test_malformed_signed_payloads_are_rejected(api, shop, raw):
    assert wh(api, None, raw=raw).status_code == 400 and events().count() == 0


def test_oversized_payloads_are_rejected(api, shop):
    assert wh(api, None, raw=b"{" + b" " * 300_000 + b"}").status_code == 413


def test_the_endpoint_needs_no_login_cookie_or_csrf_token(api, shop):
    client = APIClient(enforce_csrf_checks=True)
    assert wh(client, charge("unknown-ref")).status_code == 200


# ---- crediting through webhooks ---------------------------------------------------------------------------------------------------
def test_a_valid_charge_success_is_re_verified_with_the_provider_and_credited(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    r = wh(api, charge(ref))
    assert r.status_code == 200 and r.data == {"status": "processed"}
    assert PaymentTransaction.objects.get().status == "success" and Subscription.objects.get().status == S.ACTIVE
    assert feature_enabled(user, "ads.remove") and get_limit(user, "qr.dynamic.active_limit") == 100
    assert any(p.startswith("/transaction/verify/") for _m, p, _h in shop.requests)         # it asked the provider
    ev = events().get()
    assert ev.processing_status == "processed" and ev.event_type == "charge.success" and ev.provider_event_id == "charge.success:1001" and ev.processed_at


def test_duplicate_deliveries_never_double_credit(api, auth_client, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    wh(api, charge(ref))
    end = Subscription.objects.get().current_period_end
    for _ in range(3):
        r = wh(api, charge(ref))
        assert r.status_code == 200 and r.data == {"status": "duplicate"}
    assert Subscription.objects.get().current_period_end == end and events().count() == 1 and PaymentTransaction.objects.filter(status="success").count() == 1


def test_the_same_payment_arriving_under_a_different_event_id_still_credits_once(api, auth_client, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    wh(api, charge(ref, ident=1001))
    end = Subscription.objects.get().current_period_end
    assert wh(api, charge(ref, ident=2002)).status_code == 200
    assert Subscription.objects.get().current_period_end == end and PaymentTransaction.objects.count() == 1


def test_webhook_and_client_verification_together_credit_once(api, auth_client, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    auth_client.post("/api/v1/billing/checkout/verify/", {"reference": ref}, format="json")
    end = Subscription.objects.get().current_period_end
    wh(api, charge(ref))
    assert Subscription.objects.get().current_period_end == end


def test_a_signed_webhook_cannot_override_what_the_provider_api_says(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000", status="failed")                         # webhook claims success; the provider's own record says failed
    assert wh(api, charge(ref)).status_code == 200
    assert PaymentTransaction.objects.get().status == "failed" and not feature_enabled(user, "ads.remove")


def test_a_webhook_for_a_payment_the_provider_has_not_confirmed_is_retried_later(api, auth_client, user, shop):
    ref = start(auth_client)                                          # provider has no result yet
    r = wh(api, charge(ref))
    assert r.status_code == 503 and events().get().processing_status == "failed" and not feature_enabled(user, "ads.remove")
    shop.result(ref, "5000")                                          # the provider catches up; the redelivery succeeds
    r = wh(api, charge(ref))
    assert r.status_code == 200 and r.data == {"status": "processed"} and feature_enabled(user, "ads.remove")
    assert events().get().attempts == 2 and events().get().processing_status == "processed"


def test_tampered_amounts_are_caught_by_the_provider_check(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "100")                                           # provider says only 100 NGN was paid
    r = wh(api, charge(ref, amount=500000))                           # the webhook body claims the full price
    assert r.status_code == 200 and r.data == {"status": "failed"}
    assert PaymentTransaction.objects.get().status == "failed" and not feature_enabled(user, "ads.remove")
    assert events().get().processing_status == "failed" and "mismatch" in events().get().error_message
    assert AuditLog.objects.filter(action="billing.payment_mismatch").exists()


def test_provider_outages_ask_for_a_retry_and_recover(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    shop.mode["verify"] = 503
    assert wh(api, charge(ref)).status_code == 503
    assert events().get().processing_status == "failed" and not feature_enabled(user, "ads.remove")
    shop.mode.clear()
    assert wh(api, charge(ref)).data == {"status": "processed"} and feature_enabled(user, "ads.remove")


def test_permanent_provider_errors_are_not_retried_forever(api, auth_client, shop):
    ref = start(auth_client)
    shop.mode["verify"] = 401                                          # our credentials were rejected: retrying will not help
    r = wh(api, charge(ref))
    assert r.status_code == 200 and r.data == {"status": "failed"}


def test_retries_stop_after_the_attempt_limit(api, auth_client, shop):
    ref = start(auth_client)
    shop.mode["verify"] = 503
    for _ in range(8):
        assert wh(api, charge(ref)).status_code == 503
    r = wh(api, charge(ref))
    assert r.status_code == 200 and r.data == {"status": "gave_up"} and events().get().attempts == 8


def test_charges_we_know_nothing_about_are_ignored(api, shop):
    r = wh(api, charge("someone-elses-ref", customer={"customer_code": "CUS_unknown", "email": "x@y.z"}))
    assert r.status_code == 200 and r.data == {"status": "ignored"} and PaymentTransaction.objects.count() == 0


def test_payments_still_complete_after_pricing_is_switched_off(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    AppConfiguration.objects.filter(key="pricing_enabled").update(value=False)       # money was already taken: honour it
    assert wh(api, charge(ref)).data == {"status": "processed"}
    assert get_limit(user, "qr.dynamic.active_limit") == 100


# ---- provider-managed renewals -----------------------------------------------------------------------------------------------------------
@pytest.fixture
def subscriber(user, plans, shop):
    plans.pro.provider_refs = {"paystack_plan_code": "PLN_pro"}
    plans.pro.save()
    now = djtz.now()
    return Subscription.objects.create(user=user, plan=plans.pro, status=S.ACTIVE, billing_provider="paystack", currency="NGN",
                                       external_customer_reference="CUS_abc", external_subscription_reference="SUB_1",
                                       started_at=now - timedelta(days=25), current_period_start=now - timedelta(days=25),
                                       current_period_end=now + timedelta(days=5))


def renewal(ref="renew-1", ident=3001, **over):
    return charge(ref, ident, **over)


def test_a_provider_renewal_charge_extends_the_subscription(api, subscriber, shop):
    old_end = subscriber.current_period_end
    shop.result("renew-1", "5000", plan_code="PLN_pro")
    assert wh(api, renewal()).data == {"status": "processed"}
    sub = Subscription.objects.get()
    assert 28 <= (sub.current_period_end - old_end).days <= 31
    tx = PaymentTransaction.objects.get()
    assert tx.provider_reference == "renew-1" and tx.amount == Decimal("5000.00") and tx.status == "success" and tx.plan.slug == "pro"
    assert wh(api, renewal(ident=3002)).status_code == 200                       # same charge redelivered under another event id
    assert Subscription.objects.get().current_period_end == sub.current_period_end and PaymentTransaction.objects.count() == 1


def test_renewal_amounts_must_match_the_current_database_price(api, subscriber, shop):
    old_end = subscriber.current_period_end
    shop.result("renew-1", "1000", plan_code="PLN_pro")
    r = wh(api, renewal())
    assert r.data == {"status": "failed"} and Subscription.objects.get().current_period_end == old_end
    assert PaymentTransaction.objects.count() == 0 and AuditLog.objects.filter(action="billing.payment_mismatch").exists()


@pytest.mark.parametrize("scenario", ["other_plan", "no_price_in_currency", "not_success", "unknown_customer", "no_reference"])
def test_unmappable_renewals_are_never_credited(api, subscriber, shop, scenario):
    old_end = subscriber.current_period_end
    kw = {}
    if scenario == "other_plan":
        shop.result("renew-1", "5000", plan_code="PLN_other")
    elif scenario == "no_price_in_currency":
        shop.result("renew-1", "5000", currency="GHS", plan_code="PLN_pro")
        kw = dict(currency="GHS")
    elif scenario == "not_success":
        shop.result("renew-1", "5000", status="failed", plan_code="PLN_pro")
    elif scenario == "unknown_customer":
        shop.result("renew-1", "5000", customer="CUS_zzz", plan_code="PLN_pro")
        kw = dict(customer={"customer_code": "CUS_zzz", "email": "z@z.z"})
    else:
        kw = dict(reference="")
    r = wh(api, renewal(**kw))
    assert r.status_code == 200 and r.data["status"] in ("ignored", "failed")
    assert Subscription.objects.get().current_period_end == old_end and PaymentTransaction.objects.count() == 0


# ---- other provider events --------------------------------------------------------------------------------------------------------------------
def test_subscription_create_links_the_provider_subscription_without_storing_the_email(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    wh(api, charge(ref))
    Subscription.objects.update(external_subscription_reference="", external_customer_reference="")
    r = wh(api, ps_event("subscription.create", subscription_code="SUB_9", customer={"customer_code": "CUS_9", "email": user.email.upper()},
                         plan={"plan_code": "PLN_pro"}))
    assert r.data == {"status": "processed"}
    sub = Subscription.objects.get()
    assert sub.external_subscription_reference == "SUB_9" and sub.external_customer_reference == "CUS_9"
    ev = events().get(event_type="subscription.create")
    assert user.email.lower() not in json.dumps(ev.payload).lower() and ev.payload["subscription_code"] == "SUB_9"
    assert wh(api, ps_event("subscription.create", subscription_code="SUB_8", customer={"customer_code": "C", "email": "nobody@x.y"})).data == {"status": "ignored"}


def test_a_failed_provider_invoice_marks_past_due_but_keeps_access(api, subscriber, user, shop):
    r = wh(api, ps_event("invoice.payment_failed", invoice_code="INV_1", customer={"customer_code": "CUS_abc", "email": user.email}))
    assert r.data == {"status": "processed"} and Subscription.objects.get().status == S.PAST_DUE
    assert feature_enabled(user, "ads.remove")                                    # never cut off for one failed charge
    n = Notification.objects.get(user=user, kind="billing.payment_failed")
    assert n.severity == "warning" and "access continues" in n.body
    assert wh(api, ps_event("invoice.payment_failed", invoice_code="INV_2", customer={"customer_code": "CUS_abc"})).data == {"status": "ignored"}


def test_a_later_successful_payment_recovers_a_past_due_subscription(api, subscriber, user, shop):
    Subscription.objects.update(status=S.PAST_DUE)
    shop.result("renew-1", "5000", plan_code="PLN_pro")
    wh(api, renewal())
    assert Subscription.objects.get().status == S.ACTIVE


def test_provider_side_cancellation_keeps_access_until_the_period_end(api, subscriber, user, shop):
    r = wh(api, ps_event("subscription.disable", subscription_code="SUB_1", status="complete"))
    assert r.data == {"status": "processed"}
    sub = Subscription.objects.get()
    assert sub.status == S.CANCELLED and sub.cancel_at_period_end and feature_enabled(user, "ads.remove")
    assert wh(api, ps_event("subscription.disable", subscription_code="SUB_404")).data == {"status": "ignored"}


def paid(api, auth_client, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    wh(api, charge(ref))
    return ref


def test_refunds_revoke_access_by_default_and_are_idempotent(api, auth_client, user, shop):
    ref = paid(api, auth_client, shop)
    assert wh(api, ps_event("refund.processed", id=7, transaction_reference=ref, status="processed")).data == {"status": "processed"}
    assert PaymentTransaction.objects.get().status == "refunded"
    assert Subscription.objects.get().status == S.EXPIRED and not feature_enabled(user, "ads.remove")
    assert SubscriptionEvent.objects.filter(event_type="refunded", detail__access_revoked=True).exists()
    wh(api, ps_event("refund.processed", id=8, transaction_reference=ref))                  # a second event for the same refund
    assert SubscriptionEvent.objects.filter(event_type="refunded").count() == 1
    assert wh(api, ps_event("refund.processed", id=9, transaction_reference="nope")).data == {"status": "ignored"}


def test_refund_policy_is_configurable(api, auth_client, user, shop):
    AppConfiguration.objects.create(key="billing.refund_revokes_access", value=False)
    ref = paid(api, auth_client, shop)
    wh(api, ps_event("refund.processed", id=7, transaction_reference=ref))
    assert PaymentTransaction.objects.get().status == "refunded" and feature_enabled(user, "ads.remove")


def test_unknown_event_types_are_acknowledged_and_ignored(api, shop):
    r = wh(api, ps_event("customeridentification.success", id=5))
    assert r.data == {"status": "ignored"} and events().get().processing_status == "ignored"


def test_stored_webhook_payloads_hold_only_whitelisted_non_sensitive_fields(api, auth_client, user, shop):
    ref = start(auth_client)
    shop.result(ref, "5000")
    wh(api, charge(ref))
    stored = json.dumps(events().get().payload)
    for leak in ("4081", "408408", "SIG_x", "visa", "ada@example.com", "authorization", "email"):
        assert leak not in stored, leak
    assert set(events().get().payload) <= {"reference", "transaction_reference", "status", "amount", "currency", "channel",
                                           "customer_code", "subscription_code", "plan_code"}


# ---- Flutterwave webhooks ---------------------------------------------------------------------------------------------------------------------------
@pytest.fixture
def fw(senv, plans, pricing, pay_settings):
    AppConfiguration.objects.create(key="billing.enabled_providers", value=["paystack", "flutterwave"])
    return FlutterwaveSim(senv)


def fw_event(ref, ident=55, **over):
    d = dict(id=ident, tx_ref=ref, status="successful", amount=5000, currency="NGN", payment_type="card")
    d.update(over)
    return {"event": "charge.completed", "data": d}


def test_flutterwave_webhook_requires_the_secret_hash_and_re_verifies(api, auth_client, user, fw):
    ref = auth_client.post(CHECKOUT, {"plan": "pro", "currency": "NGN", "provider": "flutterwave"}, format="json").data["reference"]
    fw.result(ref, "5000.00")
    assert post_webhook(api, "flutterwave", fw_event(ref), signature="wrong").status_code == 401
    assert post_webhook(api, "flutterwave", fw_event(ref), signature="").status_code == 401
    assert not feature_enabled(user, "ads.remove")
    r = post_webhook(api, "flutterwave", fw_event(ref))
    assert r.data == {"status": "processed"} and feature_enabled(user, "ads.remove")
    assert post_webhook(api, "flutterwave", fw_event(ref)).data == {"status": "duplicate"}


def test_flutterwave_amount_mismatch_is_refused(api, auth_client, user, fw):
    ref = auth_client.post(CHECKOUT, {"plan": "pro", "currency": "NGN", "provider": "flutterwave"}, format="json").data["reference"]
    fw.result(ref, "50.00")
    assert post_webhook(api, "flutterwave", fw_event(ref)).data == {"status": "failed"} and not feature_enabled(user, "ads.remove")
