import json
from datetime import timedelta
from decimal import Decimal

import pytest
from django.core import mail
from django.core.management import call_command
from django.utils import timezone as djtz

from apps.audit.models import AuditLog
from apps.billing import service
from apps.billing.entitlements import effective_plan, has_access
from apps.billing.models import PaymentTransaction, Plan, Subscription, SubscriptionEvent
from apps.billing.providers.base import VerifyResult
from apps.core.entitlements import feature_enabled, get_limit
from apps.core.models import AppConfiguration
from apps.notifications.models import Notification
from tests.billing_sim import FlutterwaveSim, PaystackSim
from tests.conftest import make_plan

pytestmark = pytest.mark.django_db
S = Subscription.Status
CHECKOUT = "/api/v1/billing/checkout/"
VERIFY = "/api/v1/billing/checkout/verify/"


@pytest.fixture
def shop(plans, pricing, ps):
    return ps


def checkout(client, plan="pro", currency="NGN", **extra):
    return client.post(CHECKOUT, {"plan": plan, "currency": currency, **extra}, format="json")


def pay(client, ps, plan="pro", currency="NGN", amount=None):
    """Run a full successful purchase: checkout -> provider confirms -> client verifies."""
    r = checkout(client, plan, currency)
    assert r.status_code == 200, r.data
    ref = r.data["reference"]
    ps.result(ref, amount if amount is not None else r.data["amount"], currency)
    v = client.post(VERIFY, {"reference": ref}, format="json")
    assert v.status_code == 200, v.data
    return ref, v


# ---- checkout --------------------------------------------------------------------------------------------------------------
def test_checkout_reads_the_price_from_the_database_and_ignores_anything_the_client_sends(auth_client, user, shop):
    r = checkout(auth_client, amount=1, price="0.01", currency_amount=1, total=1, discount=100)
    assert r.status_code == 200
    assert r.data["amount"] == "5000.00" and r.data["currency"] == "NGN" and r.data["provider"] == "paystack"
    assert r.data["authorization_url"] == f"https://checkout.paystack.com/{r.data['reference']}"
    sent = shop.initialized[0]
    assert sent["amount"] == 500000 and sent["currency"] == "NGN" and sent["email"] == user.email        # kobo
    assert sent["reference"] == r.data["reference"] and sent["callback_url"] == "https://app.scansentry.test/billing/complete"
    assert sent["metadata"]["plan"] == "pro" and sent["metadata"]["user_id"] == str(user.pk)
    assert set(sent["metadata"]) == {"user_id", "plan", "reference", "app"}
    tx = PaymentTransaction.objects.get()
    assert tx.amount == Decimal("5000.00") and tx.status == "pending" and tx.plan.slug == "pro"
    assert Subscription.objects.get().status == S.PENDING_PAYMENT and not has_access(Subscription.objects.get(), djtz.now())


def test_the_secret_key_is_sent_to_the_provider_only_in_a_header(auth_client, shop):
    checkout(auth_client)
    method, path, headers = shop.requests[0]
    assert headers["authorization"] == "Bearer sk_test_secret" and "sk_test_secret" not in path


def test_price_changes_in_the_admin_take_effect_immediately(auth_client, shop, plans):
    plans.pro.prices.filter(currency="NGN").update(amount="6500.00")
    assert checkout(auth_client).data["amount"] == "6500.00" and shop.initialized[0]["amount"] == 650000


def test_usd_checkout(auth_client, shop):
    r = checkout(auth_client, currency="usd")
    assert r.status_code == 200 and r.data["amount"] == "5.00" and shop.initialized[0]["amount"] == 500 and shop.initialized[0]["currency"] == "USD"


def test_checkout_is_blocked_while_pricing_is_off(auth_client, plans, ps):
    r = checkout(auth_client)
    assert r.status_code == 403 and r.data["error"]["code"] == "pricing_disabled"
    assert PaymentTransaction.objects.count() == 0 and Subscription.objects.count() == 0 and ps.initialized == []


@pytest.mark.parametrize("slug,extra", [("nope", {}), ("free", {}), ("hidden", {}), ("old", {})])
def test_unavailable_plans_cannot_be_bought(auth_client, shop, slug, extra):
    make_plan("hidden", "Hidden", ngn="1000", is_public=False)
    make_plan("old", "Old", ngn="1000", status="inactive")
    r = checkout(auth_client, slug)
    assert r.status_code == 404 and r.data["error"]["code"] == "plan_unavailable" and shop.initialized == []


def test_currency_must_be_sold_and_supported(auth_client, shop, plans):
    r = checkout(auth_client, currency="EUR")
    assert r.status_code == 400 and r.data["error"]["code"] == "currency_unavailable" and "NGN, USD" in r.data["error"]["message"]
    make_plan("odd", "Odd", ngn="100")
    from apps.billing.models import PlanPrice
    PlanPrice.objects.create(plan=Plan.objects.get(slug="odd"), currency="JPY", amount="500")
    r = checkout(auth_client, "odd", "JPY")
    assert r.status_code == 400 and r.data["error"]["code"] == "currency_unsupported"
    assert shop.initialized == []


def test_a_zero_or_negative_price_cannot_exist(db, plans):
    from django.db import IntegrityError, transaction
    from apps.billing.models import PlanPrice
    for amount in (0, -5):
        with pytest.raises(IntegrityError), transaction.atomic():
            PlanPrice.objects.create(plan=plans.pro, currency="GHS", amount=amount)


@pytest.mark.parametrize("provider,msg", [("stripe", "not available"), ("google_play", "not available"), ("nonsense", "not available"),
                                          ("flutterwave", "not available")])      # flutterwave isn't enabled by default
def test_unavailable_providers_are_refused(auth_client, shop, provider, msg):
    r = checkout(auth_client, provider=provider)
    assert r.status_code == 400 and r.data["error"]["code"] == "provider_unavailable" and msg in r.data["error"]["message"]


def test_an_unconfigured_provider_is_unavailable(auth_client, plans, pricing, settings):
    settings.PAYSTACK_SECRET_KEY = ""
    assert checkout(auth_client).data["error"]["code"] == "provider_unavailable"


@pytest.mark.parametrize("mode,code", [(503, 503), (500, 503), (400, 502)])
def test_provider_failures_when_starting_a_payment_are_reported_cleanly(auth_client, shop, mode, code):
    shop.mode["initialize"] = mode
    r = checkout(auth_client)
    assert r.status_code == code and r.data["error"]["code"] == "provider_error"
    assert PaymentTransaction.objects.get().status == "failed" and "init_failed" in PaymentTransaction.objects.get().failure_reason


def test_suspended_accounts_cannot_check_out(auth_client, user, shop, plans):
    Subscription.objects.create(user=user, plan=plans.pro, status=S.SUSPENDED, current_period_end=djtz.now() + timedelta(days=5))
    assert checkout(auth_client).status_code == 403


def test_checkout_requires_authentication(api, shop):
    assert api.post(CHECKOUT, {"plan": "pro", "currency": "NGN"}, format="json").status_code == 401
    assert api.post(VERIFY, {"reference": "x"}, format="json").status_code == 401


# ---- verification & crediting ----------------------------------------------------------------------------------------------
def test_a_confirmed_payment_activates_the_plan(auth_client, user, shop):
    ref, v = pay(auth_client, shop)
    assert v.data["status"] == "success" and v.data["subscription"]["status"] == "active" and v.data["effective_plan"]["slug"] == "pro"
    sub = Subscription.objects.get()
    assert sub.plan.slug == "pro" and sub.billing_provider == "paystack" and sub.currency == "NGN" and sub.external_customer_reference == "CUS_abc"
    assert 28 <= (sub.current_period_end - sub.current_period_start).days <= 31
    tx = PaymentTransaction.objects.get()
    assert tx.status == "success" and tx.verified_at and tx.payment_method == "card" and tx.subscription_id == sub.id
    assert get_limit(user, "qr.dynamic.active_limit") == 100 and feature_enabled(user, "ads.remove")
    assert SubscriptionEvent.objects.filter(event_type="payment_succeeded", detail__outcome="activated").exists()
    assert AuditLog.objects.filter(action="billing.payment_succeeded").exists()
    assert Notification.objects.filter(user=user, kind="billing.subscription_activated").exists()


def test_verifying_twice_never_credits_twice(auth_client, shop):
    ref, _ = pay(auth_client, shop)
    end = Subscription.objects.get().current_period_end
    for _ in range(3):
        assert auth_client.post(VERIFY, {"reference": ref}, format="json").status_code == 200
    assert Subscription.objects.get().current_period_end == end and PaymentTransaction.objects.filter(status="success").count() == 1


def test_apply_payment_success_is_idempotent_at_the_service_level(auth_client, user, shop):
    checkout(auth_client)
    tx = PaymentTransaction.objects.get()
    vr = VerifyResult("success", Decimal("5000.00"), "NGN", tx.provider_reference, "CUS_x", "card")
    assert service.apply_payment_success(tx, vr) is True
    end = Subscription.objects.get().current_period_end
    assert service.apply_payment_success(tx, vr) is False and Subscription.objects.get().current_period_end == end


def test_a_pending_payment_stays_pending_and_grants_nothing(auth_client, user, shop):
    ref = checkout(auth_client).data["reference"]
    shop.result(ref, "5000", status="ongoing")
    v = auth_client.post(VERIFY, {"reference": ref}, format="json")
    assert v.status_code == 200 and v.data["status"] == "pending" and v.data["subscription"]["has_access"] is False
    assert get_limit(user, "qr.dynamic.active_limit") == 3


@pytest.mark.parametrize("provider_status,final", [("failed", "failed"), ("abandoned", "abandoned")])
def test_failed_or_abandoned_payments_grant_nothing(auth_client, user, shop, provider_status, final):
    ref = checkout(auth_client).data["reference"]
    shop.result(ref, "5000", status=provider_status)
    v = auth_client.post(VERIFY, {"reference": ref}, format="json")
    assert v.data["status"] == final and PaymentTransaction.objects.get().status == final
    assert not feature_enabled(user, "ads.remove")


@pytest.mark.parametrize("amount,currency", [("100", "NGN"), ("4999.99", "NGN"), ("5000", "USD"), ("0", "NGN")])
def test_an_amount_or_currency_mismatch_is_never_credited(auth_client, user, shop, amount, currency):
    ref = checkout(auth_client).data["reference"]
    shop.result(ref, amount, currency)
    v = auth_client.post(VERIFY, {"reference": ref}, format="json")
    assert v.status_code == 409 and v.data["error"]["code"] == "payment_mismatch"
    tx = PaymentTransaction.objects.get()
    assert tx.status == "failed" and "mismatch" in tx.failure_reason
    assert Subscription.objects.get().status == S.PENDING_PAYMENT and not feature_enabled(user, "ads.remove")


def test_an_unknown_reference_at_the_provider_changes_nothing(auth_client, shop):
    ref = checkout(auth_client).data["reference"]           # the provider has no record of it
    v = auth_client.post(VERIFY, {"reference": ref}, format="json")
    assert v.status_code == 200 and v.data["status"] == "pending"


def test_a_provider_outage_during_verification_is_retryable_and_credits_nothing(auth_client, user, shop):
    ref = checkout(auth_client).data["reference"]
    shop.result(ref, "5000")
    shop.mode["verify"] = 503
    assert auth_client.post(VERIFY, {"reference": ref}, format="json").status_code == 503
    assert PaymentTransaction.objects.get().status == "pending" and not feature_enabled(user, "ads.remove")
    shop.mode.clear()
    assert auth_client.post(VERIFY, {"reference": ref}, format="json").data["status"] == "success"


def test_users_cannot_verify_each_others_payments(auth_client, other_client, shop):
    ref = checkout(auth_client).data["reference"]
    shop.result(ref, "5000")
    assert other_client.post(VERIFY, {"reference": ref}, format="json").status_code == 404
    assert PaymentTransaction.objects.get().status == "pending"


# ---- renewals, upgrades --------------------------------------------------------------------------------------------------------------
def test_renewing_before_expiry_extends_from_the_old_end_date(auth_client, shop):
    pay(auth_client, shop)
    first_end = Subscription.objects.get().current_period_end
    pay(auth_client, shop)
    second_end = Subscription.objects.get().current_period_end
    assert 28 <= (second_end - first_end).days <= 31                 # a full extra period, nothing lost
    assert SubscriptionEvent.objects.filter(detail__outcome="renewed").exists() and Subscription.objects.count() == 1


def test_renewing_after_lapse_starts_a_fresh_period_from_now(auth_client, shop):
    pay(auth_client, shop)
    Subscription.objects.update(current_period_end=djtz.now() - timedelta(days=40), status=S.EXPIRED)
    pay(auth_client, shop)
    sub = Subscription.objects.get()
    assert sub.status == S.ACTIVE and 27 <= (sub.current_period_end - djtz.now()).days <= 31


def test_changing_plan_takes_effect_on_payment_without_proration(auth_client, user, shop):
    pay(auth_client, shop, plan="starter", currency="NGN")
    assert get_limit(user, "qr.dynamic.active_limit") == 10
    pay(auth_client, shop, plan="pro", currency="NGN")
    sub = Subscription.objects.get()
    assert sub.plan.slug == "pro" and get_limit(user, "qr.dynamic.active_limit") == 100
    assert SubscriptionEvent.objects.filter(detail__outcome="plan_changed").exists()
    pay(auth_client, shop, plan="starter", currency="NGN")                                   # downgrade is a purchase too
    assert Subscription.objects.get().plan.slug == "starter" and get_limit(user, "qr.dynamic.active_limit") == 10


def test_transactions_list_is_private_and_complete(auth_client, other_client, shop):
    pay(auth_client, shop)
    checkout(auth_client)                                                                    # one pending
    r = auth_client.get("/api/v1/billing/transactions/")
    assert r.data["count"] == 2 and {t["status"] for t in r.data["results"]} == {"success", "pending"}
    assert r.data["results"][0]["plan"] == "pro" and "customer_reference" not in r.data["results"][0]
    assert other_client.get("/api/v1/billing/transactions/").data["count"] == 0


def test_subscription_endpoint(auth_client, shop):
    r = auth_client.get("/api/v1/billing/subscription/")
    assert r.data["subscription"] is None and r.data["effective_plan"]["slug"] == "free" and r.data["pricing_enabled"] is True
    pay(auth_client, shop)
    s = auth_client.get("/api/v1/billing/subscription/").data
    assert s["subscription"]["status"] == "active" and s["subscription"]["has_access"] and s["subscription"]["access_until"]
    assert s["effective_plan"] == {"slug": "pro", "name": "Pro", "reason": "subscription"}


# ---- Flutterwave ------------------------------------------------------------------------------------------------------------------------------
def test_flutterwave_checkout_and_verification(auth_client, user, senv, plans, pricing, pay_settings):
    AppConfiguration.objects.create(key="billing.enabled_providers", value=["flutterwave"])
    fw = FlutterwaveSim(senv)
    r = auth_client.post(CHECKOUT, {"plan": "pro", "currency": "NGN"}, format="json")
    assert r.status_code == 200 and r.data["provider"] == "flutterwave" and r.data["authorization_url"].startswith("https://checkout.flutterwave.com/")
    sent = fw.initialized[0]
    assert sent["amount"] == "5000.00" and sent["currency"] == "NGN" and sent["tx_ref"] == r.data["reference"] and sent["customer"]["email"] == user.email
    fw.result(r.data["reference"], "5000.00")
    v = auth_client.post(VERIFY, {"reference": r.data["reference"]}, format="json")
    assert v.data["status"] == "success" and get_limit(user, "qr.dynamic.active_limit") == 100
    ref2 = auth_client.post(CHECKOUT, {"plan": "pro", "currency": "NGN"}, format="json").data["reference"]
    fw.result(ref2, "10.00")
    assert auth_client.post(VERIFY, {"reference": ref2}, format="json").status_code == 409          # wrong amount refused


# ---- trials ------------------------------------------------------------------------------------------------------------------------------------------
def test_a_trial_grants_the_plan_without_payment_once_per_plan(auth_client, user, shop):
    r = checkout(auth_client, start_trial=True)
    assert r.status_code == 200 and r.data["trial_started"] and r.data["subscription"]["status"] == "trialing"
    assert get_limit(user, "qr.dynamic.active_limit") == 100 and PaymentTransaction.objects.count() == 0
    ends = Subscription.objects.get().trial_ends_at
    assert 6 <= (ends - djtz.now()).days <= 7
    again = checkout(auth_client, start_trial=True)
    assert again.status_code == 409                                                           # already in a trial / active
    Subscription.objects.update(status=S.EXPIRED)
    assert checkout(auth_client, start_trial=True).data["error"]["code"] == "trial_already_used"


def test_trial_unavailable_cases(auth_client, user, shop, plans):
    assert checkout(auth_client, "starter", start_trial=True).data["error"]["code"] == "trial_unavailable"      # no trial configured
    AppConfiguration.objects.create(key="billing.trials_enabled", value=False)
    assert checkout(auth_client, start_trial=True).status_code == 403


def test_trial_is_blocked_with_an_active_paid_plan(auth_client, shop):
    pay(auth_client, shop, plan="starter")
    assert checkout(auth_client, "pro", start_trial=True).status_code == 409


def test_paying_during_a_trial_converts_it(auth_client, user, shop):
    checkout(auth_client, start_trial=True)
    pay(auth_client, shop)
    sub = Subscription.objects.get()
    assert sub.status == S.ACTIVE and sub.trial_ends_at is None and (sub.current_period_end - djtz.now()).days >= 27


def test_trial_ends_via_the_lifecycle_job(auth_client, user, shop, capsys):
    checkout(auth_client, start_trial=True)
    Subscription.objects.update(trial_ends_at=djtz.now() - timedelta(hours=1), current_period_end=djtz.now() - timedelta(hours=1))
    assert not feature_enabled(user, "ads.remove")                            # access is time-based: gone even before the job runs
    call_command("process_subscriptions")
    assert "expired 1" in capsys.readouterr().out and Subscription.objects.get().status == S.EXPIRED
    assert Notification.objects.filter(user=user, title="Your trial has ended").exists()


# ---- cancel / resume ----------------------------------------------------------------------------------------------------------------------------------
def test_cancelling_keeps_access_until_the_period_ends_and_can_be_undone(auth_client, user, shop):
    pay(auth_client, shop)
    r = auth_client.post("/api/v1/billing/cancel/", {}, format="json")
    assert r.status_code == 200 and r.data["status"] == "cancelled" and r.data["subscription"]["cancel_at_period_end"] is True
    assert r.data["subscription"]["has_access"] and get_limit(user, "qr.dynamic.active_limit") == 100
    assert r.data["provider_cancellation"] == "not_applicable"
    back = auth_client.post("/api/v1/billing/resume/")
    assert back.data["subscription"]["status"] == "active" and back.data["subscription"]["cancel_at_period_end"] is False


def test_immediate_cancellation_ends_access_now(auth_client, user, shop):
    pay(auth_client, shop)
    r = auth_client.post("/api/v1/billing/cancel/", {"immediately": True}, format="json")
    assert r.data["subscription"]["status"] == "expired" and r.data["subscription"]["has_access"] is False
    assert get_limit(user, "qr.dynamic.active_limit") == 3


def test_cancel_and_resume_error_cases(auth_client, user, shop):
    assert auth_client.post("/api/v1/billing/cancel/", {}, format="json").status_code == 404
    assert auth_client.post("/api/v1/billing/resume/").status_code == 409
    pay(auth_client, shop)
    assert auth_client.post("/api/v1/billing/resume/").status_code == 409                 # not cancelled
    auth_client.post("/api/v1/billing/cancel/", {}, format="json")
    Subscription.objects.update(current_period_end=djtz.now() - timedelta(days=1))
    assert auth_client.post("/api/v1/billing/resume/").status_code == 409                 # too late


def test_cancelling_a_provider_managed_subscription_also_stops_provider_renewals(auth_client, user, shop):
    pay(auth_client, shop)
    Subscription.objects.update(external_subscription_reference="SUB_1")
    r = auth_client.post("/api/v1/billing/cancel/", {}, format="json")
    assert r.data["provider_cancellation"] == "cancelled" and shop.disabled == [{"code": "SUB_1", "token": "tok-1"}]


def test_a_failed_provider_cancellation_is_reported_not_hidden(auth_client, user, shop):
    pay(auth_client, shop)
    Subscription.objects.update(external_subscription_reference="SUB_1")
    shop.mode["disable"] = 500
    r = auth_client.post("/api/v1/billing/cancel/", {}, format="json")
    assert r.status_code == 200 and r.data["provider_cancellation"] == "failed"
    assert SubscriptionEvent.objects.filter(event_type="provider_cancel_failed").exists()
    assert r.data["subscription"]["has_access"]                                            # the user's own cancel still worked


# ---- lifecycle ------------------------------------------------------------------------------------------------------------------------------------------
def test_missed_renewal_moves_through_grace_then_expiry(auth_client, user, shop, capsys):
    pay(auth_client, shop)                                                                   # pro has 3 grace days
    Subscription.objects.update(current_period_end=djtz.now() - timedelta(days=1))
    assert feature_enabled(user, "ads.remove")                                               # still inside grace
    call_command("process_subscriptions")
    assert Subscription.objects.get().status == S.GRACE_PERIOD and "1 subscription(s) to grace period" in capsys.readouterr().out
    assert Notification.objects.filter(user=user, title="Your subscription needs attention").exists()
    call_command("process_subscriptions")                                                    # idempotent
    assert SubscriptionEvent.objects.filter(event_type="grace_period_started").count() == 1
    Subscription.objects.update(current_period_end=djtz.now() - timedelta(days=4))
    assert not feature_enabled(user, "ads.remove")
    call_command("process_subscriptions")
    assert Subscription.objects.get().status == S.EXPIRED and Notification.objects.filter(title="Your subscription has ended").exists()


def test_no_grace_expires_straight_away_and_cancelled_ends_quietly(auth_client, user, shop):
    pay(auth_client, shop, plan="starter")
    Plan.objects.filter(slug="starter").update(grace_period_days=0)
    Subscription.objects.update(current_period_end=djtz.now() - timedelta(minutes=5))
    call_command("process_subscriptions")
    assert Subscription.objects.get().status == S.EXPIRED
    Subscription.objects.update(status=S.CANCELLED, current_period_end=djtz.now() - timedelta(minutes=5))
    n = Notification.objects.count()
    call_command("process_subscriptions")
    assert Subscription.objects.get().status == S.EXPIRED and Notification.objects.count() == n    # user already knows they cancelled
