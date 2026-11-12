"""Billing and subscription lifecycle.

Invariants this module guarantees:
  * the amount charged is ALWAYS the active database price; nothing the client sends can change it
  * a payment is only credited after the provider's API confirms success with the exact amount and currency
  * crediting is idempotent (a transaction can grant access once, however many webhooks / verifications arrive)
  * paid access is never cut short by cancelling, a failed renewal, or switching pricing off
  * every state change is written to SubscriptionEvent (history) and, for admin actions, to the audit log
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from rest_framework import status as http
from rest_framework.exceptions import APIException, ValidationError

from apps.audit.services import record_audit
from apps.domain_intel import service as domain_service
from apps.notifications.models import Notification
from apps.notifications.service import alert_billing

from . import config
from .entitlements import access_until, current_subscription, has_access
from .models import (EntitlementOverride, FeatureDefinition, PaymentTransaction, PaymentWebhookEvent, Plan, PlanPrice,
                     Subscription, SubscriptionEvent)
from .providers import PLANNED, get_provider
from .providers.base import ProviderError, VerifyResult
from .timeutil import add_interval

log = logging.getLogger(__name__)
S = Subscription.Status
T = PaymentTransaction.Status
K = Notification.Kind
User = get_user_model()
LIVE = (S.TRIALING, S.ACTIVE, S.PAST_DUE, S.GRACE_PERIOD)


class BillingError(APIException):
    status_code = http.HTTP_400_BAD_REQUEST

    def __init__(self, code: str, message: str, status_code: int | None = None):
        super().__init__(detail=message, code=code)
        if status_code:
            self.status_code = status_code


class PaymentMismatch(Exception):
    """The provider's numbers did not match what we asked for."""

    def __init__(self, message: str, *, mark_failed: bool = True):
        super().__init__(message)
        self.mark_failed = mark_failed


def _now() -> datetime:
    return datetime.now(timezone.utc)


def log_event(event_type, *, user, sub=None, from_status="", to_status="", from_plan=None, to_plan=None, detail=None, actor=None):
    return SubscriptionEvent.objects.create(
        user=user, subscription=sub, event_type=event_type, from_status=from_status, to_status=to_status,
        from_plan=from_plan, to_plan=to_plan, detail=detail or {}, actor=actor)


def _providers_for(key: str):
    if key in PLANNED:
        raise BillingError("provider_unavailable", f"{key} is not available yet.")
    prov = get_provider(key, domain_service.build_guard())
    if prov is None or key not in config.enabled_providers() or not prov.configured():
        raise BillingError("provider_unavailable", "This payment method is not available right now.")
    return prov


# ---- checkout --------------------------------------------------------------------------------------------------
def start_checkout(user, *, plan_slug: str, currency: str, provider_key: str) -> dict:
    if not config.pricing_enabled():
        raise BillingError("pricing_disabled", "Purchases are not available right now.", http.HTTP_403_FORBIDDEN)
    sub = current_subscription(user)
    if sub is not None and sub.status == S.SUSPENDED:
        raise BillingError("subscription_suspended", "Your subscription is suspended. Contact support.", http.HTTP_403_FORBIDDEN)
    plan = Plan.objects.filter(slug=plan_slug, status=Plan.Status.ACTIVE, is_public=True, is_free=False).first()
    if plan is None:
        raise BillingError("plan_unavailable", "This plan is not available.", http.HTTP_404_NOT_FOUND)
    currency = (currency or "").upper()
    price = PlanPrice.objects.filter(plan=plan, currency=currency, active=True).first()
    if price is None:
        offered = sorted(plan.prices.filter(active=True).values_list("currency", flat=True))
        raise BillingError("currency_unavailable", f"This plan is not sold in {currency or 'that currency'}. Available: {', '.join(offered) or 'none'}.")
    prov = _providers_for(provider_key)
    if currency not in prov.supported_currencies:
        raise BillingError("currency_unsupported", f"{prov.display_name} does not support {currency}.")

    reference = f"ss-{uuid.uuid4().hex[:24]}"
    tx = PaymentTransaction.objects.create(user=user, plan=plan, provider=prov.key, provider_reference=reference,
                                           amount=price.amount, currency=currency)     # amount from the DATABASE price
    metadata = {"user_id": str(user.pk), "plan": plan.slug, "reference": reference, "app": "scansentry"}
    try:
        init = prov.initialize(reference=reference, email=user.email, amount=price.amount, currency=currency,
                               callback_url=settings.BILLING_RETURN_URL or f"{settings.FRONTEND_URL}/billing/complete",
                               metadata=metadata, plan_code=(plan.provider_refs or {}).get(f"{prov.key}_plan_code", ""))
    except ProviderError as exc:
        PaymentTransaction.objects.filter(pk=tx.pk).update(status=T.FAILED, failure_reason=f"init_failed: {exc}"[:255])
        raise BillingError("provider_error", "The payment provider could not start the payment. Please try again.",
                           http.HTTP_503_SERVICE_UNAVAILABLE if exc.transient else http.HTTP_502_BAD_GATEWAY)
    if sub is None:
        with transaction.atomic():
            Subscription.objects.get_or_create(user=user, is_current=True, defaults=dict(
                plan=plan, status=S.PENDING_PAYMENT, billing_provider=prov.key, currency=currency))
    return {"authorization_url": init.authorization_url, "reference": reference, "provider": prov.key,
            "plan": plan.slug, "amount": str(price.amount), "currency": currency}


def start_trial(user, *, plan_slug: str, now: datetime | None = None) -> Subscription:
    now = now or _now()
    if not config.pricing_enabled() or not config.trials_enabled():
        raise BillingError("pricing_disabled", "Trials are not available right now.", http.HTTP_403_FORBIDDEN)
    plan = Plan.objects.filter(slug=plan_slug, status=Plan.Status.ACTIVE, is_public=True, is_free=False, trial_days__gt=0).first()
    if plan is None:
        raise BillingError("trial_unavailable", "This plan does not offer a trial.", http.HTTP_404_NOT_FOUND)
    with transaction.atomic():
        sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).first()
        if sub is not None and (has_access(sub, now) or sub.status == S.SUSPENDED):
            raise BillingError("trial_unavailable", "Trials are only for accounts without an active plan.", http.HTTP_409_CONFLICT)
        if SubscriptionEvent.objects.filter(user=user, event_type="trial_started", to_plan=plan).exists():
            raise BillingError("trial_already_used", "You have already used the trial for this plan.", http.HTTP_409_CONFLICT)
        end = now + timedelta(days=plan.trial_days)
        old_status = sub.status if sub else ""
        if sub is None:
            sub = Subscription.objects.create(user=user, plan=plan, status=S.TRIALING, started_at=now, current_period_start=now,
                                              current_period_end=end, trial_ends_at=end)
        else:
            sub.plan, sub.status, sub.started_at = plan, S.TRIALING, sub.started_at or now
            sub.current_period_start, sub.current_period_end, sub.trial_ends_at = now, end, end
            sub.cancel_at_period_end, sub.cancelled_at = False, None
            sub.save()
        log_event("trial_started", user=user, sub=sub, from_status=old_status, to_status=S.TRIALING, to_plan=plan,
                  detail={"ends_at": end.isoformat()})
    alert_billing(user, K.BILLING_ACTIVATED, title=f"Your {plan.name} trial has started",
                  body=f"You have {plan.trial_days} days of {plan.name}. It ends on {end:%Y-%m-%d}.", dedupe_key=f"trial:{plan.id}")
    return sub


# ---- crediting payments (idempotent) -----------------------------------------------------------------------------------
def _check_match(tx: PaymentTransaction, vr: VerifyResult) -> None:
    if vr.amount is None or Decimal(vr.amount).quantize(Decimal("0.01")) != tx.amount.quantize(Decimal("0.01")) \
            or (vr.currency or "").upper() != tx.currency:
        raise PaymentMismatch(f"expected {tx.amount} {tx.currency}, provider reported {vr.amount} {vr.currency}")


def apply_payment_success(tx: PaymentTransaction, vr: VerifyResult, *, now: datetime | None = None) -> bool:
    """Credit a verified payment. Returns False if it was already credited. Raises PaymentMismatch on bad amounts.

    A refused payment is recorded as FAILED *outside* the crediting transaction, so the record survives the rollback."""
    now = now or _now()
    try:
        return _credit(tx, vr, now)
    except PaymentMismatch as exc:
        if exc.mark_failed:
            PaymentTransaction.objects.filter(pk=tx.pk).exclude(status__in=[T.SUCCESS, T.REFUNDED]).update(
                status=T.FAILED, failure_reason=f"mismatch: {exc}"[:255])
        raise


def _credit(tx: PaymentTransaction, vr: VerifyResult, now: datetime) -> bool:
    with transaction.atomic():
        tx = PaymentTransaction.objects.select_for_update().select_related("plan", "user").get(pk=tx.pk)
        if tx.status == T.SUCCESS:
            return False
        if vr.status != "success":
            raise PaymentMismatch(f"provider status is {vr.status}", mark_failed=False)
        _check_match(tx, vr)
        plan = tx.plan
        if plan is None:
            raise PaymentMismatch("the plan no longer exists")
        tx.status, tx.verified_at, tx.paid_at = T.SUCCESS, now, vr.paid_at or now
        tx.payment_method, tx.customer_reference = vr.channel[:30], vr.customer_reference[:120]
        sub = Subscription.objects.select_for_update().filter(user=tx.user, is_current=True).select_related("plan").first()
        old_status, old_plan = (sub.status if sub else ""), (sub.plan if sub else None)
        extending = sub is not None and sub.plan_id == plan.id and has_access(sub, now) and sub.status != S.TRIALING
        if extending:
            start = max(now, sub.current_period_end)
            sub.current_period_end = add_interval(start, plan.billing_interval)
        else:
            start = now
            fields = dict(plan=plan, current_period_start=now, current_period_end=add_interval(now, plan.billing_interval))
            if sub is None:
                sub = Subscription.objects.create(user=tx.user, status=S.ACTIVE, started_at=now, **fields)
            else:
                for k, v in fields.items():
                    setattr(sub, k, v)
        sub.status, sub.trial_ends_at = S.ACTIVE, None
        sub.cancel_at_period_end, sub.cancelled_at = False, None
        sub.started_at = sub.started_at or now
        sub.billing_provider, sub.currency = tx.provider, tx.currency
        if vr.customer_reference:
            sub.external_customer_reference = vr.customer_reference
        sub.save()
        tx.subscription = sub
        tx.save()
        kind = "renewed" if extending else ("plan_changed" if (old_plan and old_plan.id != plan.id and old_status in
                                                              ("active", "trialing", "past_due", "grace_period")) else "activated")
        log_event("payment_succeeded", user=tx.user, sub=sub, from_status=old_status, to_status=S.ACTIVE, from_plan=old_plan,
                  to_plan=plan, detail={"transaction": str(tx.id), "reference": tx.provider_reference, "outcome": kind,
                                        "amount": str(tx.amount), "currency": tx.currency})
        record_audit(actor=None, action="billing.payment_succeeded", obj=tx, after={"outcome": kind})
    alert_billing(tx.user, K.BILLING_ACTIVATED,
                  title=("Subscription renewed" if kind == "renewed" else f"{plan.name} is now active"),
                  body=f"Your payment of {tx.amount} {tx.currency} was received. {plan.name} is active until {sub.current_period_end:%Y-%m-%d}.",
                  severity=Notification.Severity.INFO, dedupe_key=f"paid:{tx.id}")
    return True


def apply_payment_failure(tx: PaymentTransaction, reason: str) -> None:
    """Record a payment the provider reports as failed. Never touches access: a failed first payment grants nothing,
    and a failed renewal is handled by the provider-invoice webhook (past due, access continues)."""
    with transaction.atomic():
        tx = PaymentTransaction.objects.select_for_update().get(pk=tx.pk)
        if tx.status in (T.SUCCESS, T.REFUNDED):
            return
        tx.status, tx.failure_reason = T.FAILED, reason[:255]
        tx.save(update_fields=["status", "failure_reason"])
        log_event("payment_failed", user=tx.user, sub=current_subscription(tx.user),
                  detail={"reason": reason[:120], "transaction": str(tx.id)})


def handle_refund(tx: PaymentTransaction, *, now: datetime | None = None) -> None:
    now = now or _now()
    with transaction.atomic():
        tx = PaymentTransaction.objects.select_for_update().get(pk=tx.pk)
        if tx.status == T.REFUNDED:
            return
        was_paid = tx.status == T.SUCCESS
        tx.status = T.REFUNDED
        tx.save(update_fields=["status"])
        sub = Subscription.objects.select_for_update().filter(user=tx.user, is_current=True).first()
        latest = tx.user.payments.filter(status=T.SUCCESS).order_by("-paid_at").first()
        revoke = was_paid and config.refund_revokes_access() and sub is not None and latest is None
        if revoke:
            old = sub.status
            sub.status, sub.current_period_end = S.EXPIRED, min(sub.current_period_end or now, now)
            sub.save(update_fields=["status", "current_period_end", "updated_at"])
            log_event("refunded", user=tx.user, sub=sub, from_status=old, to_status=S.EXPIRED, detail={"transaction": str(tx.id), "access_revoked": True})
        else:
            log_event("refunded", user=tx.user, sub=sub, detail={"transaction": str(tx.id), "access_revoked": False})


def verify_and_apply(tx: PaymentTransaction, prov=None) -> PaymentTransaction:
    """Ask the provider (server to server) what happened and apply it. Safe to call repeatedly."""
    prov = prov or _providers_for(tx.provider)
    vr = prov.verify(tx.provider_reference)           # ProviderError propagates so callers can retry
    if vr.status == "success":
        apply_payment_success(tx, vr)
    elif vr.status in ("failed", "abandoned"):
        apply_payment_failure(tx, f"provider reported {vr.status}")
        PaymentTransaction.objects.filter(pk=tx.pk, status=T.FAILED).update(status=T.ABANDONED if vr.status == "abandoned" else T.FAILED)
    tx.refresh_from_db()
    return tx


def verify_checkout(user, reference: str) -> PaymentTransaction:
    tx = PaymentTransaction.objects.filter(user=user, provider_reference=reference).first()
    if tx is None:
        raise BillingError("not_found", "Unknown payment reference.", http.HTTP_404_NOT_FOUND)
    try:
        return verify_and_apply(tx)
    except PaymentMismatch as exc:
        raise BillingError("payment_mismatch", "The payment did not match the order and was not applied. Contact support.",
                           http.HTTP_409_CONFLICT)
    except ProviderError as exc:
        raise BillingError("provider_error", "Could not confirm the payment yet. Try again shortly.",
                           http.HTTP_503_SERVICE_UNAVAILABLE)


# ---- cancel / resume --------------------------------------------------------------------------------------------------------
def cancel_subscription(user, *, immediately: bool = False, now: datetime | None = None) -> dict:
    now = now or _now()
    with transaction.atomic():
        sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).select_related("plan").first()
        if sub is None or sub.status not in LIVE or not has_access(sub, now):
            raise BillingError("no_active_subscription", "You have no active subscription to cancel.", http.HTTP_404_NOT_FOUND)
        old = sub.status
        sub.cancelled_at, sub.cancel_at_period_end = now, True
        if immediately:
            sub.status, sub.current_period_end = S.EXPIRED, now
        else:
            if sub.status == S.TRIALING:
                sub.current_period_end = sub.trial_ends_at
            sub.status = S.CANCELLED
        sub.save()
        log_event("cancelled", user=user, sub=sub, from_status=old, to_status=sub.status, detail={"immediately": immediately})
        ref, provider = sub.external_subscription_reference, sub.billing_provider
    provider_cancel = "not_applicable"
    if ref and provider:                              # stop provider-managed renewals too (best effort, reported honestly)
        try:
            prov = get_provider(provider, domain_service.build_guard())
            provider_cancel = "cancelled" if prov and prov.cancel_recurring(ref) else "failed"
        except ProviderError:
            provider_cancel = "failed"
        if provider_cancel == "failed":
            log_event("provider_cancel_failed", user=user, sub=sub, detail={"provider": provider})
            log.error("could not cancel provider subscription %s for user %s", ref, user.pk)
    end = sub.current_period_end
    alert_billing(user, K.BILLING_ENDING, title="Your subscription was cancelled",
                  body=("Your access has ended." if immediately else f"You keep full access until {end:%Y-%m-%d}."),
                  dedupe_key=f"cancel:{sub.id}:{now:%Y%m%d%H}")
    return {"status": sub.status, "access_until": access_until(sub), "provider_cancellation": provider_cancel}


def resume_subscription(user, *, now: datetime | None = None) -> Subscription:
    now = now or _now()
    with transaction.atomic():
        sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).first()
        if sub is None or sub.status != S.CANCELLED or not has_access(sub, now):
            raise BillingError("nothing_to_resume", "There is no cancelled subscription to resume.", http.HTTP_409_CONFLICT)
        new_status = S.TRIALING if sub.trial_ends_at and now < sub.trial_ends_at else S.ACTIVE
        sub.status, sub.cancel_at_period_end, sub.cancelled_at = new_status, False, None
        sub.save()
        log_event("resumed", user=user, sub=sub, from_status=S.CANCELLED, to_status=new_status)
    return sub


# ---- scheduled lifecycle ---------------------------------------------------------------------------------------------------------
def process_due_subscriptions(now: datetime | None = None) -> dict:
    """Move subscriptions through trial end, grace and expiry. Run hourly. Access itself is time-based in the resolver,
    so a late run never grants or removes access incorrectly; this keeps statuses, history and notifications accurate."""
    now = now or _now()
    counts = {"expired": 0, "grace_period": 0}
    for sub in Subscription.objects.filter(is_current=True, status__in=[*LIVE, S.CANCELLED]).select_related("plan", "user"):
        until = access_until(sub)
        if until is None:
            continue
        old = sub.status
        new = None
        if now >= until:
            new = S.EXPIRED
        elif old in (S.ACTIVE, S.PAST_DUE) and sub.current_period_end and now >= sub.current_period_end:
            new = S.GRACE_PERIOD
        if new is None or new == old:
            continue
        with transaction.atomic():
            fresh = Subscription.objects.select_for_update().get(pk=sub.pk)
            if fresh.status != old:
                continue
            fresh.status = new
            fresh.save(update_fields=["status", "updated_at"])
            log_event("expired" if new == S.EXPIRED else "grace_period_started", user=sub.user, sub=fresh, from_status=old,
                      to_status=new, detail={"access_until": until.isoformat()})
        counts["expired" if new == S.EXPIRED else "grace_period"] += 1
        if new == S.GRACE_PERIOD:
            alert_billing(sub.user, K.BILLING_ENDING, severity=Notification.Severity.WARNING, title="Your subscription needs attention",
                          body=f"Your plan period has ended. Your access continues until {until:%Y-%m-%d}; renew to keep it.",
                          dedupe_key=f"grace:{sub.id}:{sub.current_period_end:%Y%m%d}")
        elif old != S.CANCELLED:
            alert_billing(sub.user, K.BILLING_ENDING, severity=Notification.Severity.WARNING,
                          title=("Your trial has ended" if old == S.TRIALING else "Your subscription has ended"),
                          body="You are back on the free plan. You can subscribe again at any time.",
                          dedupe_key=f"expired:{sub.id}:{until:%Y%m%d}")
    return counts
