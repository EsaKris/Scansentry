"""Payment webhooks: signature-verified, idempotent, re-verified with the provider, replay-safe.

HTTP semantics (so providers retry exactly when retrying can help):
  401  bad/missing signature (never processed, never stored)
  400  unparsable body            413  body too large
  503  transient problem (provider API down): the event is kept as FAILED and will be reprocessed on redelivery
  200  processed, ignored, duplicate, or permanently failed (e.g. amount mismatch): retrying cannot help
"""
import json
import logging

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.audit.services import record_audit
from apps.domain_intel import service as domain_service

from . import service as billing
from .entitlements import current_subscription
from .models import PaymentTransaction, PaymentWebhookEvent, PlanPrice, Subscription
from .providers import get_provider
from .providers.base import ProviderError

log = logging.getLogger(__name__)
MAX_BODY = 256 * 1024
MAX_ATTEMPTS = 8
T = PaymentTransaction.Status
S = Subscription.Status
P = PaymentWebhookEvent.Processing
User = get_user_model()


def _charge_success(prov, ev) -> str:
    tx = PaymentTransaction.objects.filter(provider=prov.key, provider_reference=ev.reference).first() if ev.reference else None
    if tx is None:
        return _renewal_charge(prov, ev)
    tx = billing.verify_and_apply(tx, prov)          # asks the provider; never trusts the webhook's own numbers
    if tx.status == T.PENDING:                        # signed webhook says paid, provider API does not (yet): retry later
        raise ProviderError("The provider has not confirmed this payment yet.", transient=True)
    return "processed"


def _renewal_charge(prov, ev) -> str:
    """A charge we did not initiate (provider-managed recurring billing). Mapped to a subscription we know."""
    cust = ev.data.get("customer_code", "")
    sub = (Subscription.objects.filter(is_current=True, billing_provider=prov.key, external_customer_reference=cust)
           .select_related("plan", "user").first() if cust else None)
    if sub is None or not ev.reference:
        return "ignored"
    vr = prov.verify(ev.reference)
    if vr.status != "success":
        return "ignored"
    code = (sub.plan.provider_refs or {}).get(f"{prov.key}_plan_code", "")
    if code and vr.plan_code and vr.plan_code != code:
        return "ignored"
    price = PlanPrice.objects.filter(plan=sub.plan, currency=vr.currency, active=True).first()
    if price is None or vr.amount is None or vr.amount != price.amount:
        raise billing.PaymentMismatch(f"renewal amount {vr.amount} {vr.currency} does not match the plan price")
    try:
        with transaction.atomic():
            tx = PaymentTransaction.objects.create(user=sub.user, plan=sub.plan, provider=prov.key, provider_reference=ev.reference,
                                                   amount=price.amount, currency=vr.currency, customer_reference=cust)
    except IntegrityError:                          # a concurrent delivery created it first
        tx = PaymentTransaction.objects.get(provider=prov.key, provider_reference=ev.reference)
    billing.apply_payment_success(tx, vr)
    return "processed"


def _by_customer(prov, code):
    return (Subscription.objects.filter(is_current=True, billing_provider=prov.key, external_customer_reference=code)
            .select_related("user", "plan").first() if code else None)


def _dispatch(prov, ev) -> str:
    t = ev.event_type
    if t in ("charge.success", "charge.completed"):
        return _charge_success(prov, ev)
    if prov.key != "paystack":
        return "ignored"
    if t == "subscription.create":
        user = User.objects.filter(email__iexact=ev.private.get("email", "")).first() if ev.private.get("email") else None
        sub = current_subscription(user) if user else None
        if sub is None:
            return "ignored"
        Subscription.objects.filter(pk=sub.pk).update(external_subscription_reference=ev.data.get("subscription_code", ""),
                                                      external_customer_reference=ev.data.get("customer_code", "") or sub.external_customer_reference,
                                                      billing_provider=prov.key)
        billing.log_event("provider_subscription_created", user=user, sub=sub, detail={"provider": prov.key})
        return "processed"
    if t == "invoice.payment_failed":
        sub = _by_customer(prov, ev.data.get("customer_code", ""))
        if sub is None or sub.status != S.ACTIVE:
            return "ignored"
        with transaction.atomic():
            Subscription.objects.filter(pk=sub.pk, status=S.ACTIVE).update(status=S.PAST_DUE)
            billing.log_event("payment_failed", user=sub.user, sub=sub, from_status=S.ACTIVE, to_status=S.PAST_DUE,
                              detail={"source": "provider_invoice"})
        from apps.notifications.models import Notification
        from apps.notifications.service import alert_billing
        alert_billing(sub.user, Notification.Kind.BILLING_PAYMENT_FAILED, severity=Notification.Severity.WARNING,
                      title="We could not renew your subscription",
                      body="Your latest payment did not go through. Your access continues for now; please update your payment method.",
                      dedupe_key=f"invoice-failed:{ev.event_id}")
        return "processed"
    if t in ("subscription.disable", "subscription.not_renew"):
        code = ev.data.get("subscription_code", "")
        sub = Subscription.objects.filter(is_current=True, billing_provider=prov.key, external_subscription_reference=code).select_related("user").first() if code else None
        if sub is None or sub.status not in billing.LIVE:
            return "ignored"
        Subscription.objects.filter(pk=sub.pk).update(status=S.CANCELLED, cancel_at_period_end=True, cancelled_at=timezone.now())
        billing.log_event("cancelled", user=sub.user, sub=sub, from_status=sub.status, to_status=S.CANCELLED, detail={"source": "provider"})
        return "processed"
    if t == "refund.processed":
        ref = ev.data.get("transaction_reference") or ev.data.get("reference", "")
        tx = PaymentTransaction.objects.filter(provider=prov.key, provider_reference=ref).first()
        if tx is None:
            return "ignored"
        billing.handle_refund(tx)
        return "processed"
    return "ignored"


def process(provider_key: str, raw: bytes, headers: dict) -> tuple[int, dict]:
    prov = get_provider(provider_key, domain_service.build_guard())
    if prov is None or not prov.configured():
        return 404, {"error": "unknown or unconfigured provider"}
    if len(raw) > MAX_BODY:
        return 413, {"error": "payload too large"}
    if not prov.verify_signature(raw, headers):
        log.warning("webhook signature rejected for %s", provider_key)
        return 401, {"error": "invalid signature"}
    try:
        payload = json.loads(raw)
        ev = prov.parse_webhook(payload)
    except (ValueError, ProviderError, AttributeError, TypeError):
        return 400, {"error": "malformed payload"}

    row, created = PaymentWebhookEvent.objects.get_or_create(
        provider=provider_key, provider_event_id=ev.event_id[:200], defaults=dict(event_type=ev.event_type, payload=ev.data))
    if not created and row.processing_status in (P.PROCESSED, P.IGNORED):
        return 200, {"status": "duplicate"}
    if row.attempts >= MAX_ATTEMPTS and row.processing_status == P.FAILED:
        return 200, {"status": "gave_up"}
    PaymentWebhookEvent.objects.filter(pk=row.pk).update(attempts=row.attempts + 1)

    try:
        outcome = _dispatch(prov, ev)
        status = P.PROCESSED if outcome == "processed" else P.IGNORED
        PaymentWebhookEvent.objects.filter(pk=row.pk).update(processing_status=status, processed_at=timezone.now(), error_message="")
        return 200, {"status": outcome}
    except ProviderError as exc:
        PaymentWebhookEvent.objects.filter(pk=row.pk).update(processing_status=P.FAILED, error_message=str(exc)[:255])
        return (503, {"status": "retry"}) if exc.transient else (200, {"status": "failed"})
    except billing.PaymentMismatch as exc:
        PaymentWebhookEvent.objects.filter(pk=row.pk).update(processing_status=P.FAILED, error_message=f"mismatch: {exc}"[:255])
        record_audit(actor=None, action="billing.payment_mismatch", object_type="PaymentWebhookEvent", object_id=str(row.pk),
                     after={"event": ev.event_type, "detail": str(exc)[:200]})
        return 200, {"status": "failed"}
    except Exception as exc:
        log.exception("webhook processing crashed")
        PaymentWebhookEvent.objects.filter(pk=row.pk).update(processing_status=P.FAILED, error_message=exc.__class__.__name__)
        return 500, {"status": "error"}
