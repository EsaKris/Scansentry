"""Administrative entitlement and subscription operations. Each one needs an internal note, is written to the
audit log and to the subscription history. Permissions are checked by the caller (API / admin)."""
from datetime import datetime, timedelta, timezone

from django.db import transaction
from rest_framework.exceptions import ValidationError

from apps.audit.services import record_audit
from apps.notifications.models import Notification
from apps.notifications.service import alert_billing

from .entitlements import has_access
from .models import EntitlementOverride, FeatureDefinition, Plan, Subscription
from .service import BillingError, log_event

S = Subscription.Status
O = EntitlementOverride.Kind


def _now():
    return datetime.now(timezone.utc)


def _note(note) -> str:
    note = (note or "").strip()
    if len(note) < 5:
        raise ValidationError({"note": "An internal note of at least 5 characters is required for every administrative change."})
    return note[:2000]


def grant_feature(admin, user, feature_key: str, *, enabled: bool = True, limit=None, expires_at=None, note: str,
                  kind: str = O.FEATURE) -> EntitlementOverride:
    note = _note(note)
    feature = FeatureDefinition.objects.filter(key=feature_key, active=True).first()
    if feature is None:
        raise ValidationError({"feature": "Unknown feature key."})
    if expires_at is not None and expires_at <= _now():
        raise ValidationError({"expires_at": "The expiry must be in the future."})
    if limit is not None and limit < 0:
        raise ValidationError({"limit": "The limit cannot be negative."})
    o = EntitlementOverride.objects.create(user=user, kind=kind, feature=feature, enabled=enabled, limit_value=limit,
                                           expires_at=expires_at, note=note, created_by=admin)
    log_event("override_granted", user=user, actor=admin, detail={"override": o.id, "kind": kind, "feature": feature_key,
                                                                    "enabled": enabled, "limit": limit})
    record_audit(actor=admin, action="billing.override_granted", obj=o, after={"feature": feature_key, "enabled": enabled,
                                                                              "limit": limit, "expires_at": str(expires_at), "note": note})
    return o


def grant_plan_access(admin, user, plan_slug: str, *, days: int, note: str) -> EntitlementOverride:
    note = _note(note)
    plan = Plan.objects.filter(slug=plan_slug, status=Plan.Status.ACTIVE).first()
    if plan is None:
        raise ValidationError({"plan": "Unknown or inactive plan."})
    if not 1 <= days <= 3650:
        raise ValidationError({"days": "Choose between 1 and 3650 days."})
    expires = _now() + timedelta(days=days)
    o = EntitlementOverride.objects.create(user=user, kind=O.PLAN_TRIAL, plan=plan, expires_at=expires, note=note, created_by=admin)
    log_event("override_granted", user=user, actor=admin, to_plan=plan, detail={"override": o.id, "kind": O.PLAN_TRIAL, "days": days})
    record_audit(actor=admin, action="billing.plan_access_granted", obj=o, after={"plan": plan.slug, "expires_at": expires.isoformat(), "note": note})
    alert_billing(user, Notification.Kind.BILLING_ACTIVATED, title=f"You have been given {plan.name} access",
                  body=f"{plan.name} features are available to you until {expires:%Y-%m-%d}.", dedupe_key=f"grant:{o.id}")
    return o


def revoke_override(admin, override: EntitlementOverride, *, note: str) -> EntitlementOverride:
    note = _note(note)
    if override.revoked_at is not None:
        raise BillingError("already_revoked", "This grant was already revoked.", 409)
    override.revoked_at, override.revoked_by, override.revoke_note = _now(), admin, note
    override.save(update_fields=["revoked_at", "revoked_by", "revoke_note"])
    log_event("override_revoked", user=override.user, actor=admin, detail={"override": override.id})
    record_audit(actor=admin, action="billing.override_revoked", obj=override, after={"note": note})
    return override


@transaction.atomic
def extend_subscription(admin, user, *, days: int, note: str) -> Subscription:
    note = _note(note)
    if not 1 <= days <= 3650:
        raise ValidationError({"days": "Choose between 1 and 3650 days."})
    sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).first()
    if sub is None or sub.status == S.PENDING_PAYMENT:
        raise BillingError("no_subscription", "This user has no subscription to extend. Grant plan access instead.", 404)
    now = _now()
    old_status, old_end = sub.status, sub.current_period_end
    if sub.status in (S.EXPIRED, S.SUSPENDED) or not has_access(sub, now):
        sub.status, sub.current_period_start, sub.current_period_end = S.ACTIVE, now, now + timedelta(days=days)
    else:
        sub.current_period_end = max(sub.current_period_end or now, now) + timedelta(days=days)
        if sub.status == S.TRIALING:
            sub.trial_ends_at = sub.current_period_end
        elif sub.status in (S.PAST_DUE, S.GRACE_PERIOD):
            sub.status = S.ACTIVE
    sub.save()
    log_event("extended", user=user, sub=sub, actor=admin, from_status=old_status, to_status=sub.status,
              detail={"days": days, "from": str(old_end), "to": str(sub.current_period_end)})
    record_audit(actor=admin, action="billing.subscription_extended", obj=sub,
                 before={"period_end": str(old_end), "status": old_status}, after={"period_end": str(sub.current_period_end), "note": note})
    alert_billing(user, Notification.Kind.BILLING_ACTIVATED, title="Your subscription was extended",
                  body=f"Your plan now runs until {sub.current_period_end:%Y-%m-%d}.", dedupe_key=f"extend:{sub.id}:{now:%Y%m%d%H%M}")
    return sub


@transaction.atomic
def suspend_subscription(admin, user, *, note: str) -> Subscription:
    note = _note(note)
    sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).first()
    if sub is None:
        raise BillingError("no_subscription", "This user has no subscription.", 404)
    old = sub.status
    sub.status = S.SUSPENDED
    sub.save(update_fields=["status", "updated_at"])
    log_event("suspended", user=user, sub=sub, actor=admin, from_status=old, to_status=S.SUSPENDED)
    record_audit(actor=admin, action="billing.subscription_suspended", obj=sub, before={"status": old}, after={"status": S.SUSPENDED, "note": note})
    return sub


@transaction.atomic
def restore_subscription(admin, user, *, note: str) -> Subscription:
    note = _note(note)
    sub = Subscription.objects.select_for_update().filter(user=user, is_current=True).first()
    if sub is None or sub.status != S.SUSPENDED:
        raise BillingError("not_suspended", "This subscription is not suspended.", 409)
    now = _now()
    sub.status = S.ACTIVE if sub.current_period_end and sub.current_period_end > now else S.EXPIRED
    sub.save(update_fields=["status", "updated_at"])
    log_event("restored", user=user, sub=sub, actor=admin, from_status=S.SUSPENDED, to_status=sub.status)
    record_audit(actor=admin, action="billing.subscription_restored", obj=sub, before={"status": S.SUSPENDED}, after={"status": sub.status, "note": note})
    return sub
