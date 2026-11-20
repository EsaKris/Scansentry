"""Account deletion: request -> grace period -> anonymisation.

Why anonymise instead of deleting the row: payment records must be kept for accounting (and are protected by the database), and audit entries point at their actor.
So the user row stays as an anonymous TOMBSTONE (no email, name, password or access) and everything personal around it is erased.

Every relation to the user model is decided in POLICY below, and a test fails if a new model references users without being listed here, so
a future feature cannot silently keep personal data after an account is "deleted".
"""
from datetime import datetime, timedelta, timezone

from django.contrib.auth import get_user_model
from django.db import models, transaction

from apps.audit.services import record_audit
from apps.core.config import get_config

# "delete": rows are removed.  "keep": rows stay (the tombstone holds no personal data; kept for accounting/audit).
# "detach": the link to the person is removed but the row stays.  "via_parent": removed together with its parent row.  "staff": staff-only data.
POLICY = {
    "advertising.AdPreference.user": "delete",
    "analytics.UsageCounter.user": "delete",
    "billing.EntitlementOverride.user": "delete",
    "billing.EntitlementOverride.created_by": "staff",
    "billing.EntitlementOverride.revoked_by": "staff",
    "billing.PaymentTransaction.user": "keep",
    "billing.Subscription.user": "keep",
    "billing.SubscriptionEvent.user": "keep",
    "billing.SubscriptionEvent.actor": "staff",
    "credits.RewardedAdSession.user": "delete",
    "credits.UsageCreditLedger.user": "delete",
    "credits.UsageCreditWallet.user": "delete",
    "domain_intel.DomainLookup.user": "delete",
    "notifications.Notification.user": "delete",
    "notifications.NotificationPreference.user": "delete",
    "organizations.Organization.owner": "delete",          # only when the owner is the sole member (see blockers)
    "organizations.OrganizationMembership.user": "delete",
    "qr_codes.Campaign.owner": "delete",
    "qr_codes.QRCode.owner": "delete",
    "qr_codes.QRDestinationHistory.changed_by": "via_parent",
    "abuse_reports.AbuseReport.reporter": "detach",
    "abuse_reports.AbuseReport.reviewer": "staff",
    "security_engine.SecurityCheck.requested_by": "detach",
    "audit.AuditLog.actor": "keep",
    "admin.LogEntry.user": "staff",
    "core.AppConfiguration.updated_by": "staff",
    "token_blacklist.OutstandingToken.user": "detach",       # all tokens are also blacklisted
    "accounts.User_groups.user": "staff",
    "accounts.User_user_permissions.user": "staff",
}


def user_relations() -> set[str]:
    """Every model field that points at a user, e.g. 'qr_codes.QRCode.owner'."""
    User = get_user_model()
    out = set()
    for f in User._meta.get_fields(include_hidden=True):
        if f.auto_created and not f.concrete and (f.one_to_many or f.one_to_one or f.many_to_many):
            out.add(f"{f.related_model._meta.label}.{f.field.name}")
    return out


def grace_days() -> int:
    try:
        return max(0, int(get_config("account.deletion_grace_days", 14)))
    except (TypeError, ValueError):
        return 14


def scheduled_for(user) -> datetime | None:
    return user.deletion_requested_at + timedelta(days=grace_days()) if user.deletion_requested_at else None


def request_deletion(user, now=None) -> bool:
    now = now or datetime.now(timezone.utc)
    if user.deletion_requested_at is not None:
        return False
    user.deletion_requested_at = now
    user.save(update_fields=["deletion_requested_at", "updated_at"])
    record_audit(actor=user, action="account.deletion_requested", obj=user)
    return True


def cancel_deletion(user) -> bool:
    if user.deletion_requested_at is None:
        return False
    user.deletion_requested_at = None
    user.save(update_fields=["deletion_requested_at", "updated_at"])
    record_audit(actor=user, action="account.deletion_cancelled", obj=user)
    return True


def blockers(user, now=None) -> list[str]:
    """Reasons a due deletion cannot run yet. Each is explained to the operator, never silently skipped."""
    from apps.billing.entitlements import access_until, current_subscription
    from apps.organizations.models import Organization, OrganizationMembership
    now = now or datetime.now(timezone.utc)
    reasons = []
    if user.is_staff or user.is_superuser:
        reasons.append("staff_account: remove staff access first (an automated deletion must never lock out administration)")
    for org in Organization.objects.filter(owner=user):
        if OrganizationMembership.objects.filter(organization=org).exclude(user=user).exists():
            reasons.append(f"owns_organization_with_members: transfer ownership of '{org.name}' first")
    sub = current_subscription(user)
    until = access_until(sub) if sub else None
    if until and until > now:
        reasons.append(f"paid_access_until:{until.isoformat()}")
    return reasons


def anonymize(user, now=None) -> dict:
    """Erase the person's data and turn the account into an anonymous tombstone. Irreversible. Call blockers() first."""
    from apps.abuse_reports.models import AbuseReport
    from apps.advertising.models import AdPreference
    from apps.analytics.models import UsageCounter
    from apps.billing.models import EntitlementOverride
    from apps.credits.models import RewardedAdSession, UsageCreditLedger, UsageCreditWallet
    from apps.domain_intel.models import DomainLookup
    from apps.notifications.models import Notification, NotificationPreference
    from apps.organizations.models import Organization, OrganizationMembership
    from apps.qr_codes.models import Campaign, QRCode
    from apps.security_engine.models import SecurityCheck
    now = now or datetime.now(timezone.utc)
    User = get_user_model()
    counts = {}
    with transaction.atomic():
        u = User.objects.select_for_update().get(pk=user.pk)
        file_fields = [f.name for f in QRCode._meta.concrete_fields if isinstance(f, models.FileField)]
        for qr in QRCode.objects.filter(owner=u):               # uploaded files are not removed by a database cascade
            for name in file_fields:
                f = getattr(qr, name)
                if f:
                    f.delete(save=False)
        counts["qr_codes"] = QRCode.objects.filter(owner=u).count()
        QRCode.objects.filter(owner=u).delete()
        Campaign.objects.filter(owner=u).delete()
        for org in Organization.objects.filter(owner=u):         # blockers() guarantees these have no other members
            org.delete()
        OrganizationMembership.objects.filter(user=u).delete()
        for model in (Notification, NotificationPreference, DomainLookup, AdPreference, UsageCounter, EntitlementOverride,
                      RewardedAdSession):
            model.objects.filter(user=u).delete()
        UsageCreditLedger.objects.filter(user=u).delete()        # queryset delete: ledger rows are append-only for everyone except erasure
        UsageCreditWallet.objects.filter(user=u).delete()
        AbuseReport.objects.filter(reporter=u).update(reporter=None)
        SecurityCheck.objects.filter(requested_by=u).update(requested_by=None)
        _revoke_tokens(u)
        u.email = f"deleted-{u.pk.hex[:12]}@deleted.invalid"
        u.display_name = ""
        u.is_active, u.is_staff, u.is_superuser, u.email_verified = False, False, False, False
        u.set_unusable_password()
        u.groups.clear()
        u.user_permissions.clear()
        u.anonymized_at = now
        u.save()
        record_audit(actor=None, action="account.anonymized", obj=u, after={"qr_codes_removed": counts["qr_codes"]})
    return counts


def _revoke_tokens(user) -> None:
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
    for t in OutstandingToken.objects.filter(user=user):
        BlacklistedToken.objects.get_or_create(token=t)


def process_due(now=None) -> dict:
    """Run by `process_account_deletions` (daily). Idempotent. Returns what happened so the operator can see it."""
    from apps.billing.entitlements import access_until, current_subscription
    from apps.billing.service import BillingError, cancel_subscription
    now = now or datetime.now(timezone.utc)
    User = get_user_model()
    cutoff = now - timedelta(days=grace_days())
    summary = {"anonymized": 0, "deferred": []}
    for user in User.objects.filter(deletion_requested_at__isnull=False, deletion_requested_at__lte=cutoff, anonymized_at__isnull=True):
        reasons = blockers(user, now)
        if any(r.startswith("paid_access_until") for r in reasons):
            sub = current_subscription(user)
            if sub and not sub.cancel_at_period_end:             # stop renewal now; the paid period is honoured, then the account goes
                try:
                    cancel_subscription(user, now=now)
                except BillingError:
                    pass
        if reasons:
            summary["deferred"].append({"user": str(user.pk), "reasons": reasons})
            continue
        anonymize(user, now)
        summary["anonymized"] += 1
    return summary
