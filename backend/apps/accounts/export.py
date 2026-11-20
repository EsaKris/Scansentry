"""A person's own data, as JSON (GDPR-style 'access' / 'portability').

Only data about THIS user. Never: password hashes, session tokens, other people's data, staff-internal notes, or reporter/IP hashes.
Fields are included by default and excluded by name below, so new fields are exported rather than forgotten; secrets are excluded by pattern as a second guard.
"""
from datetime import datetime, timezone

from django.db import models

MAX_ROWS = 10000
# never exported, by field name (staff-internal, or secrets)
EXCLUDE = {"password", "unique_session_token", "reviewer_notes", "reviewer", "reporter_hash", "target_key", "duplicate_of", "note", "revoke_note",
           "created_by", "revoked_by", "actor", "dedupe_key", "idempotency_key", "logo", "status_reason"}
ALLOW_TOKENISH = {"public_token"}           # the public link of the user's own QR code: not a secret
SECRET_PATTERNS = ("password", "secret", "hash", "signature", "token")


def _skip(name: str) -> bool:
    return name in EXCLUDE or (name not in ALLOW_TOKENISH and any(p in name for p in SECRET_PATTERNS))


def rows(qs, *, extra_exclude=()):
    out, truncated = [], False
    for i, obj in enumerate(qs):
        if i >= MAX_ROWS:
            truncated = True
            break
        row = {}
        for f in obj._meta.concrete_fields:
            if _skip(f.name) or f.name in extra_exclude:
                continue
            if isinstance(f, models.FileField):
                v = getattr(obj, f.name)
                row[f.name] = v.name if v else None
            elif f.is_relation:
                row[f"{f.name}_id"] = str(getattr(obj, f.attname)) if getattr(obj, f.attname) is not None else None
            else:
                row[f.name] = getattr(obj, f.name)
        out.append(row)
    return {"items": out, "count": len(out), "truncated": truncated}


def export_user_data(user) -> dict:
    from apps.abuse_reports.models import AbuseReport
    from apps.advertising.models import AdPreference
    from apps.analytics.models import UsageCounter
    from apps.audit.models import AuditLog
    from apps.billing.models import EntitlementOverride, PaymentTransaction, Subscription, SubscriptionEvent
    from apps.credits.models import RewardedAdSession, UsageCreditLedger, UsageCreditWallet
    from apps.domain_intel.models import DomainLookup
    from apps.notifications.models import Notification, NotificationPreference
    from apps.organizations.models import OrganizationMembership
    from apps.qr_codes.models import Campaign, QRCode, QRDestinationHistory
    from apps.security_engine.models import SecurityCheck

    def mine(model, **kw):
        return rows(model.objects.filter(**(kw or {"user": user})).order_by("pk"))

    qr_ids = list(QRCode.objects.filter(owner=user).values_list("pk", flat=True))
    wallet = UsageCreditWallet.objects.filter(user=user).first()
    return {
        "export": {"generated_at": datetime.now(timezone.utc), "format_version": 1,
                   "about": "Everything ScanSentry holds about your account. It excludes secrets, other people's data and internal staff notes. "
                            "Anonymous scan analytics are not tied to you and are not included."},
        "account": {"id": str(user.pk), "email": user.email, "display_name": user.display_name, "email_verified": user.email_verified,
                    "created_at": user.created_at, "deletion_requested_at": user.deletion_requested_at},
        "qr_codes": rows(QRCode.objects.filter(owner=user).order_by("created_at")),
        "qr_destination_history": rows(QRDestinationHistory.objects.filter(qr_code_id__in=qr_ids).order_by("created_at"), extra_exclude=("changed_by",)),
        "campaigns": rows(Campaign.objects.filter(owner=user)),
        "notifications": mine(Notification),
        "notification_preferences": mine(NotificationPreference),
        "advertising_preferences": mine(AdPreference),
        "domain_lookups": rows(DomainLookup.objects.filter(user=user).select_related("assessment")),
        "security_checks_requested": rows(SecurityCheck.objects.filter(requested_by=user), extra_exclude=("requested_by",)),
        "subscriptions": mine(Subscription),
        "subscription_events": mine(SubscriptionEvent),
        "payments": mine(PaymentTransaction),
        "entitlement_overrides": mine(EntitlementOverride),
        "usage_counters": mine(UsageCounter),
        "credits": {"balance": wallet.available_balance if wallet else 0, "earning_suspended": wallet.earning_suspended if wallet else False,
                    "ledger": mine(UsageCreditLedger), "rewarded_ad_sessions": mine(RewardedAdSession)},
        "abuse_reports_submitted": rows(AbuseReport.objects.filter(reporter=user)),
        "organization_memberships": mine(OrganizationMembership),
        "account_activity": rows(AuditLog.objects.filter(actor=user).order_by("created_at"), extra_exclude=("before_state", "after_state")),
    }
