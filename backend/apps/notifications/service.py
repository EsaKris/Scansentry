"""Creating notifications. Messages show host names only, never full URLs (paths/queries may hold secrets)."""
import logging
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.core.mail import send_mail
from django.db.models import Q
from django.utils import timezone

from .models import Notification, NotificationPreference

log = logging.getLogger(__name__)
DEDUPE_HOURS = 24
K = Notification.Kind
S = Notification.Severity
# which preference governs email for each kind
EMAIL_PREF = {K.DESTINATION_FLAGGED: "email_security_alerts", K.QR_DISABLED: "email_qr_status",
              K.QR_RESTORED: "email_qr_status", K.EXPIRING_SOON: "email_qr_status",
              K.ABUSE_REPORT: "email_abuse_reports"}


def host_of(url: str) -> str:
    return urlsplit(url or "").hostname or "(unknown)"


def preferences(user) -> NotificationPreference:
    return NotificationPreference.objects.get_or_create(user=user)[0]


def notify(user, kind, *, title: str, body: str, severity=S.INFO, data=None, dedupe_key: str = "", email: bool = True):
    """Create an in-app notification (deduplicated) and email it when the user's preferences allow."""
    if dedupe_key:
        since = timezone.now() - timedelta(hours=DEDUPE_HOURS)
        if Notification.objects.filter(user=user, dedupe_key=dedupe_key, created_at__gte=since).exists():
            return None
    n = Notification.objects.create(user=user, kind=kind, severity=severity, title=title[:160], body=body,
                                    data=data or {}, dedupe_key=dedupe_key)
    pref_field = EMAIL_PREF.get(kind)
    if email and pref_field and severity != S.INFO and user.is_active and user.email_verified \
            and getattr(preferences(user), pref_field):
        try:
            send_mail(f"[ScanSentry] {title}", f"{body}\n\nOpen ScanSentry to review: {settings.FRONTEND_URL}/notifications",
                      settings.DEFAULT_FROM_EMAIL, [user.email])
            Notification.objects.filter(pk=n.pk).update(emailed_at=timezone.now())
        except Exception:
            log.exception("could not email notification")
    return n


# ---- events ---------------------------------------------------------------------------------------------------
def qrs_for_destination(key: str):
    from apps.qr_codes.models import QRCode
    return QRCode.objects.filter(code_mode="dynamic", status="active").filter(
        Q(current_destination=key) | Q(current_destination__startswith=key + "?") | Q(current_destination__startswith=key + "#")
    ).select_related("owner")


def alert_destination_flagged(check) -> int:
    """Tell the owner of every active dynamic code pointing at a destination now judged high risk / malicious."""
    if check.risk_classification not in ("high_risk", "known_malicious") or not check.normalised_url:
        return 0
    n = 0
    label = "Known malicious" if check.risk_classification == "known_malicious" else "High risk"
    for qr in qrs_for_destination(check.normalised_url):
        host = host_of(qr.current_destination)
        extra = (" ScanSentry will not forward people to it." if check.risk_classification == "known_malicious" else
                 " People scanning it will see a strong warning.")
        made = notify(qr.owner, K.DESTINATION_FLAGGED, severity=S.CRITICAL,
                      title=f"Security alert: the destination of “{qr.name}” was flagged",
                      body=f"The destination ({host}) of your QR code “{qr.name}” was assessed as: {label}.{extra} "
                           "Review the destination and change or disable the code if you did not expect this.",
                      data={"qr_id": str(qr.id), "check_id": str(check.id), "classification": check.risk_classification,
                            "host": host},
                      dedupe_key=f"flag:{qr.id}:{check.risk_classification}")
        n += bool(made)
    return n


def alert_qr_disabled(qr, reason: str) -> None:
    automated = "malicious" in (reason or "").lower()
    notify(qr.owner, K.QR_DISABLED, severity=S.CRITICAL,
           title=f"Your QR code “{qr.name}” was disabled",
           body=("ScanSentry disabled your QR code “" + qr.name + "” automatically because its destination "
                 f"({host_of(qr.current_destination)}) was confirmed malicious by a threat-intelligence source."
                 if automated else
                 f"ScanSentry staff disabled your QR code “{qr.name}”. Reason: {reason or 'not specified'}. "
                 "Contact support if you believe this is a mistake."),
           data={"qr_id": str(qr.id), "automated": automated}, dedupe_key=f"disabled:{qr.id}")


def alert_qr_restored(qr) -> None:
    notify(qr.owner, K.QR_RESTORED, severity=S.INFO, title=f"Your QR code “{qr.name}” was restored",
           body=f"ScanSentry staff restored your QR code “{qr.name}”. It is active again.",
           data={"qr_id": str(qr.id)}, email=False)


def alert_destination_changed(qr, old: str, new: str) -> None:
    notify(qr.owner, K.DESTINATION_CHANGED, severity=S.INFO,
           title=f"Destination changed for “{qr.name}”",
           body=f"The destination of “{qr.name}” changed from {host_of(old)} to {host_of(new)}. "
                "If you did not make this change, secure your account and review the activity history.",
           data={"qr_id": str(qr.id), "from_host": host_of(old), "to_host": host_of(new)}, email=False)


def alert_abuse_report(qr, category: str) -> None:
    notify(qr.owner, K.ABUSE_REPORT, severity=S.WARNING, title=f"Someone reported your QR code “{qr.name}”",
           body=f"A report was submitted about your QR code “{qr.name}” (category: {category.replace('_', ' ')}). "
                "Reports are reviewed by moderators and do not change your code on their own. "
                "Check that the destination is what you expect.",
           data={"qr_id": str(qr.id), "category": category}, dedupe_key=f"abuse:{qr.id}:{category}")


def send_expiry_reminders(days: int = 3) -> int:
    from apps.qr_codes.models import QRCode
    now = timezone.now()
    count = 0
    for qr in QRCode.objects.filter(status="active", expires_at__gt=now, expires_at__lte=now + timedelta(days=days)).select_related("owner"):
        made = notify(qr.owner, K.EXPIRING_SOON, severity=S.WARNING,
                      title=f"“{qr.name}” expires on {qr.expires_at:%Y-%m-%d}",
                      body=f"Your QR code “{qr.name}” will stop working on {qr.expires_at:%Y-%m-%d %H:%M} UTC. "
                           "Extend its expiry date if it should stay active.",
                      data={"qr_id": str(qr.id), "expires_at": qr.expires_at.isoformat()},
                      dedupe_key=f"expiring:{qr.id}:{qr.expires_at:%Y%m%d}")
        count += bool(made)
    return count
