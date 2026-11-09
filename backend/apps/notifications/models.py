from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class Notification(UUIDModel):
    class Kind(models.TextChoices):
        DESTINATION_FLAGGED = "security.destination_flagged", "Destination flagged"
        QR_DISABLED = "qr.disabled", "QR code disabled"
        QR_RESTORED = "qr.restored", "QR code restored"
        DESTINATION_CHANGED = "qr.destination_changed", "Destination changed"
        EXPIRING_SOON = "qr.expiring_soon", "QR code expiring soon"
        ABUSE_REPORT = "abuse.report_received", "Abuse report received"

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notifications")
    kind = models.CharField(max_length=40, choices=Kind.choices)
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    title = models.CharField(max_length=160)
    body = models.TextField()
    data = models.JSONField(default=dict, blank=True)
    dedupe_key = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)
    emailed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "-created_at"]), models.Index(fields=["user", "dedupe_key", "created_at"])]


class NotificationPreference(models.Model):
    """In-app notifications are always created (they are safety information). These control EMAIL only."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notification_preferences")
    email_security_alerts = models.BooleanField(default=True)     # flagged destinations, policy disables
    email_qr_status = models.BooleanField(default=True)           # disabled / restored / expiring soon
    email_abuse_reports = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
