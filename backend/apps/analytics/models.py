from django.conf import settings
from django.db import models


class ScanEvent(models.Model):
    """One scan/verification. Deliberately holds NO raw IP address, NO user agent and NO URL.

    visitor_hash is an HMAC of (UTC date, IP, user agent) that rotates every day, so it can estimate
    "unique scans per day" but cannot be linked across days or reversed to an identity.
    """

    class Outcome(models.TextChoices):
        DELIVERED = "delivered", "Verification shown (active code)"
        PAUSED = "paused", "Paused code"
        DISABLED = "disabled", "Disabled code"
        EXPIRED = "expired", "Expired code"
        BLOCKED = "blocked", "Blocked (confirmed malicious destination)"
        ANALYZED = "analyzed", "Content analysed (not a ScanSentry code)"

    class ScannerType(models.TextChoices):
        CAMERA = "camera", "Camera"
        UPLOAD = "upload", "Image upload"
        LINK = "link", "Opened link"

    qr_code = models.ForeignKey("qr_codes.QRCode", null=True, blank=True, on_delete=models.CASCADE,
                                related_name="scan_events")
    scanned_at = models.DateTimeField(db_index=True)
    outcome = models.CharField(max_length=12, choices=Outcome.choices)
    device_category = models.CharField(max_length=10, default="unknown")     # mobile|tablet|desktop|unknown
    browser_category = models.CharField(max_length=10, default="other")
    approximate_country = models.CharField(max_length=2, blank=True)
    approximate_region = models.CharField(max_length=64, blank=True)
    scanner_type = models.CharField(max_length=8, choices=ScannerType.choices, default=ScannerType.LINK)
    security_status_at_scan = models.CharField(max_length=32, blank=True)
    content_kind = models.CharField(max_length=24, blank=True)               # url/phone/wifi... (external scans)
    visitor_hash = models.CharField(max_length=16, blank=True)
    is_bot = models.BooleanField(default=False)

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [models.Index(fields=["qr_code", "scanned_at"]), models.Index(fields=["is_bot", "scanned_at"])]


class UsageCounter(models.Model):
    """Atomic usage counts per user, feature and window (day / week / month, UTC)."""

    class Window(models.TextChoices):
        DAY = "day", "Day"
        WEEK = "week", "Week"
        MONTH = "month", "Month"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="usage_counters")
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True, on_delete=models.CASCADE,
                                     related_name="usage_counters")
    feature_key = models.CharField(max_length=80)
    window = models.CharField(max_length=5, choices=Window.choices)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    current_usage = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "feature_key", "window", "period_start"],
                                               name="uniq_usage_counter")]
        indexes = [models.Index(fields=["user", "feature_key", "window", "period_start"])]
