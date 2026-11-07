from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class AbuseReport(UUIDModel):
    """A public report. Reports are evidence for moderators, never an automatic verdict."""

    class Category(models.TextChoices):
        SUSPICIOUS_QR = "suspicious_qr", "Suspicious QR code"
        FRAUDULENT_PAYMENT = "fraudulent_payment", "Fraudulent payment page"
        IMPERSONATION = "impersonation", "Impersonation"
        UNEXPECTED_DESTINATION = "unexpected_destination", "Unexpected destination change"
        MALICIOUS_STICKER = "malicious_sticker", "Malicious QR sticker"
        OTHER = "other", "Other abuse"

    class Status(models.TextChoices):
        NEW = "new", "New"
        IN_REVIEW = "in_review", "In review"
        ACTIONED = "actioned", "Resolved - action taken"
        DISMISSED = "dismissed", "Dismissed"

    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                 on_delete=models.SET_NULL, related_name="abuse_reports")
    # Keyed hash of the reporter identity (IP or user id). Used only for rate/duplicate control;
    # the raw IP address is never stored.
    reporter_hash = models.CharField(max_length=64, blank=True, db_index=True)
    qr_code = models.ForeignKey("qr_codes.QRCode", null=True, blank=True,
                                on_delete=models.SET_NULL, related_name="abuse_reports")
    submitted_url = models.URLField(max_length=2048, blank=True)
    target_key = models.CharField(max_length=64, db_index=True)  # sha256 of token or normalised URL
    category = models.CharField(max_length=30, choices=Category.choices)
    description = models.TextField(max_length=2000)
    evidence_file = models.ImageField(upload_to="abuse_evidence/", null=True, blank=True)

    review_status = models.CharField(max_length=12, choices=Status.choices, default=Status.NEW,
                                     db_index=True)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                 on_delete=models.SET_NULL, related_name="+")
    reviewer_notes = models.TextField(blank=True)
    resolution = models.TextField(blank=True)
    duplicate_of = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL,
                                     related_name="duplicates")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["target_key", "category"])]

    def __str__(self) -> str:
        return f"{self.category} / {self.target_key[:8]} / {self.review_status}"
