import secrets

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.core.models import TimeStampedModel, UUIDModel


def generate_public_token() -> str:
    # 18 random bytes = 144 bits of entropy -> 24 URL-safe characters.
    return secrets.token_urlsafe(18)


class Campaign(UUIDModel, TimeStampedModel):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                              related_name="campaigns")
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["owner", "name"], name="uniq_campaign_name")]

    def __str__(self) -> str:
        return self.name


class QRCode(UUIDModel, TimeStampedModel):
    class Type(models.TextChoices):
        URL = "url", "Website URL"
        WHATSAPP = "whatsapp", "WhatsApp"
        PHONE = "phone", "Telephone"
        EMAIL = "email", "Email"
        WIFI = "wifi", "Wi-Fi"
        VCARD = "vcard", "Contact card"
        SOCIAL = "social", "Social profile"
        FILE = "file", "PDF / file link"
        LANDING = "landing", "Custom landing page"
        TEXT = "text", "Plain text"

    class Mode(models.TextChoices):
        STATIC = "static", "Static"
        DYNAMIC = "dynamic", "Dynamic"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        DISABLED = "disabled", "Disabled"

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                              related_name="qr_codes")
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True,
                                     on_delete=models.SET_NULL, related_name="qr_codes")
    campaign = models.ForeignKey(Campaign, null=True, blank=True, on_delete=models.SET_NULL,
                                 related_name="qr_codes")
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    qr_type = models.CharField(max_length=20, choices=Type.choices)
    code_mode = models.CharField(max_length=10, choices=Mode.choices, default=Mode.STATIC)

    # Random token used in the public ScanSentry URL (dynamic only). Never a database id.
    public_token = models.CharField(max_length=64, unique=True, null=True, blank=True,
                                    default=None, editable=False)
    current_destination = models.URLField(max_length=2048, blank=True)
    source_data = models.JSONField(default=dict, blank=True)
    encoded_payload = models.TextField()
    style = models.JSONField(default=dict, blank=True)
    logo = models.ImageField(upload_to="qr_logos/", blank=True)

    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    status_reason = models.CharField(max_length=255, blank=True)
    disabled_by_staff = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["owner", "status"]),
                   models.Index(fields=["owner", "created_at"])]
        constraints = [
            models.CheckConstraint(
                name="dynamic_requires_token_and_destination",
                condition=Q(code_mode="static")
                | (Q(public_token__isnull=False) & ~Q(current_destination="")),
            )
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.code_mode})"

    @property
    def is_dynamic(self) -> bool:
        return self.code_mode == self.Mode.DYNAMIC

    @property
    def effective_status(self) -> str:
        """active / paused / disabled / expired."""
        if self.status == self.Status.ACTIVE and self.expires_at and self.expires_at <= timezone.now():
            return "expired"
        return self.status


class QRDestinationHistory(models.Model):
    """Append-only record of destination changes."""

    id = models.BigAutoField(primary_key=True)
    qr_code = models.ForeignKey(QRCode, on_delete=models.CASCADE, related_name="history")
    previous_destination = models.URLField(max_length=2048, blank=True)
    new_destination = models.URLField(max_length=2048)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
                                   related_name="+")
    change_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name_plural = "QR destination history"
