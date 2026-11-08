from django.db import models

from apps.core.models import UUIDModel


class ThreatProvider(models.Model):
    """Operational configuration + health of a threat-intelligence adapter.

    Secrets are never stored here: `credential_ref` is the NAME of an environment variable.
    """

    key = models.SlugField(unique=True)            # must match an adapter in providers.ADAPTERS
    name = models.CharField(max_length=120)
    enabled = models.BooleanField(default=False)
    credential_ref = models.CharField(max_length=80, blank=True,
                                      help_text="Name of the environment variable holding the API key.")
    timeout_seconds = models.FloatField(default=4.0)
    retry_attempts = models.PositiveSmallIntegerField(default=2, help_text="Total attempts for transient errors.")
    rate_limit_per_minute = models.PositiveIntegerField(default=60, help_text="0 = unlimited")
    config = models.JSONField(default=dict, blank=True, help_text='e.g. {"cache_ttl_seconds": 0}')
    # usage metrics / health (written by the service, read-only in admin)
    request_count = models.PositiveBigIntegerField(default=0)
    error_count = models.PositiveBigIntegerField(default=0)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_error_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return self.name


class ThreatIndicator(UUIDModel):
    """A positive finding (from a provider or added by staff) kept as evidence and for the local blocklist."""

    class Type(models.TextChoices):
        DOMAIN = "domain", "Domain"
        URL = "url", "URL"

    indicator = models.CharField(max_length=2048, db_index=True)       # host/registrable or URL (no query)
    indicator_type = models.CharField(max_length=10, choices=Type.choices, default=Type.DOMAIN)
    threat_category = models.CharField(max_length=32)                  # malware|phishing|unwanted_software|suspicious|other
    provider = models.CharField(max_length=64, db_index=True)
    severity = models.CharField(max_length=10, default="high")
    source_reference = models.CharField(max_length=255, blank=True)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    checked_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)
    active = models.BooleanField(default=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["indicator", "provider", "threat_category"],
                                               name="uniq_threat_indicator")]
        indexes = [models.Index(fields=["indicator_type", "indicator", "active"])]

    def __str__(self) -> str:
        return f"{self.threat_category}: {self.indicator} ({self.provider})"
