from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class DomainAssessment(UUIDModel):
    """One assessment run. Runs are never overwritten, so changes can be compared over time."""

    domain = models.CharField(max_length=255, db_index=True)            # ASCII host assessed
    registrable_domain = models.CharField(max_length=255, db_index=True)
    display_domain = models.CharField(max_length=255, blank=True)

    # registration (RDAP)
    registration_created_at = models.DateTimeField(null=True, blank=True)
    registration_age_days = models.IntegerField(null=True, blank=True)
    age_group = models.CharField(max_length=24, default="unknown")
    registrar_name = models.CharField(max_length=255, blank=True)
    registration_expires_at = models.DateTimeField(null=True, blank=True)
    registration_updated_at = models.DateTimeField(null=True, blank=True)
    raw_status_flags = models.JSONField(default=list, blank=True)
    registration_status = models.CharField(max_length=32, default="UNKNOWN")
    registration_status_explanation = models.TextField(blank=True)
    rdap_data = models.JSONField(default=dict, blank=True)

    # observations (kept as structured results)
    hosting_status = models.CharField(max_length=48, default="UNKNOWN")
    dns_status = models.CharField(max_length=24, blank=True)
    tls_status = models.CharField(max_length=24, blank=True)
    http_status = models.IntegerField(null=True, blank=True)
    dns_results = models.JSONField(default=dict, blank=True)
    tls_results = models.JSONField(default=dict, blank=True)
    http_results = models.JSONField(default=dict, blank=True)

    # scores
    domain_health_score = models.IntegerField(null=True, blank=True)
    health_details = models.JSONField(default=dict, blank=True)
    security_risk_score = models.IntegerField(null=True, blank=True)    # filled by the security engine
    risk_classification = models.CharField(max_length=32, blank=True)
    confidence = models.CharField(max_length=10, default="low")

    missing_checks = models.JSONField(default=list, blank=True)
    provider_errors = models.JSONField(default=list, blank=True)
    completion_status = models.CharField(max_length=12, default="complete")  # complete|partial|failed
    error_state = models.CharField(max_length=255, blank=True)
    source_provider = models.CharField(max_length=255, blank=True)
    engine_version = models.CharField(max_length=32)
    checked_at = models.DateTimeField()
    cache_expires_at = models.DateTimeField()

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["domain", "-checked_at"])]

    def __str__(self) -> str:
        return f"{self.domain} @ {self.checked_at:%Y-%m-%d %H:%M}"


class DomainObservation(models.Model):
    assessment = models.ForeignKey(DomainAssessment, on_delete=models.CASCADE, related_name="observations")
    observation_type = models.CharField(max_length=24)     # rdap | dns | tls | http
    observation_value = models.JSONField(default=dict)
    result_status = models.CharField(max_length=48)
    evidence = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField()

    class Meta:
        ordering = ["observed_at", "id"]
        indexes = [models.Index(fields=["assessment", "observation_type"])]


class DomainLookup(models.Model):
    """A user's request for an assessment (powers history and, later, usage metering)."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="domain_lookups")
    assessment = models.ForeignKey(DomainAssessment, on_delete=models.CASCADE, related_name="lookups")
    submitted_value = models.CharField(max_length=300)
    served_from_cache = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "-created_at"])]
