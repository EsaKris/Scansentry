from django.conf import settings
from django.db import models

from apps.core.models import UUIDModel


class SecurityRule(models.Model):
    """Admin-tunable settings for a rule. Detection logic lives in code (rules.REGISTRY); the database
    only holds what an administrator may change: enabled, weight, severity and thresholds."""

    key = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=32)
    strength = models.CharField(max_length=10)                     # weak | moderate | strong (code-defined)
    severity = models.CharField(max_length=10)
    enabled = models.BooleanField(default=True)
    weight = models.PositiveSmallIntegerField()
    params = models.JSONField(default=dict, blank=True, help_text="Rule-specific thresholds")
    recommended_action = models.CharField(max_length=300, blank=True)
    version = models.PositiveSmallIntegerField(default=1)          # code version of the detection logic
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["category", "key"]

    def __str__(self) -> str:
        return self.key


class SecurityCheck(UUIDModel):
    """One security assessment of a URL/destination, with the evidence behind its classification."""

    submitted_url = models.CharField(max_length=2048)              # query/fragment removed
    normalised_url = models.CharField(max_length=2048, blank=True)
    normalised_domain = models.CharField(max_length=255, blank=True, db_index=True)
    source_type = models.CharField(max_length=16, default="api")   # api | scanner | qr_verify | recheck
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                     on_delete=models.SET_NULL, related_name="security_checks")
    domain_assessment = models.ForeignKey("domain_intel.DomainAssessment", null=True, blank=True,
                                          on_delete=models.SET_NULL, related_name="security_checks")
    rule_results = models.JSONField(default=list, blank=True)
    threat_findings = models.JSONField(default=dict, blank=True)
    redirect_trace = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(null=True, blank=True)
    risk_classification = models.CharField(max_length=32, db_index=True)
    health_score = models.PositiveSmallIntegerField(null=True, blank=True)
    confidence = models.CharField(max_length=10, default="low")
    missing_checks = models.JSONField(default=list, blank=True)
    provider_errors = models.JSONField(default=list, blank=True)
    explanation = models.JSONField(null=True, blank=True)
    scoring = models.JSONField(default=dict, blank=True)           # versions, thresholds, ruleset hash
    completion_status = models.CharField(max_length=12, default="complete")
    engine_version = models.CharField(max_length=32)
    checked_at = models.DateTimeField()
    cache_expires_at = models.DateTimeField()

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["normalised_url", "-checked_at"]),
                   models.Index(fields=["risk_classification", "-checked_at"])]

    def __str__(self) -> str:
        return f"{self.risk_classification} {self.normalised_domain}"
