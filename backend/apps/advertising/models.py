from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models

from apps.core.models import TimeStampedModel, UUIDModel


class AdProvider(models.Model):
    """An ad network. Identifiers stored here are PUBLIC client-side values; never put secrets in `config`."""

    key = models.SlugField(unique=True)
    name = models.CharField(max_length=80)
    platforms = models.CharField(max_length=40, help_text="comma separated: web, android")
    enabled = models.BooleanField(default=False)
    config = models.JSONField(default=dict, blank=True,
                              help_text='Public identifiers only, e.g. {"app_id": "..."}, {"publisher_id": "..."}, {"network_code": "..."}')
    notes = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return self.name


class AdPlacement(TimeStampedModel):
    class Format(models.TextChoices):
        BANNER = "banner", "Banner"
        NATIVE = "native", "Native"
        DISPLAY = "display", "Responsive display (web)"
        REWARDED = "rewarded", "Rewarded (served by the credits system)"

    key = models.CharField(max_length=80, unique=True, validators=[RegexValidator(r"^[a-z0-9][a-z0-9._-]*$", "Use lower-case letters, digits, dots, hyphens and underscores.")],
                           help_text='e.g. "android.dashboard.banner"')
    display_name = models.CharField(max_length=120)
    platform = models.CharField(max_length=10, choices=[("web", "Web"), ("android", "Android")])
    surface = models.CharField(max_length=24)
    format = models.CharField(max_length=10, choices=Format.choices)
    provider = models.ForeignKey(AdProvider, on_delete=models.PROTECT, related_name="placements")
    enabled = models.BooleanField(default=False)
    ad_unit_identifier = models.CharField(max_length=200, blank=True,
                                          help_text="The provider's ad unit / slot id for production. Never a Google test id.")
    allow_anonymous = models.BooleanField(default=False, help_text="May signed-out visitors see this placement?")
    eligible_plan_rules = models.JSONField(default=dict, blank=True,
                                           help_text='{"categories": ["free","trial"], "include_plans": [], "exclude_plans": ["business"]}. Empty = follow the global switches.')
    frequency_configuration = models.JSONField(default=dict, blank=True,
                                               help_text='Hints for the client, e.g. {"max_per_session": 3, "min_seconds_between": 60}')
    display_rules = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["platform", "surface", "key"]
        permissions = [("manage_ads", "Can manage advertising settings, providers, placements and reports")]

    def __str__(self) -> str:
        return self.key


class AdPreference(models.Model):
    """The user's own choice about ad personalisation. Consent itself lives with the provider's consent platform."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ad_preference")
    personalized_ads = models.BooleanField(null=True, blank=True, help_text="null = no choice made")
    updated_at = models.DateTimeField(auto_now=True)


class AdProviderReport(UUIDModel):
    """Figures reported BY the ad provider (imported or entered by an administrator). We never estimate or invent any."""

    provider = models.ForeignKey(AdProvider, on_delete=models.CASCADE, related_name="reports")
    platform = models.CharField(max_length=10)
    date = models.DateField()
    requests = models.BigIntegerField(null=True, blank=True)
    impressions = models.BigIntegerField(null=True, blank=True)
    fill_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    estimated_revenue = models.DecimalField(max_digits=14, decimal_places=4, null=True, blank=True)
    currency = models.CharField(max_length=3, blank=True)
    source = models.CharField(max_length=20, default="manual")      # manual | import | api
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-date"]
        constraints = [models.UniqueConstraint(fields=["provider", "platform", "date"], name="uniq_ad_report_day")]


def _validate_placement(p: "AdPlacement") -> None:
    """Rules enforced on every save (and by the admin form). The serving layer re-checks them independently."""
    from django.core.exceptions import ValidationError
    from .constants import ALLOWED_SURFACES, FORBIDDEN_SURFACES, PROVIDER_CAPABILITIES, is_test_identifier
    errors = {}
    if p.surface in FORBIDDEN_SURFACES:
        errors["surface"] = (f"Ads are never allowed on this screen ({FORBIDDEN_SURFACES[p.surface]}). "
                             f"Choose one of: {', '.join(sorted(ALLOWED_SURFACES))}.")
    elif p.surface not in ALLOWED_SURFACES:
        errors["surface"] = f"Unknown surface. Choose one of: {', '.join(sorted(ALLOWED_SURFACES))}."
    caps = PROVIDER_CAPABILITIES.get(p.provider.key) if p.provider_id else None
    if caps:
        platforms, formats = caps
        if p.platform not in platforms:
            errors["platform"] = f"{p.provider.name} does not serve the {p.platform} platform."
        if p.format not in formats:
            errors["format"] = f"{p.provider.name} does not support the '{p.format}' format."
    if is_test_identifier(p.ad_unit_identifier):
        errors["ad_unit_identifier"] = "Google's sample/test ad unit ids must never be stored here; test mode supplies them automatically."
    for name in ("eligible_plan_rules", "frequency_configuration", "display_rules"):
        if not isinstance(getattr(p, name), dict):
            errors[name] = "Must be a JSON object."
    rules = p.eligible_plan_rules if isinstance(p.eligible_plan_rules, dict) else {}
    cats = rules.get("categories", [])
    if not isinstance(cats, list) or not set(cats) <= {"anonymous", "free", "trial", "paid", "enterprise"}:
        errors["eligible_plan_rules"] = 'categories must be a list drawn from "anonymous", "free", "trial", "paid", "enterprise".'
    freq = p.frequency_configuration if isinstance(p.frequency_configuration, dict) else {}
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in freq.values()):
        errors["frequency_configuration"] = "Frequency values must be non-negative whole numbers."
    if errors:
        raise ValidationError(errors)


def _placement_clean(self):
    _validate_placement(self)


def _placement_save(self, *args, **kwargs):
    _validate_placement(self)
    super(AdPlacement, self).save(*args, **kwargs)


AdPlacement.clean = _placement_clean
AdPlacement.save = _placement_save
