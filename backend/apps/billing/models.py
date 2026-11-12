from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core.models import TimeStampedModel, UUIDModel


class Plan(UUIDModel, TimeStampedModel):
    """A commercial plan. Nothing about a plan is hardcoded: it is all admin-configured."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"

    class Interval(models.TextChoices):
        WEEK = "week", "Weekly"
        MONTH = "month", "Monthly"
        QUARTER = "quarter", "Quarterly"
        YEAR = "year", "Yearly"

    name = models.CharField(max_length=80)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    is_public = models.BooleanField(default=True, help_text="Private plans never appear on the pricing page.")
    is_free = models.BooleanField(default=False, help_text="No payment needed (the base tier).")
    billing_interval = models.CharField(max_length=10, choices=Interval.choices, default=Interval.MONTH)
    trial_days = models.PositiveIntegerField(default=0)
    grace_period_days = models.PositiveIntegerField(default=0)
    display_order = models.PositiveIntegerField(default=0)
    featured = models.BooleanField(default=False)
    provider_refs = models.JSONField(default=dict, blank=True, help_text='e.g. {"paystack_plan_code": "PLN_xxx"} for provider-managed recurring billing')

    class Meta:
        ordering = ["display_order", "name"]
        permissions = [("manage_pricing", "Can manage pricing, plans, features and pricing switches")]

    def __str__(self) -> str:
        return self.name


class PlanPrice(models.Model):
    """One price per currency, so a plan can be sold in NGN and USD (where the provider supports it)."""

    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name="prices")
    currency = models.CharField(max_length=3)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    active = models.BooleanField(default=True)
    provider_refs = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["plan", "currency"], name="uniq_plan_currency"),
                       models.CheckConstraint(condition=Q(amount__gt=0), name="price_positive")]
        ordering = ["currency"]

    def save(self, *args, **kwargs):
        self.currency = self.currency.upper()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.plan.slug} {self.amount} {self.currency}"


class FeatureDefinition(models.Model):
    class DataType(models.TextChoices):
        BOOLEAN = "boolean", "On/off"
        INTEGER = "integer", "Number / limit"
        STRING = "string", "Text"
        JSON = "json", "JSON"

    key = models.CharField(max_length=80, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    data_type = models.CharField(max_length=10, choices=DataType.choices, default=DataType.BOOLEAN)
    default_value = models.JSONField(null=True, blank=True,
                                     help_text="Boolean features: true/false. Number features: the default limit (empty = unlimited).")
    measurable = models.BooleanField(default=False)
    assignable = models.BooleanField(default=True, help_text="Available for assignment to plans")
    active = models.BooleanField(default=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return self.key


class PlanFeature(models.Model):
    plan = models.ForeignKey(Plan, on_delete=models.CASCADE, related_name="features")
    feature = models.ForeignKey(FeatureDefinition, on_delete=models.CASCADE, related_name="plan_features")
    enabled = models.BooleanField(default=True)
    limit_value = models.BigIntegerField(null=True, blank=True, help_text="Empty = unlimited (when enabled)")
    configuration = models.JSONField(default=dict, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["plan", "feature"], name="uniq_plan_feature")]

    def __str__(self) -> str:
        return f"{self.plan.slug}:{self.feature.key}"


class Subscription(UUIDModel, TimeStampedModel):
    class Status(models.TextChoices):
        TRIALING = "trialing", "Trial"
        ACTIVE = "active", "Active"
        PENDING_PAYMENT = "pending_payment", "Pending payment"
        PAST_DUE = "past_due", "Past due"
        GRACE_PERIOD = "grace_period", "Grace period"
        CANCELLED = "cancelled", "Cancelled (access until period end)"
        EXPIRED = "expired", "Expired"
        SUSPENDED = "suspended", "Suspended"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="subscriptions")
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True, on_delete=models.SET_NULL,
                                     related_name="subscriptions")
    plan = models.ForeignKey(Plan, on_delete=models.PROTECT, related_name="subscriptions")
    is_current = models.BooleanField(default=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING_PAYMENT, db_index=True)
    billing_provider = models.CharField(max_length=20, blank=True)
    currency = models.CharField(max_length=3, blank=True)
    external_subscription_reference = models.CharField(max_length=120, blank=True)
    external_customer_reference = models.CharField(max_length=120, blank=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    cancelled_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user"], condition=Q(is_current=True), name="one_current_subscription")]
        indexes = [models.Index(fields=["status", "current_period_end"])]
        permissions = [("manage_subscriptions", "Can extend, suspend and restore subscriptions")]


class SubscriptionEvent(models.Model):
    """Append-only history of every subscription / entitlement change."""

    subscription = models.ForeignKey(Subscription, null=True, blank=True, on_delete=models.SET_NULL, related_name="events")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="subscription_events")
    event_type = models.CharField(max_length=40, db_index=True)
    from_status = models.CharField(max_length=16, blank=True)
    to_status = models.CharField(max_length=16, blank=True)
    from_plan = models.ForeignKey(Plan, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    to_plan = models.ForeignKey(Plan, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    detail = models.JSONField(default=dict, blank=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]


class EntitlementOverride(models.Model):
    """Administrative grants. Every one needs an internal note and is audited."""

    class Kind(models.TextChoices):
        FEATURE = "feature", "Feature grant / revoke"
        PLAN_TRIAL = "plan_trial", "Temporary premium (plan) access"
        PROMOTION = "promotion", "Promotional entitlement"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="entitlement_overrides")
    kind = models.CharField(max_length=12, choices=Kind.choices)
    feature = models.ForeignKey(FeatureDefinition, null=True, blank=True, on_delete=models.CASCADE, related_name="overrides")
    plan = models.ForeignKey(Plan, null=True, blank=True, on_delete=models.CASCADE, related_name="overrides")
    enabled = models.BooleanField(default=True, help_text="False revokes the feature")
    limit_value = models.BigIntegerField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    note = models.TextField()
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    revoke_note = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        permissions = [("grant_entitlements", "Can grant, revoke and extend entitlements")]


class PaymentTransaction(UUIDModel):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Succeeded"
        FAILED = "failed", "Failed"
        ABANDONED = "abandoned", "Abandoned"
        REFUNDED = "refunded", "Refunded"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="payments")
    subscription = models.ForeignKey(Subscription, null=True, blank=True, on_delete=models.SET_NULL, related_name="payments")
    plan = models.ForeignKey(Plan, null=True, on_delete=models.SET_NULL, related_name="payments")
    provider = models.CharField(max_length=20)
    provider_reference = models.CharField(max_length=120)
    amount = models.DecimalField(max_digits=12, decimal_places=2)       # always calculated from the DB price
    currency = models.CharField(max_length=3)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING, db_index=True)
    payment_method = models.CharField(max_length=30, blank=True)
    customer_reference = models.CharField(max_length=120, blank=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [models.UniqueConstraint(fields=["provider", "provider_reference"], name="uniq_payment_reference")]
        permissions = [("view_payments", "Can view payment and revenue data")]


class PaymentWebhookEvent(models.Model):
    class Processing(models.TextChoices):
        RECEIVED = "received", "Received"
        PROCESSED = "processed", "Processed"
        IGNORED = "ignored", "Ignored"
        FAILED = "failed", "Failed"

    provider = models.CharField(max_length=20)
    provider_event_id = models.CharField(max_length=200)
    event_type = models.CharField(max_length=60, blank=True)
    payload = models.JSONField(default=dict, blank=True)          # whitelisted fields only; never raw card data
    processing_status = models.CharField(max_length=10, choices=Processing.choices, default=Processing.RECEIVED)
    processed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.CharField(max_length=255, blank=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["provider", "provider_event_id"], name="uniq_webhook_event")]
        ordering = ["-created_at"]
