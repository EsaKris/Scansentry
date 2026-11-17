"""ScanSentry Credits: internal usage units. No cash value, non-transferable, non-withdrawable, cannot buy subscriptions.

The LEDGER is authoritative and append-only. `UsageCreditWallet.available_balance` is a transactionally maintained total
and `CreditLot` rows track which credits expire when (they decide what gets spent first). A consistency check compares all three.
"""
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

from apps.core.models import TimeStampedModel, UUIDModel


class UsageCreditWallet(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="credit_wallet")
    available_balance = models.PositiveBigIntegerField(default=0)       # the database refuses a negative balance
    earning_suspended = models.BooleanField(default=False, help_text="Abuse control: no new rewarded-ad credits can be earned.")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        permissions = [
            ("manage_credits", "Can grant, reverse and correct ScanSentry Credits"),
            ("view_credit_reports", "Can view credit and rewarded-ad reporting"),
        ]

    def __str__(self) -> str:
        return f"wallet {self.user_id}: {self.available_balance}"


class UsageCreditLedger(models.Model):
    """One credit movement. Rows are never edited or deleted (enforced in save/delete and read-only in the admin)."""

    class Type(models.TextChoices):
        REWARDED_AD_EARNED = "rewarded_ad_earned", "Earned from a rewarded ad"
        PROMOTIONAL_CREDIT = "promotional_credit", "Promotional credit"
        ADMIN_GRANT = "admin_grant", "Administrator grant"
        FEATURE_USAGE = "feature_usage", "Spent on a feature"
        CREDIT_EXPIRY = "credit_expiry", "Expired"
        ADMIN_REVERSAL = "admin_reversal", "Administrator reversal"
        USAGE_REFUND = "usage_refund", "Refund of a failed credit-funded use"

    CREDIT_TYPES = (Type.REWARDED_AD_EARNED, Type.PROMOTIONAL_CREDIT, Type.ADMIN_GRANT, Type.USAGE_REFUND)
    DEBIT_TYPES = (Type.FEATURE_USAGE, Type.CREDIT_EXPIRY, Type.ADMIN_REVERSAL)

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(UsageCreditWallet, on_delete=models.CASCADE, related_name="entries")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="credit_entries")
    transaction_type = models.CharField(max_length=24, choices=Type.choices)
    amount = models.BigIntegerField(help_text="Positive for a credit, negative for a debit")
    balance_after = models.PositiveBigIntegerField()
    feature_key = models.CharField(max_length=80, blank=True)
    rewarded_ad_session = models.ForeignKey("credits.RewardedAdSession", null=True, blank=True, on_delete=models.SET_NULL,
                                            related_name="ledger_entries")
    provider_transaction_id = models.CharField(max_length=200, blank=True)
    idempotency_key = models.CharField(max_length=200, unique=True)
    reason = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        constraints = [
            models.CheckConstraint(name="credit_ledger_sign", condition=(
                Q(transaction_type__in=["rewarded_ad_earned", "promotional_credit", "admin_grant", "usage_refund"], amount__gt=0)
                | Q(transaction_type__in=["feature_usage", "credit_expiry", "admin_reversal"], amount__lt=0))),
        ]
        indexes = [models.Index(fields=["user", "created_at"]), models.Index(fields=["transaction_type", "created_at"])]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError("Ledger entries are append-only and cannot be changed.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Ledger entries are append-only and cannot be deleted.")


class CreditLot(models.Model):
    """Which part of a credit grant is still unspent, and when it expires. Spending takes the soonest-expiring credits first."""

    entry = models.OneToOneField(UsageCreditLedger, on_delete=models.CASCADE, related_name="lot")
    wallet = models.ForeignKey(UsageCreditWallet, on_delete=models.CASCADE, related_name="lots")
    amount = models.PositiveBigIntegerField()
    remaining = models.PositiveBigIntegerField()
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Empty = never expires")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.CheckConstraint(name="credit_lot_remaining_le_amount", condition=Q(remaining__lte=models.F("amount")))]
        indexes = [models.Index(fields=["wallet", "remaining", "expires_at"])]


class RewardedAdOffer(UUIDModel, TimeStampedModel):
    """An administrator-configured rewarded-ad offer. Every commercial value lives here, not in code."""

    class Platform(models.TextChoices):
        WEB = "web", "Web"
        ANDROID = "android", "Android"
        BOTH = "both", "Both (only for a provider that serves both)"

    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=False)
    platform = models.CharField(max_length=8, choices=Platform.choices)
    provider = models.ForeignKey("advertising.AdProvider", on_delete=models.PROTECT, related_name="rewarded_offers")
    reward_amount = models.PositiveIntegerField(help_text="ScanSentry Credits granted per verified completed ad")
    eligible_plans = models.JSONField(default=list, blank=True, help_text='Plan slugs, e.g. ["free"]. Empty = every plan.')
    eligible_categories = models.JSONField(default=list, blank=True,
                                           help_text='Account categories from "free", "trial", "paid", "enterprise". Empty = all.')
    eligible_features = models.JSONField(default=list, blank=True,
                                         help_text='Features the credits are meant for (shown to the user), e.g. ["domain.lookups"]. Empty = any credit-funded feature.')
    maximum_claims_per_day = models.PositiveIntegerField(null=True, blank=True)
    maximum_claims_per_week = models.PositiveIntegerField(null=True, blank=True)
    maximum_claims_per_month = models.PositiveIntegerField(null=True, blank=True)
    cooldown_seconds = models.PositiveIntegerField(default=0)
    credit_expiry_days = models.PositiveIntegerField(null=True, blank=True, help_text="Empty = credits from this offer never expire")
    starts_at = models.DateTimeField(null=True, blank=True)
    ends_at = models.DateTimeField(null=True, blank=True)
    ad_unit_identifier = models.CharField(max_length=200, blank=True,
                                          help_text="Production rewarded ad unit id (public client-side value). Never a Google test id.")
    configuration = models.JSONField(default=dict, blank=True, help_text=(
        'Optional: {"allowed_countries": ["NG"], "blocked_countries": [], "test_ad_unit_identifier": "..."} '
        "(country rules need GEO_COUNTRY_HEADER; the test unit is only used for Ad Manager web in test mode)."))

    class Meta:
        ordering = ["platform", "name"]
        constraints = [models.CheckConstraint(name="rewarded_offer_amount_positive", condition=Q(reward_amount__gt=0))]

    def __str__(self) -> str:
        return self.name


class RewardedAdSession(UUIDModel):
    """A short-lived, single-use rewarded-ad session created by the backend. Credits are granted only on a validated completion."""

    class Status(models.TextChoices):
        CREATED = "created", "Created"
        AD_AVAILABLE = "ad_available", "Ad available"
        STARTED = "started", "Started"
        REWARDED = "rewarded", "Rewarded"
        CLOSED_WITHOUT_REWARD = "closed_without_reward", "Closed without reward"
        EXPIRED = "expired", "Expired"
        REJECTED = "rejected", "Rejected"

    class Verification(models.TextChoices):
        PENDING = "pending", "Pending"
        VERIFIED = "verified", "Verified by the provider's signed callback"
        CLIENT_ATTESTED = "client_attested", "Client attested (not provider-verified)"
        FAILED = "failed", "Failed"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rewarded_sessions")
    rewarded_ad_offer = models.ForeignKey(RewardedAdOffer, on_delete=models.PROTECT, related_name="sessions")
    platform = models.CharField(max_length=8)
    provider = models.CharField(max_length=40)
    unique_session_token = models.CharField(max_length=64, unique=True)
    provider_transaction_id = models.CharField(max_length=200, null=True, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.CREATED)
    expected_reward_amount = models.PositiveIntegerField()
    credit_expiry_days = models.PositiveIntegerField(null=True, blank=True)       # snapshot of the offer at creation
    ad_unit_id = models.CharField(max_length=200, blank=True)                      # the unit we told the client to use
    provider_verification_status = models.CharField(max_length=16, choices=Verification.choices, default=Verification.PENDING)
    close_reason = models.CharField(max_length=40, blank=True)
    rejection_reason = models.CharField(max_length=60, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    started_at = models.DateTimeField(null=True, blank=True)
    client_reward_reported_at = models.DateTimeField(null=True, blank=True)       # informational only: never grants anything
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [models.UniqueConstraint(fields=["provider", "provider_transaction_id"],
                                               condition=Q(provider_transaction_id__isnull=False), name="uniq_reward_provider_tx")]
        indexes = [models.Index(fields=["user", "status", "completed_at"]), models.Index(fields=["rewarded_ad_offer", "user"])]


class RewardCallbackEvent(models.Model):
    """Every provider callback we received, for administrator review. Holds no IP address and no signature."""

    provider = models.CharField(max_length=40)
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)
    outcome = models.CharField(max_length=64)
    session = models.ForeignKey(RewardedAdSession, null=True, blank=True, on_delete=models.SET_NULL, related_name="callbacks")
    provider_transaction_id = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["-received_at"]


# ---- offer validation (on every save and in the admin form) --------------------------------------------------------------
def _validate_offer(o: "RewardedAdOffer") -> None:
    from apps.advertising.constants import PROVIDER_CAPABILITIES, is_test_identifier
    errors = {}
    caps = PROVIDER_CAPABILITIES.get(o.provider.key) if o.provider_id else None
    if caps is not None:
        provider_platforms, formats = caps
        if "rewarded" not in formats:
            errors["provider"] = f"{o.provider.name} cannot serve rewarded ads (ordinary display/banner/native ads are never a reward mechanism)."
        else:
            wanted = {"web", "android"} if o.platform == "both" else {o.platform}
            if not wanted <= provider_platforms:
                errors["platform"] = (f"{o.provider.name} serves only {', '.join(sorted(provider_platforms))}. "
                                      "Create one offer per platform/provider.")
    if is_test_identifier(o.ad_unit_identifier):
        errors["ad_unit_identifier"] = "Google's sample/test ad unit ids must never be stored here; test mode supplies them automatically."
    for name in ("eligible_plans", "eligible_categories", "eligible_features"):
        v = getattr(o, name)
        if not isinstance(v, list) or any(not isinstance(i, str) for i in v):
            errors[name] = "Must be a JSON list of text values."
    if isinstance(o.eligible_categories, list) and not set(o.eligible_categories) <= {"free", "trial", "paid", "enterprise"}:
        errors["eligible_categories"] = 'Use values from "free", "trial", "paid", "enterprise".'
    if not isinstance(o.configuration, dict):
        errors["configuration"] = "Must be a JSON object."
    else:
        for k in ("allowed_countries", "blocked_countries"):
            v = o.configuration.get(k, [])
            if not isinstance(v, list) or any(not isinstance(c, str) or len(c) != 2 for c in v):
                errors["configuration"] = f"{k} must be a list of 2-letter country codes."
    if o.starts_at and o.ends_at and o.ends_at <= o.starts_at:
        errors["ends_at"] = "Must be after the start."
    if o.reward_amount is not None and o.reward_amount <= 0:
        errors["reward_amount"] = "Must be at least 1."
    if errors:
        raise ValidationError(errors)


def _offer_clean(self):
    _validate_offer(self)


def _offer_save(self, *args, **kwargs):
    _validate_offer(self)
    super(RewardedAdOffer, self).save(*args, **kwargs)


RewardedAdOffer.clean = _offer_clean
RewardedAdOffer.save = _offer_save
