from django import forms
from django.contrib import admin

from apps.audit.services import record_audit

from .models import (CreditLot, RewardCallbackEvent, RewardedAdOffer, RewardedAdSession, UsageCreditLedger, UsageCreditWallet)


class ReadOnly:
    """Records nobody edits by hand: they are created by the system and corrected only by appending (audited) ledger entries."""

    def has_add_permission(self, request, *a):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def _can_report(user) -> bool:
    return user.is_superuser or user.has_perm("credits.view_credit_reports") or user.has_perm("credits.manage_credits")


class ReportsOnly:
    def has_view_permission(self, request, obj=None):
        return _can_report(request.user)

    def has_module_permission(self, request):
        return _can_report(request.user)


@admin.register(UsageCreditLedger)
class LedgerAdmin(ReportsOnly, ReadOnly, admin.ModelAdmin):
    list_display = ("created_at", "user", "transaction_type", "amount", "balance_after", "feature_key", "reason")
    list_filter = ("transaction_type",)
    search_fields = ("user__email", "feature_key", "reason", "idempotency_key")
    date_hierarchy = "created_at"


@admin.register(UsageCreditWallet)
class WalletAdmin(ReportsOnly, admin.ModelAdmin):
    """Balances are read-only here: change them with the audited adjustment endpoint (it needs a reason and writes the ledger)."""

    list_display = ("user", "available_balance", "earning_suspended", "updated_at")
    list_filter = ("earning_suspended",)
    search_fields = ("user__email",)
    readonly_fields = ("user", "available_balance", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return request.user.is_superuser or request.user.has_perm("credits.manage_credits")

    def save_model(self, request, obj, form, change):
        before = {"earning_suspended": str(UsageCreditWallet.objects.filter(pk=obj.pk).values_list("earning_suspended", flat=True).first())}
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="credits.wallet_changed", obj=obj, before=before,
                     after={"earning_suspended": str(obj.earning_suspended), "user": str(obj.user_id)})


@admin.register(CreditLot)
class LotAdmin(ReportsOnly, ReadOnly, admin.ModelAdmin):
    list_display = ("wallet", "amount", "remaining", "expires_at", "created_at")


@admin.register(RewardedAdSession)
class SessionAdmin(ReportsOnly, ReadOnly, admin.ModelAdmin):
    list_display = ("created_at", "user", "platform", "provider", "status", "provider_verification_status", "expected_reward_amount",
                    "rejection_reason", "close_reason")
    list_filter = ("status", "platform", "provider", "provider_verification_status")
    search_fields = ("user__email", "provider_transaction_id")
    exclude = ("unique_session_token",)               # the token is a secret of the session's owner


@admin.register(RewardCallbackEvent)
class CallbackAdmin(ReportsOnly, ReadOnly, admin.ModelAdmin):
    list_display = ("received_at", "provider", "outcome", "provider_transaction_id")
    list_filter = ("provider", "outcome")


class NeedsManageAds:
    def _ok(self, request):
        return request.user.is_superuser or request.user.has_perm("advertising.manage_ads")

    def has_add_permission(self, request, *a):
        return super().has_add_permission(request, *a) and self._ok(request)

    def has_change_permission(self, request, *a):
        return super().has_change_permission(request, *a) and self._ok(request)

    def has_delete_permission(self, request, *a):
        return False                                   # disable an offer instead: sessions reference it


class OfferForm(forms.ModelForm):
    class Meta:
        model = RewardedAdOffer
        fields = "__all__"


@admin.register(RewardedAdOffer)
class OfferAdmin(NeedsManageAds, admin.ModelAdmin):
    form = OfferForm
    list_display = ("name", "platform", "provider", "reward_amount", "enabled", "cooldown_seconds", "updated_at")
    list_filter = ("enabled", "platform", "provider")
    search_fields = ("name",)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="rewarded_offer.saved", obj=obj,
                     after={f: str(getattr(obj, f, ""))[:200] for f in form.changed_data})
