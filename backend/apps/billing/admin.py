from django import forms
from django.contrib import admin

from apps.audit.services import record_audit

from .models import (EntitlementOverride, FeatureDefinition, PaymentTransaction, PaymentWebhookEvent, Plan, PlanFeature,
                     PlanPrice, Subscription, SubscriptionEvent)


class NeedsPerm:
    """Staff need the named permission in addition to Django's model permission (role-based administration)."""
    required_perm = ""

    def _ok(self, request):
        return request.user.is_superuser or request.user.has_perm(f"billing.{self.required_perm}")

    def has_add_permission(self, request, *a):
        return super().has_add_permission(request, *a) and self._ok(request)

    def has_change_permission(self, request, *a):
        return super().has_change_permission(request, *a) and self._ok(request)

    def has_delete_permission(self, request, *a):
        return super().has_delete_permission(request, *a) and self._ok(request)


class ReadOnly:
    def has_add_permission(self, request, *a):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class PriceInline(NeedsPerm, admin.TabularInline):
    model = PlanPrice
    extra = 0
    required_perm = "manage_pricing"


class PlanFeatureInline(NeedsPerm, admin.TabularInline):
    model = PlanFeature
    extra = 0
    autocomplete_fields = ["feature"]
    required_perm = "manage_pricing"


@admin.register(Plan)
class PlanAdmin(NeedsPerm, admin.ModelAdmin):
    required_perm = "manage_pricing"
    list_display = ("name", "slug", "status", "is_public", "is_free", "billing_interval", "trial_days", "display_order", "featured")
    list_filter = ("status", "is_public", "is_free", "billing_interval")
    prepopulated_fields = {"slug": ("name",)}
    inlines = [PriceInline, PlanFeatureInline]

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="billing.plan_saved", obj=obj, after={f: str(getattr(obj, f)) for f in form.changed_data})


@admin.register(FeatureDefinition)
class FeatureDefinitionAdmin(NeedsPerm, admin.ModelAdmin):
    required_perm = "manage_pricing"
    list_display = ("key", "name", "data_type", "default_value", "measurable", "assignable", "active")
    list_filter = ("data_type", "measurable", "active")
    search_fields = ("key", "name")


@admin.register(Subscription)
class SubscriptionAdmin(ReadOnly, admin.ModelAdmin):
    """Read-only: changes go through the audited service/API so history and notes are never skipped."""
    list_display = ("user", "plan", "status", "current_period_end", "billing_provider", "currency", "cancel_at_period_end")
    list_filter = ("status", "plan", "billing_provider")
    search_fields = ("user__email", "external_subscription_reference", "external_customer_reference")


@admin.register(SubscriptionEvent)
class SubscriptionEventAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("created_at", "user", "event_type", "from_status", "to_status", "to_plan", "actor")
    list_filter = ("event_type",)
    search_fields = ("user__email",)


@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("created_at", "user", "plan", "provider", "amount", "currency", "status", "provider_reference")
    list_filter = ("status", "provider", "currency")
    search_fields = ("user__email", "provider_reference")

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser or request.user.has_perm("billing.view_payments")


@admin.register(PaymentWebhookEvent)
class PaymentWebhookEventAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("created_at", "provider", "event_type", "processing_status", "attempts", "error_message")
    list_filter = ("provider", "processing_status", "event_type")

    def has_view_permission(self, request, obj=None):
        return request.user.is_superuser or request.user.has_perm("billing.view_payments")


class OverrideForm(forms.ModelForm):
    class Meta:
        model = EntitlementOverride
        fields = ("user", "kind", "feature", "plan", "enabled", "limit_value", "expires_at", "note")

    def clean_note(self):
        note = (self.cleaned_data.get("note") or "").strip()
        if len(note) < 5:
            raise forms.ValidationError("An internal note of at least 5 characters is required for every administrative change.")
        return note

    def clean(self):
        d = super().clean()
        kind, feature, plan = d.get("kind"), d.get("feature"), d.get("plan")
        if kind == "plan_trial" and not (plan and d.get("expires_at")):
            raise forms.ValidationError("Temporary plan access needs a plan and an expiry date.")
        if kind != "plan_trial" and not feature:
            raise forms.ValidationError("Choose the feature to grant or revoke.")
        return d


@admin.register(EntitlementOverride)
class EntitlementOverrideAdmin(NeedsPerm, admin.ModelAdmin):
    form = OverrideForm
    """Creating a grant requires an internal note; it is audited. Revoke through the API (needs a note)."""
    required_perm = "grant_entitlements"
    list_display = ("created_at", "user", "kind", "feature", "plan", "enabled", "limit_value", "expires_at", "revoked_at", "created_by")
    list_filter = ("kind", "enabled")
    search_fields = ("user__email", "note")
    readonly_fields = ("created_by", "created_at", "revoked_at", "revoked_by", "revoke_note")

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="billing.override_saved", obj=obj, after={"kind": obj.kind, "note": obj.note[:200]})
