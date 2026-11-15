from django import forms
from django.contrib import admin

from apps.audit.services import record_audit

from .models import AdPlacement, AdPreference, AdProvider, AdProviderReport


class NeedsManageAds:
    def _ok(self, request):
        return request.user.is_superuser or request.user.has_perm("advertising.manage_ads")

    def has_add_permission(self, request, *a):
        return super().has_add_permission(request, *a) and self._ok(request)

    def has_change_permission(self, request, *a):
        return super().has_change_permission(request, *a) and self._ok(request)

    def has_delete_permission(self, request, *a):
        return super().has_delete_permission(request, *a) and self._ok(request)


class AuditedSave:
    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action=f"advertising.{obj.__class__.__name__.lower()}_saved", obj=obj,
                     after={f: str(getattr(obj, f, ""))[:200] for f in form.changed_data})


@admin.register(AdProvider)
class AdProviderAdmin(NeedsManageAds, AuditedSave, admin.ModelAdmin):
    list_display = ("name", "key", "platforms", "enabled", "updated_at")
    list_filter = ("enabled",)
    readonly_fields = ("key",)

    def has_add_permission(self, request, *a):
        return False


class PlacementForm(forms.ModelForm):
    class Meta:
        model = AdPlacement
        fields = "__all__"


@admin.register(AdPlacement)
class AdPlacementAdmin(NeedsManageAds, AuditedSave, admin.ModelAdmin):
    form = PlacementForm
    list_display = ("key", "platform", "surface", "format", "provider", "enabled", "updated_at")
    list_filter = ("platform", "surface", "format", "enabled", "provider")
    search_fields = ("key", "display_name")


@admin.register(AdProviderReport)
class AdProviderReportAdmin(NeedsManageAds, AuditedSave, admin.ModelAdmin):
    list_display = ("date", "provider", "platform", "requests", "impressions", "fill_rate", "estimated_revenue", "currency", "source")
    list_filter = ("provider", "platform", "source")
    date_hierarchy = "date"


@admin.register(AdPreference)
class AdPreferenceAdmin(admin.ModelAdmin):
    list_display = ("user", "personalized_ads", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
