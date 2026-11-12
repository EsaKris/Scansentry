from django.contrib import admin

from apps.audit.services import record_audit

from .models import AppConfiguration

# Settings with commercial or advertising impact need the billing permission, not just "change app configuration".
PROTECTED_PREFIXES = ("pricing", "billing.", "ads", "rewarded", "credits")


def _protected(key: str) -> bool:
    return (key or "").startswith(PROTECTED_PREFIXES) or key == "default_entitlements"


@admin.register(AppConfiguration)
class AppConfigurationAdmin(admin.ModelAdmin):
    list_display = ("key", "is_public", "updated_by", "updated_at")
    list_filter = ("is_public",)
    search_fields = ("key", "description")

    def _can_touch(self, request, obj):
        return not (obj is not None and _protected(obj.key)) or request.user.is_superuser or request.user.has_perm("billing.manage_pricing")

    def has_change_permission(self, request, obj=None):
        return super().has_change_permission(request, obj) and self._can_touch(request, obj)

    def has_delete_permission(self, request, obj=None):
        return super().has_delete_permission(request, obj) and self._can_touch(request, obj)

    def save_model(self, request, obj, form, change):
        if _protected(obj.key) and not (request.user.is_superuser or request.user.has_perm("billing.manage_pricing")):
            from django.core.exceptions import PermissionDenied
            raise PermissionDenied("Pricing, billing and entitlement settings need the 'manage pricing' permission.")
        before = {"value": str(AppConfiguration.objects.filter(pk=obj.pk).values_list("value", flat=True).first())} if change else None
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="config.changed", obj=obj, before=before, after={"key": obj.key, "value": str(obj.value)[:500]})
