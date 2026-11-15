from django.contrib import admin

from apps.audit.services import record_audit

from .models import AppConfiguration

# Settings with commercial or advertising impact need the billing permission, not just "change app configuration".
BILLING_PREFIXES = ("pricing", "billing.")
ADS_PREFIXES = ("ads_", "ads.", "rewarded", "credits")


def _required_perm(key: str):
    """The permission needed to touch a setting, or None for ordinary settings."""
    key = key or ""
    if key.startswith(BILLING_PREFIXES) or key == "default_entitlements":
        return "billing.manage_pricing"
    if key.startswith(ADS_PREFIXES):
        return "advertising.manage_ads"
    return None


def _protected(key: str) -> bool:
    return _required_perm(key) is not None


def _allowed(user, key: str) -> bool:
    perm = _required_perm(key)
    return perm is None or user.is_superuser or user.has_perm(perm)


@admin.register(AppConfiguration)
class AppConfigurationAdmin(admin.ModelAdmin):
    list_display = ("key", "is_public", "updated_by", "updated_at")
    list_filter = ("is_public",)
    search_fields = ("key", "description")

    def _can_touch(self, request, obj):
        return obj is None or _allowed(request.user, obj.key)

    def has_change_permission(self, request, obj=None):
        return super().has_change_permission(request, obj) and self._can_touch(request, obj)

    def has_delete_permission(self, request, obj=None):
        return super().has_delete_permission(request, obj) and self._can_touch(request, obj)

    def save_model(self, request, obj, form, change):
        if not _allowed(request.user, obj.key):
            from django.core.exceptions import PermissionDenied
            raise PermissionDenied("This setting needs a specific permission (pricing/billing: manage pricing; advertising: manage ads).")
        before = {"value": str(AppConfiguration.objects.filter(pk=obj.pk).values_list("value", flat=True).first())} if change else None
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="config.changed", obj=obj, before=before, after={"key": obj.key, "value": str(obj.value)[:500]})
