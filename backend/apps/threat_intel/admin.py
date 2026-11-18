from django.contrib import admin

from apps.audit.services import record_audit

from .models import ThreatIndicator, ThreatProvider


@admin.register(ThreatProvider)
class ThreatProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "key", "enabled", "request_count", "error_count", "last_success_at", "last_error_at")
    list_filter = ("enabled",)
    readonly_fields = ("key", "request_count", "error_count", "last_success_at", "last_error_at", "last_error", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        before = {f: str(getattr(ThreatProvider.objects.get(pk=obj.pk), f)) for f in form.changed_data} if change else None
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="threat_provider.changed", obj=obj, before=before,
                     after={f: str(getattr(obj, f)) for f in form.changed_data})


@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    list_display = ("indicator", "indicator_type", "threat_category", "provider", "severity", "active", "last_seen_at")
    list_filter = ("provider", "threat_category", "active", "indicator_type")
    search_fields = ("indicator", "source_reference", "note")
    date_hierarchy = "last_seen_at"

    def save_model(self, request, obj, form, change):
        from django.utils import timezone
        now = timezone.now()
        if not change:
            obj.first_seen_at = obj.first_seen_at or now
            obj.last_seen_at = obj.last_seen_at or now
            obj.checked_at = obj.checked_at or now
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="threat_indicator.saved", obj=obj,
                     after={"indicator": obj.indicator, "category": obj.threat_category, "active": obj.active})
