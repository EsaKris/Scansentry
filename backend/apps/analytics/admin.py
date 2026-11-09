from django.contrib import admin

from .models import ScanEvent, UsageCounter


@admin.register(ScanEvent)
class ScanEventAdmin(admin.ModelAdmin):
    """Platform-wide, read-only. Events hold no IP address, user agent or URL."""

    list_display = ("scanned_at", "qr_code", "outcome", "device_category", "browser_category", "approximate_country",
                    "scanner_type", "security_status_at_scan", "is_bot")
    list_filter = ("outcome", "scanner_type", "device_category", "is_bot", "security_status_at_scan")
    date_hierarchy = "scanned_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UsageCounter)
class UsageCounterAdmin(admin.ModelAdmin):
    list_display = ("user", "feature_key", "window", "period_start", "current_usage")
    list_filter = ("feature_key", "window")
    search_fields = ("user__email",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
