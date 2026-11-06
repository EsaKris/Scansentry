from django.contrib import admin, messages

from . import services
from .models import Campaign, QRCode, QRDestinationHistory


class HistoryInline(admin.TabularInline):
    model = QRDestinationHistory
    extra = 0
    can_delete = False
    readonly_fields = ("previous_destination", "new_destination", "changed_by",
                       "change_reason", "created_at")

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(QRCode)
class QRCodeAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "qr_type", "code_mode", "status", "current_destination",
                    "last_scanned_at", "created_at")
    list_filter = ("code_mode", "qr_type", "status", "disabled_by_staff")
    search_fields = ("name", "owner__email", "current_destination", "public_token")
    readonly_fields = ("public_token", "encoded_payload", "source_data", "created_at",
                       "updated_at", "last_scanned_at", "disabled_by_staff")
    inlines = [HistoryInline]
    actions = ["disable_as_staff", "restore_as_staff"]

    @admin.action(description="Disable selected codes (staff action, owner cannot undo)")
    def disable_as_staff(self, request, queryset):
        for qr in queryset:
            services.disable_qr(qr, user=request.user, reason="Disabled by ScanSentry staff",
                                by_staff=True)
        self.message_user(request, f"Disabled {queryset.count()} QR code(s).", messages.SUCCESS)

    @admin.action(description="Restore selected codes to active")
    def restore_as_staff(self, request, queryset):
        for qr in queryset:
            services.staff_restore_qr(qr, user=request.user)
        self.message_user(request, f"Restored {queryset.count()} QR code(s).", messages.SUCCESS)


@admin.register(Campaign)
class CampaignAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "created_at")
    search_fields = ("name", "owner__email")
