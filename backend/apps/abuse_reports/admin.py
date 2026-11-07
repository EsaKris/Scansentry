from django.contrib import admin, messages

from apps.qr_codes import services as qr_services

from . import services
from .models import AbuseReport


@admin.register(AbuseReport)
class AbuseReportAdmin(admin.ModelAdmin):
    list_display = ("created_at", "category", "review_status", "target", "reporter", "is_duplicate")
    list_filter = ("review_status", "category")
    search_fields = ("submitted_url", "description", "qr_code__name", "reporter__email")
    readonly_fields = ("reporter", "reporter_hash", "qr_code", "submitted_url", "target_key",
                       "category", "description", "evidence_file", "duplicate_of", "reviewer",
                       "created_at", "reviewed_at")
    actions = ["mark_in_review", "mark_dismissed", "mark_actioned", "disable_linked_qr"]

    @admin.display(description="Target")
    def target(self, obj):
        return obj.qr_code or obj.submitted_url

    @admin.display(boolean=True, description="Duplicate")
    def is_duplicate(self, obj):
        return obj.duplicate_of_id is not None

    def save_model(self, request, obj, form, change):
        if change and "review_status" in form.changed_data:
            services.review_report(obj, reviewer=request.user, status=obj.review_status,
                                   notes=obj.reviewer_notes, resolution=obj.resolution)
        else:
            super().save_model(request, obj, form, change)

    def _bulk(self, request, queryset, status):
        for report in queryset:
            services.review_report(report, reviewer=request.user, status=status,
                                   notes=report.reviewer_notes, resolution=report.resolution)
        self.message_user(request, f"Updated {queryset.count()} report(s).", messages.SUCCESS)

    @admin.action(description="Mark as in review")
    def mark_in_review(self, request, queryset):
        self._bulk(request, queryset, AbuseReport.Status.IN_REVIEW)

    @admin.action(description="Dismiss")
    def mark_dismissed(self, request, queryset):
        self._bulk(request, queryset, AbuseReport.Status.DISMISSED)

    @admin.action(description="Mark resolved (action taken)")
    def mark_actioned(self, request, queryset):
        self._bulk(request, queryset, AbuseReport.Status.ACTIONED)

    @admin.action(description="Disable the linked dynamic QR code (staff action)")
    def disable_linked_qr(self, request, queryset):
        count = 0
        for report in queryset.select_related("qr_code"):
            if report.qr_code:
                qr_services.disable_qr(report.qr_code, user=request.user,
                                       reason="Disabled after abuse review", by_staff=True)
                count += 1
        self.message_user(request, f"Disabled {count} QR code(s). A moderator decision is required "
                          "for each; reports alone never disable codes.", messages.WARNING)
