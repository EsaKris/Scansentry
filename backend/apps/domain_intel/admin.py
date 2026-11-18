from django.contrib import admin

from .models import DomainAssessment, DomainLookup, DomainObservation


class ObservationInline(admin.TabularInline):
    model = DomainObservation
    extra = 0
    can_delete = False
    readonly_fields = ("observation_type", "result_status", "observed_at", "observation_value", "evidence")

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(DomainAssessment)
class DomainAssessmentAdmin(admin.ModelAdmin):
    """Read-only operational view: RDAP data, raw status flags, DNS/TLS/HTTP results, provider failures."""

    list_display = ("domain", "checked_at", "registration_status", "hosting_status", "domain_health_score",
                    "completion_status", "confidence")
    list_filter = ("registration_status", "hosting_status", "completion_status", "age_group", "confidence")
    search_fields = ("domain", "registrable_domain", "registrar_name")
    inlines = [ObservationInline]

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(DomainLookup)
class DomainLookupAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "submitted_value", "served_from_cache")
    search_fields = ("submitted_value", "user__email")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
