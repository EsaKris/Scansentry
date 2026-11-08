from django.contrib import admin

from apps.audit.services import record_audit

from .models import SecurityCheck, SecurityRule


@admin.register(SecurityRule)
class SecurityRuleAdmin(admin.ModelAdmin):
    """Administrators may change: enabled, weight, severity and thresholds. Detection logic is in code."""

    list_display = ("key", "name", "category", "strength", "severity", "weight", "enabled", "version", "updated_at")
    list_filter = ("enabled", "category", "strength", "severity")
    search_fields = ("key", "name", "description")
    readonly_fields = ("key", "name", "description", "category", "strength", "recommended_action", "version", "updated_at")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        before = {f: str(form.initial.get(f)) for f in form.changed_data}
        super().save_model(request, obj, form, change)
        record_audit(actor=request.user, action="security_rule.changed", obj=obj, before=before,
                     after={f: str(getattr(obj, f)) for f in form.changed_data})


@admin.register(SecurityCheck)
class SecurityCheckAdmin(admin.ModelAdmin):
    list_display = ("checked_at", "normalised_domain", "risk_classification", "risk_score", "confidence",
                    "completion_status", "source_type")
    list_filter = ("risk_classification", "completion_status", "source_type", "confidence")
    search_fields = ("normalised_domain", "normalised_url")

    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
