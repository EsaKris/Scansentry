from django.contrib import admin

from .models import AppConfiguration


@admin.register(AppConfiguration)
class AppConfigurationAdmin(admin.ModelAdmin):
    list_display = ("key", "is_public", "updated_by", "updated_at")
    list_filter = ("is_public",)
    search_fields = ("key", "description")

    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
