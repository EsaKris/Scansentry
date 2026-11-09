from django.contrib import admin

from .models import Notification, NotificationPreference


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("created_at", "user", "kind", "severity", "title", "read_at", "emailed_at")
    list_filter = ("kind", "severity")
    search_fields = ("user__email", "title")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


admin.site.register(NotificationPreference)
