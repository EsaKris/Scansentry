from django.urls import path

from .views import MarkReadView, NotificationListView, PreferencesView, ReadAllView, UnreadCountView

urlpatterns = [
    path("notifications/", NotificationListView.as_view(), name="notifications"),
    path("notifications/unread-count/", UnreadCountView.as_view(), name="notifications-unread"),
    path("notifications/read-all/", ReadAllView.as_view(), name="notifications-read-all"),
    path("notifications/preferences/", PreferencesView.as_view(), name="notifications-preferences"),
    path("notifications/<uuid:pk>/read/", MarkReadView.as_view(), name="notification-read"),
]
