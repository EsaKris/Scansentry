from django.urls import path

from .views import AccountActivityView, QRActivityView

urlpatterns = [
    path("activity/", AccountActivityView.as_view(), name="activity"),
    path("qr/<uuid:pk>/activity/", QRActivityView.as_view(), name="qr-activity"),
]
