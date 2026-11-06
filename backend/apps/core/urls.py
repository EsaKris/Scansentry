from django.urls import path

from .views import HealthView, PublicConfigView

urlpatterns = [
    path("health/", HealthView.as_view(), name="health"),
    path("config/", PublicConfigView.as_view(), name="public-config"),
]
