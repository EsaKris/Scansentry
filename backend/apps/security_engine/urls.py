from django.urls import path

from .views import AnalyzeView, CheckDetailView, ProvidersView

urlpatterns = [
    path("security/analyze/", AnalyzeView.as_view(), name="security-analyze"),
    path("security/checks/<uuid:pk>/", CheckDetailView.as_view(), name="security-check"),
    path("security/providers/", ProvidersView.as_view(), name="security-providers"),
]
