from django.urls import include, path

from .views import AnalyzeView, DecodeView, VerifyTokenView

urlpatterns = [
    path("scanner/decode/", DecodeView.as_view(), name="scanner-decode"),
    path("scanner/analyze/", AnalyzeView.as_view(), name="scanner-analyze"),
    path("scanner/verify/<str:token>/", VerifyTokenView.as_view(), name="scanner-verify"),
    path("scanner/", include("apps.abuse_reports.urls")),
]
