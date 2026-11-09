from django.urls import path

from .views import OverviewView, QRAnalyticsView, QRPerformanceView, ScansView, UsageLimitsView, UsageView

urlpatterns = [
    path("analytics/overview/", OverviewView.as_view(), name="analytics-overview"),
    path("analytics/scans/", ScansView.as_view(), name="analytics-scans"),
    path("analytics/qr-performance/", QRPerformanceView.as_view(), name="analytics-qr-performance"),
    path("qr/<uuid:pk>/analytics/", QRAnalyticsView.as_view(), name="qr-analytics"),
    path("usage/overview/", UsageView.as_view(), name="usage-overview"),
    path("usage/limits/", UsageLimitsView.as_view(), name="usage-limits"),
]
