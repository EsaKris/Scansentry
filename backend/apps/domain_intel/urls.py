from django.urls import path

from .views import AnalyzeView, AssessmentDetailView, HistoryView

urlpatterns = [
    path("domains/analyze/", AnalyzeView.as_view(), name="domains-analyze"),
    path("domains/assessments/<uuid:pk>/", AssessmentDetailView.as_view(), name="domains-assessment"),
    path("domains/history/", HistoryView.as_view(), name="domains-history"),
]
