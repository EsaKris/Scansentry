from django.urls import path

from . import views as v

urlpatterns = [
    path("credits/balance/", v.BalanceView.as_view(), name="credits-balance"),
    path("credits/history/", v.HistoryView.as_view(), name="credits-history"),
    path("credits/limit-screen/", v.LimitScreenView.as_view(), name="credits-limit-screen"),
    path("credits/rewarded-offers/", v.OffersView.as_view(), name="credits-offers"),
    path("credits/rewarded-sessions/", v.SessionsView.as_view(), name="credits-sessions"),
    path("credits/rewarded-sessions/<uuid:pk>/", v.SessionDetailView.as_view(), name="credits-session"),
    path("credits/rewarded-sessions/<uuid:pk>/events/", v.SessionEventView.as_view(), name="credits-session-event"),
    path("credits/rewarded-sessions/<uuid:pk>/complete/", v.SessionCompleteView.as_view(), name="credits-session-complete"),
    path("advertising/reward-callbacks/<slug:provider>/", v.CallbackView.as_view(), name="reward-callback"),
    path("admin/credits/overview/", v.AdminOverviewView.as_view(), name="admin-credits-overview"),
    path("admin/credits/adjust/", v.AdminAdjustView.as_view(), name="admin-credits-adjust"),
]
