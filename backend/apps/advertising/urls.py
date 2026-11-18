from django.urls import path

from . import views as v

urlpatterns = [
    path("advertising/config/", v.ConfigView.as_view(), name="ads-config"),
    path("advertising/eligible-placements/", v.EligiblePlacementsView.as_view(), name="ads-eligible"),
    path("advertising/preferences/", v.PreferencesView.as_view(), name="ads-preferences"),
    path("admin/advertising/overview/", v.AdminOverviewView.as_view(), name="admin-ads-overview"),
    path("admin/advertising/simulate/", v.AdminSimulateView.as_view(), name="admin-ads-simulate"),
]
