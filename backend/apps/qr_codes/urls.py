from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import CampaignViewSet, QRCodeViewSet, VerifyTokenView

router = DefaultRouter(trailing_slash=True)
router.include_root_view = False
router.register("qr", QRCodeViewSet, basename="qr")
router.register("campaigns", CampaignViewSet, basename="campaign")

urlpatterns = [
    path("scanner/verify/<str:token>/", VerifyTokenView.as_view(), name="scanner-verify"),
    *router.urls,
]
