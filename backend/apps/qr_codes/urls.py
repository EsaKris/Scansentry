from rest_framework.routers import DefaultRouter

from .views import CampaignViewSet, QRCodeViewSet

router = DefaultRouter(trailing_slash=True)
router.include_root_view = False
router.register("qr", QRCodeViewSet, basename="qr")
router.register("campaigns", CampaignViewSet, basename="campaign")

urlpatterns = [
    *router.urls,
]
