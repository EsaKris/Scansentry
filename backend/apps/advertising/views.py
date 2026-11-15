from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.db.models import Count, Sum
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import generics, serializers
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.authentication import OptionalJWTAuthentication

from . import settings_store as cfg
from .constants import ALLOWED_SURFACES, FORBIDDEN_SURFACES, PLATFORMS, SPONSORED_LABEL, is_test_identifier
from .decision import PUBLIC_PROVIDER_KEYS, decide
from .models import AdPlacement, AdPreference, AdProvider, AdProviderReport

User = get_user_model()


def decision_payload(d) -> dict:
    return {"eligible": d.eligible, "reason": d.reason, "user_category": d.category, "platform": d.platform, "surface": d.surface,
            "request_non_personalized_ads": d.request_non_personalized_ads, "test_mode": d.test_mode, "placements": d.placements,
            "consent_note": ("Obtain consent through the provider's consent platform (Google UMP on Android, a certified CMP on web) "
                             "before requesting personalised ads. If consent is missing or refused, request non-personalised ads."),
            "rules": {"ads_never_shown_on": sorted(FORBIDDEN_SURFACES), "label_required": SPONSORED_LABEL}}


class ConfigView(APIView):
    """Safe, public advertising settings for the clients. Contains no secrets and no per-user data."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        test = cfg.flag("ads_test_mode")
        providers = [{"key": p.key, "platforms": p.platforms.split(","),
                      "config": {k: v for k, v in (p.config or {}).items() if k in PUBLIC_PROVIDER_KEYS and isinstance(v, str)}}
                     for p in AdProvider.objects.filter(enabled=True)] if cfg.flag("ads_enabled") else []
        resp = Response({
            "ads_enabled": cfg.flag("ads_enabled"),
            "platforms": {"web": cfg.flag("ads_enabled") and cfg.flag("ads_web_enabled"),
                          "android": cfg.flag("ads_enabled") and cfg.flag("ads_android_enabled")},
            "test_mode": test, "non_personalized_default": cfg.flag("ads_non_personalized_default"),
            "providers": providers, "label": SPONSORED_LABEL, "ads_never_shown_on": sorted(FORBIDDEN_SURFACES),
            "allowed_surfaces": sorted(ALLOWED_SURFACES),
            "note": "Ask /advertising/eligible-placements/ for the actual decision; never decide eligibility on the client."})
        resp["Cache-Control"] = "public, max-age=60"
        return resp


class EligiblePlacementsView(APIView):
    """The single ad-eligibility decision for a user, platform and screen."""

    authentication_classes = [OptionalJWTAuthentication]
    permission_classes = [AllowAny]

    @extend_schema(parameters=[OpenApiParameter("platform", OpenApiTypes.STR, enum=list(PLATFORMS), required=True),
                               OpenApiParameter("surface", OpenApiTypes.STR, description="The screen asking, e.g. dashboard")],
                   responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        platform = (request.query_params.get("platform") or "").lower()
        if platform not in PLATFORMS:
            raise ValidationError({"platform": f"Use one of: {', '.join(PLATFORMS)}."})
        surface = (request.query_params.get("surface") or "").lower() or None
        user = request.user if request.user.is_authenticated else None
        resp = Response(decision_payload(decide(user, platform, surface)))
        resp["Cache-Control"] = "private, no-store"
        return resp


class AdPreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = AdPreference
        fields = ("personalized_ads", "updated_at")
        read_only_fields = ("updated_at",)


class PreferencesView(generics.RetrieveUpdateAPIView):
    """The user's own personalisation choice (null = none made). Provider consent is collected by the client's consent platform."""

    serializer_class = AdPreferenceSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "patch", "head", "options"]

    def get_object(self):
        return AdPreference.objects.get_or_create(user=self.request.user)[0]


# ---- administration ----------------------------------------------------------------------------------------------------
class CanManageAds(BasePermission):
    message = "This action needs the 'manage_ads' permission."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_active and u.is_staff and (u.is_superuser or u.has_perm("advertising.manage_ads")))


class AdminOverviewView(APIView):
    permission_classes = [CanManageAds]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        test = cfg.flag("ads_test_mode")
        problems = []
        for p in AdPlacement.objects.filter(enabled=True).select_related("provider"):
            if not p.provider.enabled:
                problems.append({"placement": p.key, "problem": "its provider is disabled"})
            if not test and (not p.ad_unit_identifier.strip() or is_test_identifier(p.ad_unit_identifier)):
                problems.append({"placement": p.key, "problem": "production mode needs a real ad unit id"})
        since = timezone.now().date() - timedelta(days=30)
        rows = AdProviderReport.objects.filter(date__gte=since)
        report = None
        if rows.exists():
            agg = rows.aggregate(requests=Sum("requests"), impressions=Sum("impressions"), revenue=Sum("estimated_revenue"), days=Count("date", distinct=True))
            report = {"available": True, "window_days": 30, "days_with_data": agg["days"], "requests": agg["requests"],
                      "impressions": agg["impressions"], "estimated_revenue": None if agg["revenue"] is None else str(Decimal(agg["revenue"]).quantize(Decimal("0.0001"))),
                      "currencies": sorted(set(rows.exclude(currency="").values_list("currency", flat=True))),
                      "note": "Figures are exactly as reported by the ad provider (imported or entered by an administrator)."}
        else:
            report = {"available": False, "reason": "No provider report data has been imported. ScanSentry never estimates or invents "
                                                    "impression, fill-rate or revenue figures."}
        return Response({
            "switches": {k: cfg.get(k) for k in cfg.DEFAULTS},
            "warnings": ((["Test mode is ON: Google's official test ad units are being served. Switch ads_test_mode off for production."] if test else [])
                         + ([] if cfg.flag("ads_enabled") else ["The master switch ads_enabled is OFF: no ads are served."])),
            "providers": [{"key": p.key, "name": p.name, "enabled": p.enabled, "platforms": p.platforms} for p in AdProvider.objects.all()],
            "placements": {"total": AdPlacement.objects.count(), "enabled": AdPlacement.objects.filter(enabled=True).count()},
            "misconfigured_placements": problems, "reporting": report})


class AdminSimulateView(APIView):
    """Support tool: what would this user see on this screen? Uses the real decision engine."""

    permission_classes = [CanManageAds]

    @extend_schema(parameters=[OpenApiParameter("user", OpenApiTypes.STR), OpenApiParameter("platform", OpenApiTypes.STR),
                               OpenApiParameter("surface", OpenApiTypes.STR)], responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        who = request.query_params.get("user", "anonymous")
        platform = (request.query_params.get("platform") or "").lower()
        if platform not in PLATFORMS:
            raise ValidationError({"platform": f"Use one of: {', '.join(PLATFORMS)}."})
        user = None
        if who != "anonymous":
            q = {"email__iexact": who} if "@" in who else {"pk": who}
            try:
                user = User.objects.filter(**q).first()
            except Exception:
                user = None
            if user is None:
                raise NotFound("No such user.")
        return Response(decision_payload(decide(user, platform, (request.query_params.get("surface") or "").lower() or None)))
