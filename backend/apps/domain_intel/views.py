from datetime import timedelta

from django.utils import timezone
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView, get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.core.authentication import OptionalJWTAuthentication
from apps.core.entitlements import FeatureLimitReached, get_limit

from . import service
from .models import DomainAssessment, DomainLookup
from .normalize import InvalidDomainInput
from .presenters import present


class DomainAnonThrottle(AnonRateThrottle):
    scope = "domain_anon"


class DomainUserThrottle(UserRateThrottle):
    scope = "domain_user"


class DomainAnalyzeRequestSerializer(serializers.Serializer):
    value = serializers.CharField(max_length=2048)
    refresh = serializers.BooleanField(required=False, default=False)


def _check_lookup_limits(user):
    now = timezone.now()
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    windows = {"domain.lookups.daily_limit": day, "domain.lookups.weekly_limit": day - timedelta(days=day.weekday()),
               "domain.lookups.monthly_limit": day.replace(day=1)}
    for key, start in windows.items():
        limit = get_limit(user, key)
        if limit is not None and DomainLookup.objects.filter(user=user, created_at__gte=start).count() >= limit:
            raise FeatureLimitReached(f"You have reached your {key.split('.')[-1].replace('_limit', '')} "
                                      "limit for domain lookups.")


class AnalyzeView(APIView):
    """Public domain checker (rate-limited). Signed-in users also get history and may force a refresh."""

    authentication_classes = [OptionalJWTAuthentication]
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    throttle_classes = [DomainAnonThrottle, DomainUserThrottle]

    @extend_schema(request=DomainAnalyzeRequestSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = DomainAnalyzeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = request.user if request.user.is_authenticated else None
        if user is not None:
            _check_lookup_limits(user)
        try:
            assessment, cached = service.assess(
                ser.validated_data["value"], user=user, refresh=ser.validated_data["refresh"])
        except InvalidDomainInput as exc:
            raise ValidationError({"value": str(exc)})
        resp = Response(present(assessment, cached=cached))
        resp["Cache-Control"] = "no-store"
        return resp


class AssessmentDetailView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [DomainAnonThrottle]

    @extend_schema(responses={200: OpenApiTypes.OBJECT, 404: OpenApiTypes.OBJECT})
    def get(self, request, pk):
        a = get_object_or_404(DomainAssessment, pk=pk)
        return Response(present(a, cached=False))


class HistorySerializer(serializers.ModelSerializer):
    assessment_id = serializers.UUIDField(read_only=True)  # FK id, exposed as a UUID
    domain = serializers.CharField(source="assessment.domain")
    checked_at = serializers.DateTimeField(source="assessment.checked_at")
    domain_health_score = serializers.IntegerField(source="assessment.domain_health_score")
    registration_status = serializers.CharField(source="assessment.registration_status")
    hosting_status = serializers.CharField(source="assessment.hosting_status")
    completion_status = serializers.CharField(source="assessment.completion_status")

    class Meta:
        model = DomainLookup
        fields = ("id", "assessment_id", "domain", "submitted_value", "served_from_cache", "created_at",
                  "checked_at", "domain_health_score", "registration_status", "hosting_status",
                  "completion_status")


class HistoryView(ListAPIView):
    serializer_class = HistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return DomainLookup.objects.none()
        qs = DomainLookup.objects.filter(user=self.request.user).select_related("assessment")
        q = self.request.query_params.get("domain")
        return qs.filter(assessment__domain__icontains=q) if q else qs
