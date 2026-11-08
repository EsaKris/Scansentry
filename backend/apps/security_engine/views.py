from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.core.authentication import OptionalJWTAuthentication
from apps.scanner.serializers import RawContentField
from apps.threat_intel.models import ThreatProvider
from apps.threat_intel.providers import ADAPTERS, read_secret

from . import service
from .models import SecurityCheck
from .presenters import present_check


class SecurityAnonThrottle(AnonRateThrottle):
    scope = "security_anon"


class SecurityUserThrottle(UserRateThrottle):
    scope = "security_user"


class SecurityAnalyzeRequestSerializer(serializers.Serializer):
    url = RawContentField(max_length=2048)
    trace = serializers.BooleanField(default=True, help_text="Follow redirects of known URL shorteners")
    ai = serializers.BooleanField(default=False, help_text="Request an AI-worded explanation (signed-in, if enabled)")


class AnalyzeView(APIView):
    """Security assessment of a web link. Public (rate-limited); results are explained with evidence."""

    authentication_classes = [OptionalJWTAuthentication]
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    throttle_classes = [SecurityAnonThrottle, SecurityUserThrottle]

    @extend_schema(request=SecurityAnalyzeRequestSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = SecurityAnalyzeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        user = request.user if request.user.is_authenticated else None
        try:
            check, cached = service.analyze(d["url"], user=user, source="api", trace=d["trace"], ai=d["ai"])
        except service.NotApplicable:
            raise ValidationError({"url": "Security assessment applies to web links (http/https)."})
        resp = Response(present_check(check, cached=cached))
        resp["Cache-Control"] = "no-store"
        return resp


class CheckDetailView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [SecurityAnonThrottle]

    @extend_schema(responses={200: OpenApiTypes.OBJECT, 404: OpenApiTypes.OBJECT})
    def get(self, request, pk):
        return Response(present_check(get_object_or_404(SecurityCheck, pk=pk)))


class ProvidersView(APIView):
    """Administrators only. Never returns credentials."""

    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        rows = []
        for p in ThreatProvider.objects.all():
            adapter = ADAPTERS.get(p.key)
            rows.append({
                "key": p.key, "name": p.name, "enabled": p.enabled, "adapter_installed": adapter is not None,
                "external_source": getattr(adapter, "external", None),
                "credential_configured": bool(read_secret(p.credential_ref)) if (adapter and adapter.needs_credential) else None,
                "timeout_seconds": p.timeout_seconds, "retry_attempts": p.retry_attempts,
                "rate_limit_per_minute": p.rate_limit_per_minute,
                "request_count": p.request_count, "error_count": p.error_count,
                "last_success_at": p.last_success_at, "last_error_at": p.last_error_at, "last_error": p.last_error or None,
                "licensing_note": getattr(adapter, "commercial_note", ""),
            })
        return Response({"providers": rows})
