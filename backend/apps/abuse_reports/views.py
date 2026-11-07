from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.core.authentication import OptionalJWTAuthentication

from . import services
from .serializers import AbuseReportCreateSerializer


class ReportView(APIView):
    """Public: anyone can report. Reports never change a code's or domain's status by themselves."""

    authentication_classes = [OptionalJWTAuthentication]
    permission_classes = [AllowAny]
    parser_classes = [JSONParser, MultiPartParser, FormParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "abuse_report"

    @extend_schema(request={"multipart/form-data": AbuseReportCreateSerializer,
                            "application/json": AbuseReportCreateSerializer},
                   responses={201: dict})
    def post(self, request):
        ser = AbuseReportCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        services.submit_report(
            request=request, qr_token=d.get("qr_token") or None, url=d.get("url") or None,
            category=d["category"], description=d["description"], evidence=d.get("evidence"))
        # Identical response for new and duplicate reports so reports cannot be probed.
        return Response({"detail": "Thank you. Your report was received and will be reviewed by a "
                                   "moderator."}, status=status.HTTP_201_CREATED)
