from django.db import connection
from drf_spectacular.utils import OpenApiTypes, extend_schema, inline_serializer
from rest_framework import serializers
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AppConfiguration


class HealthView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = []

    @extend_schema(responses=inline_serializer("Health", {
        "status": serializers.CharField(), "database": serializers.CharField()}))
    def get(self, request):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            db = "ok"
        except Exception:
            db = "unavailable"
        status_code = 200 if db == "ok" else 503
        return Response({"status": "ok" if db == "ok" else "degraded", "database": db},
                        status=status_code)


class PublicConfigView(APIView):
    """Only is_public settings (feature flags, pricing_enabled, ...)."""

    authentication_classes = []
    permission_classes = [AllowAny]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        rows = AppConfiguration.objects.filter(is_public=True)
        return Response({row.key: row.value for row in rows})
