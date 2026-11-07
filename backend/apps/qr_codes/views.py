from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend

from apps.audit.services import record_audit
from apps.core.entitlements import require_feature

from . import services
from .models import Campaign, QRCode
from .payloads import REGISTRY
from .rendering import PayloadTooLarge, render_qr
from .serializers import (
    CampaignSerializer, LogoUploadSerializer, QRCodeCreateSerializer, QRCodeSerializer,
    QRCodeUpdateSerializer, QRDestinationHistorySerializer, QRPreviewSerializer,
)

CONTENT_TYPES = {"png": "image/png", "svg": "image/svg+xml", "pdf": "application/pdf"}
PREVIEW_TOKEN = "PREVIEW-NOT-A-REAL-CODE"


class CampaignViewSet(viewsets.ModelViewSet):
    serializer_class = CampaignSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Campaign.objects.none()
        return Campaign.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class QRCodeViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin,
                    mixins.DestroyModelMixin, viewsets.GenericViewSet):
    """Every queryset is scoped to the requesting user: other users' codes return 404."""

    permission_classes = [IsAuthenticated]
    lookup_value_regex = "[0-9a-fA-F-]{36}"
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["status", "qr_type", "code_mode", "campaign"]
    search_fields = ["name", "description"]
    ordering_fields = ["created_at", "updated_at", "name", "last_scanned_at"]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return QRCode.objects.none()
        return QRCode.objects.filter(owner=self.request.user).select_related("campaign")

    def get_serializer_class(self):
        return {"create": QRCodeCreateSerializer}.get(self.action, QRCodeSerializer)

    # --- create / update / delete -------------------------------------------------
    @extend_schema(request=QRCodeCreateSerializer, responses={201: QRCodeSerializer})
    def create(self, request):
        ser = QRCodeCreateSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        qr = services.create_qr(
            user=request.user, name=d["name"], description=d["description"], qr_type=d["qr_type"],
            code_mode=d["code_mode"], data=d["data"], expires_at=d["expires_at"],
            campaign=d["campaign"], style=d["style"])
        return Response(QRCodeSerializer(qr).data, status=status.HTTP_201_CREATED)

    @extend_schema(request=QRCodeUpdateSerializer, responses={200: QRCodeSerializer})
    @transaction.atomic
    def partial_update(self, request, pk=None):
        qr = self.get_object()
        ser = QRCodeUpdateSerializer(data=request.data, partial=True, context={"request": request})
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        if qr.status == QRCode.Status.DISABLED and qr.disabled_by_staff:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("This QR code was disabled by ScanSentry staff.")

        if "current_destination" in d:
            services.change_destination(qr, d["current_destination"], user=request.user,
                                        reason=d.get("change_reason", ""))
        if "style" in d:
            services.update_style(qr, d["style"], user=request.user)
        for field in ("name", "description", "expires_at", "campaign"):
            if field in d:
                setattr(qr, field, d[field])
        qr.save(update_fields=[f for f in ("name", "description", "expires_at", "campaign")
                               if f in d] + ["updated_at"])
        qr.refresh_from_db()
        return Response(QRCodeSerializer(qr).data)

    def perform_destroy(self, instance):
        services.delete_qr(instance, user=self.request.user)

    # --- lifecycle ----------------------------------------------------------------------
    @extend_schema(request=None, responses=QRCodeSerializer)
    @action(detail=True, methods=["post"])
    def pause(self, request, pk=None):
        qr = self.get_object()
        services.pause_qr(qr, user=request.user)
        return Response(QRCodeSerializer(qr).data)

    @extend_schema(request=None, responses=QRCodeSerializer)
    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        qr = self.get_object()
        if qr.disabled_by_staff:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("This QR code was disabled by ScanSentry staff.")
        services.activate_qr(qr, user=request.user)
        return Response(QRCodeSerializer(qr).data)

    @extend_schema(request=None, responses=QRCodeSerializer)
    @action(detail=True, methods=["post"])
    def disable(self, request, pk=None):
        qr = self.get_object()
        services.disable_qr(qr, user=request.user, reason=str(request.data.get("reason", ""))[:255])
        return Response(QRCodeSerializer(qr).data)

    @extend_schema(responses=QRDestinationHistorySerializer(many=True))
    @action(detail=True, methods=["get"])
    def history(self, request, pk=None):
        qr = self.get_object()
        page = self.paginate_queryset(qr.history.select_related("changed_by"))
        return self.get_paginated_response(QRDestinationHistorySerializer(page, many=True).data)

    # --- logo -------------------------------------------------------------------------------
    @extend_schema(request={"multipart/form-data": LogoUploadSerializer}, responses=QRCodeSerializer)
    @action(detail=True, methods=["post", "delete"], parser_classes=[MultiPartParser, FormParser, JSONParser])
    def logo(self, request, pk=None):
        qr = self.get_object()
        if request.method == "DELETE":
            services.remove_logo(qr, user=request.user)
        else:
            ser = LogoUploadSerializer(data=request.data)
            ser.is_valid(raise_exception=True)
            services.set_logo(qr, ser.validated_data["logo"], user=request.user)
        qr.refresh_from_db()
        return Response(QRCodeSerializer(qr).data)

    # --- images ---------------------------------------------------------------------------------
    @extend_schema(
        parameters=[OpenApiParameter("download", OpenApiTypes.BOOL, required=False)],
        responses={200: OpenApiTypes.BINARY})
    @action(detail=True, methods=["get"], url_path=r"image/(?P<fmt>png|svg|pdf)")
    def image(self, request, pk=None, fmt="png"):
        qr = self.get_object()
        if fmt == "svg":
            require_feature(request.user, "qr.svg_export")
        if fmt == "pdf":
            require_feature(request.user, "qr.pdf_export")
        logo_bytes = None
        if qr.logo and fmt != "svg":
            with qr.logo.open("rb") as fh:
                logo_bytes = fh.read()
        try:
            body = render_qr(qr.encoded_payload, qr.style, fmt, logo_bytes)
        except PayloadTooLarge as exc:
            return Response({"error": {"code": "payload_too_large", "message": str(exc),
                                       "details": None}}, status=400)
        resp = HttpResponse(body, content_type=CONTENT_TYPES[fmt])
        resp["Cache-Control"] = "private, no-store"
        resp["X-Content-Type-Options"] = "nosniff"
        if request.query_params.get("download"):
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in qr.name)[:60] or "qr"
            resp["Content-Disposition"] = f'attachment; filename="{safe}.{fmt}"'
        return resp

    @extend_schema(request=QRPreviewSerializer, responses={200: OpenApiTypes.BINARY})
    @action(detail=False, methods=["post"])
    def preview(self, request):
        """Render a PNG without saving anything. Dynamic previews use a placeholder URL."""
        ser = QRPreviewSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        _, built = services.build_payload(d["qr_type"], d["data"], d["code_mode"])
        payload = (f"{services.settings.REDIRECT_BASE_URL}/r/{PREVIEW_TOKEN}"
                   if d["code_mode"] == QRCode.Mode.DYNAMIC else built.payload)
        from .rendering import DEFAULT_STYLE
        style = {**DEFAULT_STYLE, **d["style"]}
        try:
            body = render_qr(payload, style, "png")
        except PayloadTooLarge as exc:
            return Response({"error": {"code": "payload_too_large", "message": str(exc),
                                       "details": None}}, status=400)
        resp = HttpResponse(body, content_type="image/png")
        resp["Cache-Control"] = "no-store"
        return resp
