from django.utils import timezone
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import generics, serializers
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Notification, NotificationPreference
from .service import preferences


class NotificationSerializer(serializers.ModelSerializer):
    read = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ("id", "kind", "severity", "title", "body", "data", "read", "created_at", "read_at")
        read_only_fields = fields

    def get_read(self, obj) -> bool:
        return obj.read_at is not None


class PreferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationPreference
        fields = ("email_security_alerts", "email_qr_status", "email_abuse_reports", "updated_at")
        read_only_fields = ("updated_at",)


class NotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Notification.objects.none()
        qs = Notification.objects.filter(user=self.request.user)
        p = self.request.query_params
        if p.get("unread", "").lower() in ("1", "true", "yes"):
            qs = qs.filter(read_at__isnull=True)
        if p.get("kind"):
            qs = qs.filter(kind=p["kind"])
        if p.get("severity"):
            qs = qs.filter(severity=p["severity"])
        return qs


class MarkReadView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses=NotificationSerializer)
    def post(self, request, pk):
        n = get_object_or_404(Notification, pk=pk, user=request.user)
        if n.read_at is None:
            n.read_at = timezone.now()
            n.save(update_fields=["read_at"])
        return Response(NotificationSerializer(n).data)


class ReadAllView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        updated = Notification.objects.filter(user=request.user, read_at__isnull=True).update(read_at=timezone.now())
        return Response({"marked_read": updated})


class UnreadCountView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        qs = Notification.objects.filter(user=request.user, read_at__isnull=True)
        return Response({"unread": qs.count(), "critical_unread": qs.filter(severity="critical").count()})


class PreferencesView(generics.RetrieveUpdateAPIView):
    serializer_class = PreferenceSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "patch", "head", "options"]

    def get_object(self):
        return preferences(self.request.user)
