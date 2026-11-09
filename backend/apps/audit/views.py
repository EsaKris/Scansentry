from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import generics, serializers
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated

from apps.qr_codes.models import QRCode

from .models import AuditLog

LABELS = {
    "qr.created": "Created", "qr.destination_changed": "Destination changed", "qr.paused": "Paused",
    "qr.active": "Reactivated", "qr.disabled": "Disabled", "qr.logo_set": "Logo added", "qr.logo_removed": "Logo removed",
    "qr.deleted": "Deleted", "account.registered": "Account created", "account.email_verified": "Email verified",
    "account.password_reset": "Password reset", "account.deletion_requested": "Account deletion requested",
}


class ActivitySerializer(serializers.ModelSerializer):
    label = serializers.SerializerMethodField()
    actor = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ("id", "action", "label", "object_type", "object_id", "actor", "before_state", "after_state", "created_at")
        read_only_fields = fields

    def get_label(self, obj) -> str:
        return LABELS.get(obj.action, obj.action.replace(".", " ").replace("_", " ").capitalize())

    def get_actor(self, obj) -> str:
        """Who did it, without exposing staff identities or other users."""
        me = self.context["request"].user
        if obj.actor_id is None:
            return "system"
        if obj.actor_id == me.id:
            return "you"
        return "scansentry_staff" if obj.actor.is_staff else "another_user"


class AccountActivityView(generics.ListAPIView):
    """The signed-in user's own audit trail. Read-only; IP addresses are never exposed."""

    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return AuditLog.objects.none()
        qs = AuditLog.objects.filter(actor=self.request.user).select_related("actor")
        prefix = self.request.query_params.get("action")
        return qs.filter(action__startswith=prefix) if prefix else qs


class QRActivityView(generics.ListAPIView):
    """Everything that happened to one QR code (owner only), including staff/system actions."""

    serializer_class = ActivitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return AuditLog.objects.none()
        qr = get_object_or_404(QRCode, pk=self.kwargs["pk"], owner=self.request.user)
        return AuditLog.objects.filter(object_type="QRCode", object_id=str(qr.pk)).select_related("actor")
