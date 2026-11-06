from django.utils import timezone
from rest_framework import serializers

from apps.core.urlsafety import validate_http_url

from .models import Campaign, QRCode, QRDestinationHistory
from .payloads import HttpUrlField, SafeText
from .rendering import EC_LEVELS, HEX_RE, check_colors


class StyleSerializer(serializers.Serializer):
    fg_color = serializers.RegexField(HEX_RE, required=False)
    bg_color = serializers.RegexField(HEX_RE, required=False)
    error_correction = serializers.ChoiceField(choices=list(EC_LEVELS), required=False)
    box_size = serializers.IntegerField(min_value=5, max_value=20, required=False)
    frame_text = SafeText(max_length=30, required=False, allow_blank=True)

    def validate(self, attrs):
        from .rendering import DEFAULT_STYLE
        fg = attrs.get("fg_color", DEFAULT_STYLE["fg_color"])
        bg = attrs.get("bg_color", DEFAULT_STYLE["bg_color"])
        problems = check_colors(fg, bg)
        if problems:
            raise serializers.ValidationError({"colors": problems})
        return attrs


class CampaignSerializer(serializers.ModelSerializer):
    qr_count = serializers.IntegerField(source="qr_codes.count", read_only=True)

    class Meta:
        model = Campaign
        fields = ("id", "name", "description", "qr_count", "created_at", "updated_at")
        read_only_fields = ("id", "created_at", "updated_at")

    def validate_name(self, value):
        user = self.context["request"].user
        qs = Campaign.objects.filter(owner=user, name__iexact=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("You already have a campaign with this name.")
        return value


class QRCodeSerializer(serializers.ModelSerializer):
    effective_status = serializers.CharField(read_only=True)
    has_logo = serializers.SerializerMethodField()
    data = serializers.JSONField(source="source_data", read_only=True)
    public_url = serializers.SerializerMethodField()

    class Meta:
        model = QRCode
        fields = ("id", "name", "description", "qr_type", "code_mode", "status", "effective_status",
                  "status_reason", "current_destination", "encoded_payload", "public_url",
                  "public_token", "data", "style", "has_logo", "campaign", "expires_at",
                  "created_at", "updated_at", "last_scanned_at")
        read_only_fields = fields

    def get_has_logo(self, obj) -> bool:
        return bool(obj.logo)

    def get_public_url(self, obj) -> str | None:
        return obj.encoded_payload if obj.is_dynamic else None


class QRCodeCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=120)
    description = serializers.CharField(required=False, allow_blank=True, default="")
    qr_type = serializers.ChoiceField(choices=QRCode.Type.choices)
    code_mode = serializers.ChoiceField(choices=QRCode.Mode.choices, default=QRCode.Mode.STATIC)
    data = serializers.DictField()
    style = StyleSerializer(required=False, default=dict)
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)
    campaign = serializers.PrimaryKeyRelatedField(queryset=Campaign.objects.none(),
                                                  required=False, allow_null=True, default=None)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request is not None and request.user.is_authenticated:
            self.fields["campaign"].queryset = Campaign.objects.filter(owner=request.user)

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Expiry must be in the future.")
        return value


class QRCodeUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=120, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    current_destination = HttpUrlField(max_length=2048, required=False)
    change_reason = serializers.CharField(max_length=255, required=False, allow_blank=True, default="")
    style = StyleSerializer(required=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    campaign = serializers.PrimaryKeyRelatedField(queryset=Campaign.objects.none(),
                                                  required=False, allow_null=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request is not None and request.user.is_authenticated:
            self.fields["campaign"].queryset = Campaign.objects.filter(owner=request.user)

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Expiry must be in the future.")
        return value


class QRPreviewSerializer(serializers.Serializer):
    qr_type = serializers.ChoiceField(choices=QRCode.Type.choices)
    code_mode = serializers.ChoiceField(choices=QRCode.Mode.choices, default=QRCode.Mode.STATIC)
    data = serializers.DictField()
    style = StyleSerializer(required=False, default=dict)


class LogoUploadSerializer(serializers.Serializer):
    logo = serializers.FileField()


class QRDestinationHistorySerializer(serializers.ModelSerializer):
    changed_by = serializers.SerializerMethodField()

    class Meta:
        model = QRDestinationHistory
        fields = ("id", "previous_destination", "new_destination", "changed_by",
                  "change_reason", "created_at")
        read_only_fields = fields

    def get_changed_by(self, obj) -> str | None:
        return obj.changed_by.display_name or obj.changed_by.email if obj.changed_by else None
