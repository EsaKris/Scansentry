from rest_framework import serializers

from .models import AbuseReport


class AbuseReportCreateSerializer(serializers.Serializer):
    qr_token = serializers.RegexField(r"^[A-Za-z0-9_-]{16,64}$", required=False, allow_blank=True)
    url = serializers.CharField(max_length=2048, required=False, allow_blank=True)
    category = serializers.ChoiceField(choices=AbuseReport.Category.choices)
    description = serializers.CharField(min_length=10, max_length=2000)
    evidence = serializers.FileField(required=False, allow_null=True)

    def validate(self, attrs):
        if not attrs.get("qr_token") and not attrs.get("url"):
            raise serializers.ValidationError("Provide the QR token or the URL you are reporting.")
        return attrs
