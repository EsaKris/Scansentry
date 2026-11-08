from django.conf import settings
from django.core.validators import ProhibitNullCharactersValidator
from rest_framework import serializers


class DecodeRequestSerializer(serializers.Serializer):
    image = serializers.FileField()
    assess = serializers.BooleanField(default=False, help_text="Also run the full security assessment (slower)")


class RawContentField(serializers.CharField):
    """Scanned content is untrusted and may legitimately contain control/NUL characters.
    Accept it so it can be analysed and neutralised, instead of failing the request."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators = [v for v in self.validators
                           if not isinstance(v, ProhibitNullCharactersValidator)]


class AnalyzeRequestSerializer(serializers.Serializer):
    content = RawContentField(trim_whitespace=True)
    assess = serializers.BooleanField(default=False, help_text="Also run the full security assessment (slower)")

    def validate_content(self, value):
        if len(value) > settings.SCANNER_MAX_CONTENT_CHARS:
            raise serializers.ValidationError("The scanned content is too long.")
        return value
