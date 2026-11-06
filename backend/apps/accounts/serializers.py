from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=254)
    display_name = serializers.CharField(max_length=80, required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def validate_email(self, value):
        return value.strip().lower()

    def validate(self, attrs):
        probe = User(email=attrs["email"], display_name=attrs.get("display_name", ""))
        try:
            validate_password(attrs["password"], user=probe)
        except Exception as exc:  # django ValidationError
            raise serializers.ValidationError({"password": list(getattr(exc, "messages", [str(exc)]))})
        return attrs


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "email", "display_name", "email_verified", "is_staff",
                  "created_at", "updated_at", "deletion_requested_at")
        read_only_fields = ("id", "email", "email_verified", "is_staff", "created_at",
                            "updated_at", "deletion_requested_at")


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class VerifyEmailSerializer(serializers.Serializer):
    token = serializers.CharField()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)


class GenericDetailSerializer(serializers.Serializer):
    detail = serializers.CharField()
