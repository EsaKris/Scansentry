from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from drf_spectacular.utils import extend_schema
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.audit.services import record_audit

from . import emails
from .serializers import (
    GenericDetailSerializer, LogoutSerializer, PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer, RegisterSerializer, UserSerializer,
    VerifyEmailSerializer,
)

User = get_user_model()


def _scoped(scope):
    """Class attrs for ScopedRateThrottle."""
    return {"throttle_classes": [ScopedRateThrottle], "throttle_scope": scope}


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_register"

    @extend_schema(request=RegisterSerializer, responses={201: GenericDetailSerializer})
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        existing = User.objects.filter(email__iexact=data["email"]).first()
        if existing:
            # Same response either way: no account enumeration.
            emails.send_existing_account_notice(existing)
        else:
            user = User.objects.create_user(
                email=data["email"], password=data["password"],
                display_name=data.get("display_name", ""),
            )
            emails.send_verification_email(user)
            record_audit(actor=user, action="account.registered", obj=user)

        return Response(
            {"detail": "If the details are valid, check your email to verify your account."},
            status=status.HTTP_201_CREATED,
        )


class LoginView(TokenObtainPairView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_login"
    permission_classes = [AllowAny]
    authentication_classes: list = []


class RefreshView(TokenRefreshView):
    permission_classes = [AllowAny]
    authentication_classes: list = []


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=LogoutSerializer, responses={204: None})
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            RefreshToken(serializer.validated_data["refresh"]).blacklist()
        except TokenError:
            pass  # already invalid/expired: logging out is idempotent
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "patch", "head", "options"]

    def get_object(self):
        return self.request.user


class DeletionRequestView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={202: GenericDetailSerializer})
    def post(self, request):
        user = request.user
        if user.deletion_requested_at is None:
            user.deletion_requested_at = timezone.now()
            user.save(update_fields=["deletion_requested_at", "updated_at"])
            record_audit(actor=user, action="account.deletion_requested", obj=user)
        return Response(
            {"detail": "Your account deletion request has been recorded."},
            status=status.HTTP_202_ACCEPTED,
        )


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_verify"

    @extend_schema(request=VerifyEmailSerializer, responses={200: GenericDetailSerializer})
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            payload = emails.read_verification_token(serializer.validated_data["token"])
            user = User.objects.get(pk=payload["uid"], email=payload["email"])
        except (signing.BadSignature, User.DoesNotExist, ValueError):
            return Response({"detail": "This verification link is invalid or has expired."},
                            status=status.HTTP_400_BAD_REQUEST)
        if not user.email_verified:
            user.email_verified = True
            user.save(update_fields=["email_verified", "updated_at"])
            record_audit(actor=user, action="account.email_verified", obj=user)
        return Response({"detail": "Email verified."})


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_password_reset"

    @extend_schema(request=PasswordResetRequestSerializer, responses={200: GenericDetailSerializer})
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(
            email__iexact=serializer.validated_data["email"], is_active=True
        ).first()
        if user:
            emails.send_password_reset_email(user)
        return Response({"detail": "If an account exists, a reset link has been sent."})


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    authentication_classes: list = []
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth_password_reset"

    @extend_schema(request=PasswordResetConfirmSerializer, responses={200: GenericDetailSerializer})
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        invalid = Response({"detail": "This reset link is invalid or has expired."},
                           status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(pk=force_str(urlsafe_base64_decode(data["uid"])))
        except (User.DoesNotExist, ValueError, TypeError, OverflowError, DjangoValidationError):
            return invalid
        if not default_token_generator.check_token(user, data["token"]):
            return invalid
        try:
            validate_password(data["new_password"], user=user)
        except DjangoValidationError as exc:
            return Response({"error": {"code": "validation_error",
                                       "message": "The password is not acceptable.",
                                       "details": {"new_password": exc.messages}}},
                            status=status.HTTP_400_BAD_REQUEST)
        user.set_password(data["new_password"])
        user.save(update_fields=["password", "updated_at"])
        record_audit(actor=user, action="account.password_reset", obj=user)
        return Response({"detail": "Password updated."})
