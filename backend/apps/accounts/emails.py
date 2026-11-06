from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.mail import send_mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

VERIFY_SALT = "scansentry.email-verify"


def make_verification_token(user) -> str:
    return signing.dumps({"uid": str(user.pk), "email": user.email}, salt=VERIFY_SALT)


def read_verification_token(token: str) -> dict:
    return signing.loads(token, salt=VERIFY_SALT, max_age=settings.EMAIL_VERIFICATION_MAX_AGE)


def send_verification_email(user) -> None:
    link = f"{settings.FRONTEND_URL}/verify-email?token={make_verification_token(user)}"
    send_mail(
        "Verify your ScanSentry email",
        f"Welcome to ScanSentry.\n\nConfirm your email address:\n{link}\n\n"
        "If you did not create this account, you can ignore this message.",
        settings.DEFAULT_FROM_EMAIL, [user.email],
    )


def send_existing_account_notice(user) -> None:
    """Sent instead of revealing that the email is already registered."""
    send_mail(
        "Someone tried to register with your email",
        "A registration was attempted with this email address, but an account already "
        f"exists. If this was you, sign in or reset your password at {settings.FRONTEND_URL}.",
        settings.DEFAULT_FROM_EMAIL, [user.email],
    )


def send_password_reset_email(user) -> None:
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    link = f"{settings.FRONTEND_URL}/reset-password?uid={uid}&token={token}"
    send_mail(
        "Reset your ScanSentry password",
        f"Use this link to reset your password (it expires soon):\n{link}\n\n"
        "If you did not request this, you can ignore this message.",
        settings.DEFAULT_FROM_EMAIL, [user.email],
    )
