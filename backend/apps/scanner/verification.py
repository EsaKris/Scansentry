"""Shared builder for the public verification payload of a ScanSentry dynamic QR code."""
from django.utils import timezone

from apps.qr_codes.models import QRCode

from .analysis import SECURITY_NOT_ASSESSED

STATE_MESSAGES = {
    "paused": "The owner has paused this QR code.",
    "disabled": "This QR code has been disabled.",
    "expired": "This QR code has expired.",
}


def build_verification(qr: QRCode, *, touch: bool = True) -> dict:
    """State + (only while active) destination. Never reveals a former destination."""
    state = qr.effective_status
    owner = qr.owner
    verified_publisher = bool(owner.email_verified and owner.display_name)
    body = {
        "state": state,
        "qr": {
            "name": qr.name,
            "qr_type": qr.qr_type,
            "created_at": qr.created_at,
            "publisher": owner.display_name if verified_publisher else None,
            "publisher_verified": verified_publisher,
        },
        "destination": None,
        "requires_user_confirmation": True,
        "security": SECURITY_NOT_ASSESSED,
    }
    if state == "active":
        body["destination"] = qr.current_destination
        if touch:
            QRCode.objects.filter(pk=qr.pk).update(last_scanned_at=timezone.now())
    else:
        body["message"] = STATE_MESSAGES.get(state, "This QR code is unavailable.")
    return body
