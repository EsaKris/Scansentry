"""Shared builder for the public verification payload of a ScanSentry dynamic QR code."""
import logging

from django.utils import timezone

from apps.qr_codes.models import QRCode

from .analysis import SECURITY_NOT_ASSESSED

log = logging.getLogger(__name__)
STATE_MESSAGES = {
    "paused": "The owner has paused this QR code.",
    "disabled": "This QR code has been disabled.",
    "expired": "This QR code has expired.",
}


def security_for(destination: str, *, assess: bool) -> tuple[dict, object]:
    """Return (security summary, SecurityCheck|None). assess=False only reads a cached check (no network)."""
    from apps.security_engine import service as sec
    from apps.security_engine.presenters import summary
    try:
        check = sec.analyze(destination, source="qr_verify")[0] if assess else sec.latest_cached_check(destination)
    except sec.NotApplicable:
        return SECURITY_NOT_ASSESSED, None
    except Exception:
        log.exception("security assessment failed")
        return {"status": "assessment_unavailable", "label": "Assessment unavailable",
                "message": "The security assessment could not be completed right now."}, None
    return (summary(check), check) if check else (SECURITY_NOT_ASSESSED, None)


def build_verification(qr: QRCode, *, touch: bool = True, assess: bool = False) -> dict:
    """State + (only while active and not blocked) destination. Never reveals a former destination."""
    from apps.security_engine.policy import MALICIOUS_MESSAGE, apply_malicious_policy
    state = qr.effective_status
    owner = qr.owner
    verified_publisher = bool(owner.email_verified and owner.display_name)
    body = {
        "state": state,
        "qr": {"name": qr.name, "qr_type": qr.qr_type, "created_at": qr.created_at,
               "publisher": owner.display_name if verified_publisher else None,
               "publisher_verified": verified_publisher},
        "destination": None,
        "requires_user_confirmation": True,
        "security": SECURITY_NOT_ASSESSED,
    }
    if state != "active":
        body["message"] = STATE_MESSAGES.get(state, "This QR code is unavailable.")
        return body

    security, check = security_for(qr.current_destination, assess=assess)
    body["security"] = security
    if check is not None and check.risk_classification == "known_malicious":
        apply_malicious_policy(qr, check)
        body["state"] = "blocked"
        body["message"] = MALICIOUS_MESSAGE
        return body
    body["destination"] = qr.current_destination
    if touch:
        QRCode.objects.filter(pk=qr.pk).update(last_scanned_at=timezone.now())
    return body
