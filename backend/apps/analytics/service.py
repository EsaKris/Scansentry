"""Recording scan events. Analytics must never break scanning: every failure is swallowed and logged."""
import hashlib
import hmac
import logging
import re
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.throttling import BaseThrottle

from .models import ScanEvent
from .ua import classify

log = logging.getLogger(__name__)
SCANNER_TYPES = {"camera", "upload", "link"}
_CC = re.compile(r"^[A-Z]{2}$")


def visitor_hash(request, now) -> str:
    """Daily-rotating keyed hash of (date, IP, UA). Not reversible, not linkable across days."""
    ip = BaseThrottle().get_ident(request)
    ua = request.META.get("HTTP_USER_AGENT", "")[:512]
    msg = f"{now:%Y-%m-%d}|{ip}|{ua}".encode()
    return hmac.new(settings.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()[:16]


def _header(request, name: str) -> str:
    if not name:
        return ""
    return request.META.get("HTTP_" + name.upper().replace("-", "_"), "")


def geo(request) -> tuple[str, str]:
    """Only what the operator's CDN supplied; never derived from the IP here."""
    country = _header(request, settings.GEO_COUNTRY_HEADER).strip().upper()
    region = _header(request, settings.GEO_REGION_HEADER).strip()[:64]
    region = re.sub(r"[\x00-\x1f\x7f]", "", region)
    return (country if _CC.match(country) and country not in ("XX", "T1") else ""), region


def record_scan(request, *, qr=None, outcome: str, scanner_type: str = "link", security_status: str = "",
                content_kind: str = "", now=None):
    try:
        now = now or timezone.now()
        info = classify(request.META.get("HTTP_USER_AGENT", ""))
        vh = visitor_hash(request, now)
        scanner_type = scanner_type if scanner_type in SCANNER_TYPES else "link"
        if qr is not None and settings.ANALYTICS_DEDUPE_SECONDS:
            window = now - timedelta(seconds=settings.ANALYTICS_DEDUPE_SECONDS)
            if ScanEvent.objects.filter(qr_code=qr, visitor_hash=vh, scanned_at__gte=window).exists():
                return None                    # same device scanning the same code moments ago: one scan
        country, region = geo(request)
        return ScanEvent.objects.create(
            qr_code=qr, scanned_at=now, outcome=outcome, device_category=info["device"],
            browser_category=info["browser"], approximate_country=country, approximate_region=region,
            scanner_type=scanner_type, security_status_at_scan=security_status[:32], content_kind=content_kind[:24],
            visitor_hash=vh, is_bot=info["is_bot"])
    except Exception:
        log.exception("could not record scan event")
        return None
