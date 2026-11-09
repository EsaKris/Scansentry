import hashlib
import hmac
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.throttling import BaseThrottle

from apps.audit.services import record_audit
from apps.core.images import sanitize_image_upload
from apps.core.urlsafety import validate_http_url

from .models import AbuseReport


def _hash(value: str) -> str:
    return hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def reporter_identity(request) -> str:
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated:
        return _hash(f"user:{user.pk}")
    return _hash(f"ip:{BaseThrottle().get_ident(request)}")


def submit_report(*, request, qr_token, url, category, description, evidence):
    from apps.qr_codes.services import resolve_token

    qr = None
    submitted_url = ""
    if qr_token:
        qr = resolve_token(qr_token)
        if qr is None:
            raise ValidationError({"qr_token": "No QR code matches this token."})
        target = f"qr:{qr_token}"
    else:
        from django.core.exceptions import ValidationError as DjangoValidationError
        try:
            submitted_url = validate_http_url(url)
        except DjangoValidationError as exc:
            raise ValidationError({"url": exc.messages})
        target = f"url:{submitted_url}"
    target_key = hashlib.sha256(target.encode()).hexdigest()
    who = reporter_identity(request)

    # Same reporter, same target, same category inside the window: accept silently, store once.
    window = timezone.now() - timedelta(hours=settings.ABUSE_DEDUPE_HOURS)
    if AbuseReport.objects.filter(reporter_hash=who, target_key=target_key, category=category,
                                  created_at__gte=window).exists():
        return None

    evidence_file = None
    if evidence is not None:
        evidence_file = sanitize_image_upload(
            evidence, field="evidence", max_bytes=settings.ABUSE_EVIDENCE_MAX_BYTES)

    original = AbuseReport.objects.filter(target_key=target_key, category=category,
                                          duplicate_of__isnull=True).order_by("created_at").first()
    user = request.user if request.user.is_authenticated else None
    report = AbuseReport(
        reporter=user, reporter_hash=who, qr_code=qr, submitted_url=submitted_url,
        target_key=target_key, category=category, description=description, duplicate_of=original)
    if evidence_file is not None:
        report.evidence_file.save(evidence_file.name, evidence_file, save=False)
    report.save()
    if qr is not None:
        from apps.notifications.service import alert_abuse_report
        alert_abuse_report(qr, category)      # category only: the reporter's identity is never shared
    return report


def review_report(report: AbuseReport, *, reviewer, status, notes="", resolution=""):
    before = {"status": report.review_status}
    report.review_status = status
    report.reviewer = reviewer
    report.reviewer_notes = notes
    report.resolution = resolution
    report.reviewed_at = timezone.now()
    report.save(update_fields=["review_status", "reviewer", "reviewer_notes", "resolution",
                               "reviewed_at"])
    record_audit(actor=reviewer, action="abuse_report.reviewed", obj=report, before=before,
                 after={"status": status})
