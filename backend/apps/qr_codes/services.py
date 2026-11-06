import io
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from PIL import Image, UnidentifiedImageError
from rest_framework.exceptions import ValidationError

from apps.audit.services import record_audit
from apps.core.entitlements import FeatureLimitReached, get_limit, require_feature

from .models import QRCode, QRDestinationHistory, generate_public_token
from .payloads import REGISTRY
from .rendering import DEFAULT_STYLE

User = get_user_model()
MAX_LOGO_PIXELS = 4_000_000


def _active_dynamic_count(user) -> int:
    now = timezone.now()
    return QRCode.objects.filter(
        owner=user, code_mode=QRCode.Mode.DYNAMIC, status=QRCode.Status.ACTIVE
    ).filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now)).count()


def _check_dynamic_limit(user) -> None:
    limit = get_limit(user, "qr.dynamic.active_limit")
    if limit is not None and _active_dynamic_count(user) >= limit:
        raise FeatureLimitReached(
            f"You have reached your limit of {limit} active dynamic QR codes.")


def build_payload(qr_type: str, data: dict, code_mode: str):
    """Validate type-specific data and build the payload. Raises DRF ValidationError."""
    spec = REGISTRY[qr_type]
    ser = spec.serializer(data=data)
    ser.is_valid(raise_exception=True)
    built = spec.build(ser.validated_data)
    if len(built.payload) > settings.QR_MAX_PAYLOAD_CHARS:
        raise ValidationError({"data": "The content is too long for a QR code."})
    if code_mode == QRCode.Mode.DYNAMIC and not (spec.dynamic_capable and built.destination):
        raise ValidationError({"code_mode": "This QR type cannot be dynamic. Use a static code."})
    return ser.validated_data, built


@transaction.atomic
def create_qr(*, user, name, description, qr_type, code_mode, data, expires_at, campaign, style):
    clean, built = build_payload(qr_type, data, code_mode)
    style = {**DEFAULT_STYLE, **(style or {})}
    if code_mode == QRCode.Mode.DYNAMIC:
        require_feature(user, "qr.dynamic.create")
        User.objects.select_for_update().get(pk=user.pk)  # serialise concurrent creates
        _check_dynamic_limit(user)
        token = generate_public_token()
        payload = f"{settings.REDIRECT_BASE_URL}/r/{token}"
        destination = built.destination
    else:
        require_feature(user, "qr.static.create")
        token, payload, destination = None, built.payload, ""

    from .rendering import check_fits, PayloadTooLarge
    try:
        check_fits(payload, style["error_correction"])
    except PayloadTooLarge as exc:
        raise ValidationError({"data": str(exc)})

    qr = QRCode.objects.create(
        owner=user, name=name, description=description, qr_type=qr_type, code_mode=code_mode,
        public_token=token, current_destination=destination, source_data=clean,
        encoded_payload=payload, style=style, expires_at=expires_at, campaign=campaign,
    )
    if qr.is_dynamic:
        QRDestinationHistory.objects.create(
            qr_code=qr, previous_destination="", new_destination=destination,
            changed_by=user, change_reason="Initial destination")
    record_audit(actor=user, action="qr.created", obj=qr,
                 after={"mode": code_mode, "type": qr_type})
    return qr


@transaction.atomic
def change_destination(qr: QRCode, new_destination: str, *, user, reason: str = "") -> bool:
    """Returns True if the destination changed. History is append-only."""
    if not qr.is_dynamic:
        raise ValidationError({"current_destination": "Static QR codes cannot be edited."})
    if qr.disabled_by_staff:
        raise ValidationError({"current_destination": "This QR code was disabled by ScanSentry staff."})
    if new_destination == qr.current_destination:
        return False
    old = qr.current_destination
    qr.current_destination = new_destination
    qr.save(update_fields=["current_destination", "updated_at"])
    QRDestinationHistory.objects.create(
        qr_code=qr, previous_destination=old, new_destination=new_destination,
        changed_by=user, change_reason=reason[:255])
    record_audit(actor=user, action="qr.destination_changed", obj=qr,
                 before={"destination": old}, after={"destination": new_destination})
    return True


def _set_status(qr: QRCode, status: str, *, user, reason="", by_staff=False):
    before = {"status": qr.status}
    qr.status = status
    qr.status_reason = reason[:255]
    qr.disabled_by_staff = by_staff and status == QRCode.Status.DISABLED
    qr.save(update_fields=["status", "status_reason", "disabled_by_staff", "updated_at"])
    record_audit(actor=user, action=f"qr.{status}", obj=qr, before=before, after={"status": status})


@transaction.atomic
def pause_qr(qr: QRCode, *, user):
    if qr.status == QRCode.Status.DISABLED:
        raise ValidationError({"detail": "A disabled QR code cannot be paused."})
    if qr.status != QRCode.Status.PAUSED:
        _set_status(qr, QRCode.Status.PAUSED, user=user)


@transaction.atomic
def activate_qr(qr: QRCode, *, user):
    if qr.status == QRCode.Status.ACTIVE:
        return
    if qr.status == QRCode.Status.DISABLED:
        raise ValidationError({"detail": "A disabled QR code cannot be reactivated."})
    if qr.expires_at and qr.expires_at <= timezone.now():
        raise ValidationError({"detail": "This QR code has expired. Set a new expiry date first."})
    if qr.is_dynamic:
        User.objects.select_for_update().get(pk=qr.owner_id)
        _check_dynamic_limit(qr.owner)
    _set_status(qr, QRCode.Status.ACTIVE, user=user)


@transaction.atomic
def disable_qr(qr: QRCode, *, user, reason="", by_staff=False):
    if qr.status != QRCode.Status.DISABLED:
        _set_status(qr, QRCode.Status.DISABLED, user=user, reason=reason, by_staff=by_staff)


@transaction.atomic
def staff_restore_qr(qr: QRCode, *, user):
    _set_status(qr, QRCode.Status.ACTIVE, user=user)


def process_logo_upload(upload) -> ContentFile:
    """Validate by actual content, strip metadata by re-encoding, return a PNG."""
    if upload.size > settings.QR_MAX_LOGO_BYTES:
        raise ValidationError({"logo": "Logo file is too large."})
    try:
        probe = Image.open(upload)
        probe.verify()
        upload.seek(0)
        img = Image.open(upload)
        if img.format not in {"PNG", "JPEG", "WEBP"}:
            raise ValidationError({"logo": "Logo must be a PNG, JPEG or WebP image."})
        if img.width * img.height > MAX_LOGO_PIXELS:
            raise ValidationError({"logo": "Logo dimensions are too large."})
        img = img.convert("RGBA")
    except (UnidentifiedImageError, OSError, SyntaxError):
        raise ValidationError({"logo": "Upload a valid image file."})
    out = io.BytesIO()
    img.save(out, format="PNG")  # re-encode: drops EXIF/other metadata
    return ContentFile(out.getvalue(), name=f"{uuid.uuid4().hex}.png")


@transaction.atomic
def set_logo(qr: QRCode, upload, *, user):
    require_feature(user, "qr.logo_upload")
    content = process_logo_upload(upload)
    if qr.logo:
        qr.logo.delete(save=False)
    qr.logo.save(content.name, content, save=False)
    if qr.style.get("error_correction") in ("L", "M"):
        qr.style = {**qr.style, "error_correction": "H"}  # logos need redundancy to stay scannable
    qr.save(update_fields=["logo", "style", "updated_at"])
    record_audit(actor=user, action="qr.logo_set", obj=qr)


@transaction.atomic
def remove_logo(qr: QRCode, *, user):
    if qr.logo:
        qr.logo.delete(save=False)
        qr.logo = ""
        qr.save(update_fields=["logo", "updated_at"])
        record_audit(actor=user, action="qr.logo_removed", obj=qr)


def delete_qr(qr: QRCode, *, user):
    record_audit(actor=user, action="qr.deleted", obj=qr,
                 before={"name": qr.name, "mode": qr.code_mode})
    if qr.logo:
        qr.logo.delete(save=False)
    qr.delete()


def resolve_token(token: str):
    """Return the QRCode for a public token or None. Callers decide what to reveal."""
    return QRCode.objects.select_related("owner").filter(
        public_token=token, code_mode=QRCode.Mode.DYNAMIC).first()


@transaction.atomic
def update_style(qr: QRCode, new_style: dict, *, user):
    from .rendering import PayloadTooLarge, check_colors, check_fits
    merged = {**DEFAULT_STYLE, **qr.style, **new_style}
    problems = check_colors(merged["fg_color"], merged["bg_color"])
    if problems:
        raise ValidationError({"style": problems})
    if qr.logo and merged["error_correction"] in ("L", "M"):
        raise ValidationError({"style": ["A QR code with a logo needs error correction Q or H."]})
    try:
        check_fits(qr.encoded_payload, merged["error_correction"])
    except PayloadTooLarge as exc:
        raise ValidationError({"style": [str(exc)]})
    qr.style = merged
    qr.save(update_fields=["style", "updated_at"])
