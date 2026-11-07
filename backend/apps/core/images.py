"""Validate uploaded images by content and re-encode them (drops EXIF/other metadata)."""
import io
import uuid

from django.core.files.base import ContentFile
from PIL import Image, UnidentifiedImageError
from rest_framework.exceptions import ValidationError

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}


def open_validated_image(upload, *, field: str, max_bytes: int, max_pixels: int,
                         allowed=ALLOWED_FORMATS) -> Image.Image:
    """Return a fully loaded RGBA-capable PIL image or raise a DRF ValidationError."""
    if upload.size > max_bytes:
        raise ValidationError({field: "File is too large."})
    try:
        probe = Image.open(upload)
        probe.verify()
        upload.seek(0)
        img = Image.open(upload)
        if img.format not in allowed:
            raise ValidationError({field: "Unsupported image type. Use PNG, JPEG or WebP."})
        if img.width * img.height > max_pixels:  # checked before pixel data is decoded
            raise ValidationError({field: "Image dimensions are too large."})
        img.load()
        return img
    except ValidationError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError, ValueError):
        raise ValidationError({field: "Upload a valid image file."})


def sanitize_image_upload(upload, *, field: str, max_bytes: int, max_pixels: int = 4_000_000) -> ContentFile:
    img = open_validated_image(upload, field=field, max_bytes=max_bytes, max_pixels=max_pixels)
    out = io.BytesIO()
    img.convert("RGBA").save(out, format="PNG")  # re-encode: no metadata survives
    return ContentFile(out.getvalue(), name=f"{uuid.uuid4().hex}.png")
