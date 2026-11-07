"""Server-side QR decoding for uploaded images. Pure computation: nothing is stored or fetched."""
import cv2
import numpy as np
from django.conf import settings
from PIL import Image

from apps.core.images import open_validated_image

MAX_RESULTS = 5
MAX_SIDE = 2400  # downscale very large photos so decoding stays fast


def _frames(img: np.ndarray):
    """Yield image variants: original, other scales, and inverted (light-on-dark codes)."""
    for scale in (1.0, 0.5, 1.5):
        frame = img if scale == 1.0 else cv2.resize(
            img, None, fx=scale, fy=scale,
            interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_CUBIC)
        yield frame
    yield cv2.bitwise_not(img)


def decode_array(img: np.ndarray) -> list[str]:
    detectors = [cv2.QRCodeDetector(), cv2.QRCodeDetectorAruco()]
    found: list[str] = []

    def add(values):
        for v in values:
            if v and v not in found and len(found) < MAX_RESULTS:
                found.append(v)

    for frame in _frames(img):
        for det in detectors:
            try:
                ok, decoded, _, _ = det.detectAndDecodeMulti(frame)
                if ok:
                    add(decoded)
                if not found:
                    value, _, _ = det.detectAndDecode(frame)
                    add([value])
            except cv2.error:
                continue
            if found:
                return found
    return found


def decode_upload(upload) -> list[str]:
    """Validate the upload by content (type, size, pixel count) and decode any QR codes."""
    pil = open_validated_image(
        upload, field="image", max_bytes=settings.SCANNER_MAX_IMAGE_BYTES,
        max_pixels=settings.SCANNER_MAX_IMAGE_PIXELS)
    pil = pil.convert("RGB")
    if max(pil.size) > MAX_SIDE:
        pil.thumbnail((MAX_SIDE, MAX_SIDE), Image.LANCZOS)
    img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
    return decode_array(img)
