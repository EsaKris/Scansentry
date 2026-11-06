"""QR image rendering (PNG / SVG / PDF) with scannability guards."""
import io
import re

import qrcode
from django.conf import settings
from PIL import Image, ImageDraw, ImageFont
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q
from qrcode.exceptions import DataOverflowError
from qrcode.image.svg import SvgPathImage

QUIET_ZONE_MODULES = 4  # fixed: the QR specification's minimum quiet zone
EC_LEVELS = {"L": ERROR_CORRECT_L, "M": ERROR_CORRECT_M, "Q": ERROR_CORRECT_Q, "H": ERROR_CORRECT_H}
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

DEFAULT_STYLE = {"fg_color": "#000000", "bg_color": "#FFFFFF", "error_correction": "M",
                 "box_size": 10, "frame_text": ""}


class PayloadTooLarge(Exception):
    pass


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _luminance(hex_color: str) -> float:
    def chan(c):
        c = c / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (chan(c) for c in _rgb(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: str, bg: str) -> float:
    a, b = _luminance(fg), _luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def check_colors(fg: str, bg: str) -> list[str]:
    """Return human-readable problems that would make the code hard to scan."""
    problems = []
    if _luminance(fg) >= _luminance(bg):
        problems.append("The code colour must be darker than the background (inverted codes "
                        "are not read by many scanners).")
    elif contrast_ratio(fg, bg) < settings.QR_MIN_CONTRAST_RATIO:
        problems.append(f"Contrast is too low for reliable scanning "
                        f"(minimum ratio {settings.QR_MIN_CONTRAST_RATIO}).")
    return problems


def _make_qr(payload: str, ec: str) -> qrcode.QRCode:
    qr = qrcode.QRCode(error_correction=EC_LEVELS[ec], box_size=10, border=QUIET_ZONE_MODULES)
    qr.add_data(payload)
    try:
        qr.make(fit=True)
    except (DataOverflowError, ValueError):
        raise PayloadTooLarge("The content is too large to fit in a QR code.")
    return qr


def check_fits(payload: str, ec: str) -> None:
    _make_qr(payload, ec)


def _paste_logo(img: Image.Image, logo_bytes: bytes, bg: str) -> Image.Image:
    logo = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
    target = int(img.width * settings.QR_MAX_LOGO_RATIO)
    pad = max(2, target // 12)
    logo.thumbnail((target - 2 * pad, target - 2 * pad))
    backing = Image.new("RGBA", (logo.width + 2 * pad, logo.height + 2 * pad), (*_rgb(bg), 255))
    backing.paste(logo, (pad, pad), logo)
    pos = ((img.width - backing.width) // 2, (img.height - backing.height) // 2)
    img.paste(backing.convert("RGB"), pos)
    return img


def _add_frame(img: Image.Image, text: str, fg: str, bg: str) -> Image.Image:
    band = max(40, img.height // 7)
    out = Image.new("RGB", (img.width, img.height + band), _rgb(bg))
    out.paste(img, (0, 0))
    draw = ImageDraw.Draw(out)
    draw.rectangle([0, img.height, img.width, img.height + band], fill=_rgb(fg))
    font = ImageFont.load_default(size=max(14, band // 2))
    box = draw.textbbox((0, 0), text, font=font)
    x = (img.width - (box[2] - box[0])) // 2 - box[0]
    y = img.height + (band - (box[3] - box[1])) // 2 - box[1]
    draw.text((x, y), text, font=font, fill=_rgb(bg))
    return out


def render_qr(payload: str, style: dict | None, fmt: str, logo_bytes: bytes | None = None) -> bytes:
    s = {**DEFAULT_STYLE, **(style or {})}
    fg, bg, ec = s["fg_color"], s["bg_color"], s["error_correction"]
    qr = _make_qr(payload, ec)

    if fmt == "svg":
        class _Svg(SvgPathImage):
            QR_PATH_STYLE = {"fill": fg, "fill-opacity": "1", "fill-rule": "nonzero", "stroke": "none"}
        svg = qr.make_image(image_factory=_Svg)
        buf = io.BytesIO()
        svg.save(buf)
        text = buf.getvalue().decode("utf-8")
        rect = f'<rect width="100%" height="100%" fill="{bg}"/>'
        text = re.sub(r"(<svg[^>]*>)", lambda m: m.group(1) + rect, text, count=1)
        return text.encode("utf-8")

    scale = int(s["box_size"]) / 10
    img = qr.make_image(fill_color=fg, back_color=bg).get_image().convert("RGB")
    if scale != 1:
        img = img.resize((int(img.width * scale), int(img.height * scale)), Image.NEAREST)
    if logo_bytes:
        img = _paste_logo(img, logo_bytes, bg)
    if s.get("frame_text"):
        img = _add_frame(img, s["frame_text"], fg, bg)

    buf = io.BytesIO()
    if fmt == "pdf":
        img.save(buf, format="PDF", resolution=150.0)
    else:
        img.save(buf, format="PNG")
    return buf.getvalue()
