import io

import cv2
import numpy as np
import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

from apps.qr_codes.rendering import check_colors, contrast_ratio
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db


def decode(png: bytes) -> str:
    """Decode with OpenCV. A single OpenCV detector pass misses ~4% of valid codes, so try the
    second detector and a few scales before concluding a code is unreadable."""
    img = cv2.imdecode(np.frombuffer(png, np.uint8), cv2.IMREAD_COLOR)
    detectors = [cv2.QRCodeDetector(), cv2.QRCodeDetectorAruco()]
    for scale in (1, 0.5, 0.75, 1.5, 2):
        frame = img if scale == 1 else cv2.resize(
            img, None, fx=scale, fy=scale,
            interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_NEAREST)
        for det in detectors:
            value, _, _ = det.detectAndDecode(frame)
            if value:
                return value
    return ""


def get_png(client, qid):
    r = client.get(f"/api/v1/qr/{qid}/image/png/")
    assert r.status_code == 200 and r["Content-Type"] == "image/png"
    return r.content


def test_many_random_dynamic_codes_all_decode():
    from apps.qr_codes.models import generate_public_token
    from apps.qr_codes.rendering import render_qr
    for _ in range(60):
        payload = f"http://localhost:8000/r/{generate_public_token()}"
        assert decode(render_qr(payload, {}, "png")) == payload


def test_default_png_decodes_to_payload(auth_client):
    created = make_qr(auth_client, code_mode="static").data
    assert decode(get_png(auth_client, created["id"])) == "https://example.com/menu"


def test_dynamic_png_decodes_to_redirect_url_not_destination(auth_client):
    created = make_qr(auth_client).data
    value = decode(get_png(auth_client, created["id"]))
    assert value == created["encoded_payload"] and "example.com/menu" not in value


@pytest.mark.parametrize("style", [
    {"fg_color": "#0B1F3A", "bg_color": "#F4FBFB"},
    {"fg_color": "#0E7C86", "bg_color": "#FFFFFF"},
    {"error_correction": "H", "box_size": 6},
    {"error_correction": "L", "box_size": 20},
    {"frame_text": "SCAN ME"},
    {"fg_color": "#0B1F3A", "bg_color": "#FFFFFF", "frame_text": "SCAN ME", "error_correction": "Q"},
])
def test_styled_codes_remain_scannable(auth_client, style):
    created = make_qr(auth_client, code_mode="static", style=style).data
    assert decode(get_png(auth_client, created["id"])) == "https://example.com/menu"


def test_code_with_logo_remains_scannable(auth_client):
    created = make_qr(auth_client, code_mode="static").data
    buf = io.BytesIO()
    Image.new("RGB", (400, 300), (220, 40, 40)).save(buf, format="PNG")
    up = SimpleUploadedFile("logo.png", buf.getvalue(), content_type="image/png")
    r = auth_client.post(f"/api/v1/qr/{created['id']}/logo/", {"logo": up}, format="multipart")
    assert r.status_code == 200
    png = get_png(auth_client, created["id"])
    assert decode(png) == "https://example.com/menu"
    # logo really is drawn: centre pixel is the logo colour
    img = Image.open(io.BytesIO(png)).convert("RGB")
    assert img.getpixel((img.width // 2, img.height // 2)) == (220, 40, 40)


def test_wifi_and_vcard_payloads_decode(auth_client):
    w = make_qr(auth_client, qr_type="wifi", code_mode="static",
                data={"ssid": "Home", "password": "hunter2hunter2"}).data
    assert decode(get_png(auth_client, w["id"])) == w["encoded_payload"]
    v = make_qr(auth_client, qr_type="vcard", code_mode="static",
                data={"first_name": "Ada", "last_name": "L", "phone": "+441234567890"}).data
    assert decode(get_png(auth_client, v["id"])) == v["encoded_payload"]


def test_quiet_zone_is_present(auth_client):
    created = make_qr(auth_client, code_mode="static").data
    img = Image.open(io.BytesIO(get_png(auth_client, created["id"]))).convert("L")
    # 4 modules x 10px border on every side must be pure background
    assert all(img.getpixel((x, y)) == 255 for x in range(40) for y in range(img.height))
    assert all(img.getpixel((x, y)) == 255 for x in range(img.width) for y in range(40))


def test_svg_and_pdf_exports_and_download_header(auth_client):
    created = make_qr(auth_client, code_mode="static",
                      style={"fg_color": "#0B1F3A", "bg_color": "#F4FBFB"}).data
    svg = auth_client.get(f"/api/v1/qr/{created['id']}/image/svg/")
    assert svg.status_code == 200 and svg["Content-Type"] == "image/svg+xml"
    body = svg.content.decode()
    assert "<svg" in body and "#0B1F3A" in body and "#F4FBFB" in body and "<script" not in body
    pdf = auth_client.get(f"/api/v1/qr/{created['id']}/image/pdf/?download=1")
    assert pdf.content.startswith(b"%PDF") and "attachment" in pdf["Content-Disposition"]
    assert pdf["Content-Disposition"].endswith('.pdf"')
    assert svg["X-Content-Type-Options"] == "nosniff" and svg["Cache-Control"] == "private, no-store"
    assert auth_client.get(f"/api/v1/qr/{created['id']}/image/gif/").status_code == 404


def test_download_filename_is_sanitised(auth_client):
    created = make_qr(auth_client, name='bad"/..\\name\r\nX: y', code_mode="static").data
    r = auth_client.get(f"/api/v1/qr/{created['id']}/image/png/?download=1")
    disp = r["Content-Disposition"]
    assert "\n" not in disp and "/" not in disp and "\\" not in disp and '"/' not in disp


def test_preview_does_not_save_and_uses_placeholder_for_dynamic(auth_client):
    body = {"qr_type": "url", "code_mode": "dynamic", "data": {"url": "https://example.com/x"}}
    r = auth_client.post("/api/v1/qr/preview/", body, format="json")
    assert r.status_code == 200 and r["Content-Type"] == "image/png"
    assert "PREVIEW-NOT-A-REAL-CODE" in decode(r.content) and "example.com/x" not in decode(r.content)
    assert auth_client.get("/api/v1/qr/").data["count"] == 0
    bad = auth_client.post("/api/v1/qr/preview/", {**body, "data": {"url": "javascript:1"}}, format="json")
    assert bad.status_code == 400


def test_contrast_helpers():
    assert contrast_ratio("#000000", "#FFFFFF") == pytest.approx(21.0)
    assert check_colors("#000000", "#FFFFFF") == []
    assert check_colors("#FFFFFF", "#000000")      # inverted
    assert check_colors("#999999", "#AAAAAA")      # too little contrast
