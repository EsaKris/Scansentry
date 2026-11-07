import io

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from PIL import Image

from apps.qr_codes.rendering import render_qr
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db
URL = "/api/v1/scanner/decode/"


def upload(api, data: bytes, name="qr.png", ctype="image/png"):
    return api.post(URL, {"image": SimpleUploadedFile(name, data, content_type=ctype)}, format="multipart")


def test_decode_png_url(api):
    r = upload(api, render_qr("https://example.com/menu", {}, "png"))
    assert r.status_code == 200 and r.data["found"] and r.data["count"] == 1
    item = r.data["results"][0]
    assert item["content"] == "https://example.com/menu"
    assert item["analysis"]["kind"] == "url" and item["analysis"]["actions"]["requires_user_confirmation"]


def test_decode_jpeg_screenshot_style_with_margin_and_scale(api):
    png = Image.open(io.BytesIO(render_qr("https://example.com/menu", {}, "png"))).convert("RGB")
    canvas = Image.new("RGB", (png.width + 200, png.height + 200), (230, 230, 230))
    canvas.paste(png, (100, 100))
    canvas = canvas.resize((int(canvas.width * 0.6), int(canvas.height * 0.6)))
    buf = io.BytesIO()
    canvas.save(buf, format="JPEG", quality=70)
    r = upload(api, buf.getvalue(), "photo.jpg", "image/jpeg")
    assert r.status_code == 200 and r.data["found"], r.data
    assert r.data["results"][0]["content"] == "https://example.com/menu"


def test_decode_light_on_dark_code(api):
    img = Image.open(io.BytesIO(render_qr("https://example.com/inv", {}, "png"))).convert("RGB")
    inverted = Image.eval(img, lambda v: 255 - v)
    buf = io.BytesIO()
    inverted.save(buf, format="PNG")
    r = upload(api, buf.getvalue())
    assert r.data["found"] and r.data["results"][0]["content"] == "https://example.com/inv"


def test_decode_dynamic_code_includes_managed_analysis(auth_client, api):
    qr = make_qr(auth_client).data
    r = upload(api, auth_client.get(f"/api/v1/qr/{qr['id']}/image/png/").content)
    a = r.data["results"][0]["analysis"]
    assert a["scansentry"]["state"] == "active" and a["actions"]["open_target"] == "https://example.com/menu"


def test_decode_dangerous_scheme_code_is_reported_blocked(api):
    r = upload(api, render_qr("javascript:alert(document.cookie)", {}, "png"))
    a = r.data["results"][0]["analysis"]
    assert a["kind"] == "blocked_scheme" and a["actions"]["blocked"]


def test_blank_image_finds_nothing(api):
    buf = io.BytesIO()
    Image.new("RGB", (300, 300), "white").save(buf, format="PNG")
    r = upload(api, buf.getvalue())
    assert r.status_code == 200 and r.data == {"found": False, "count": 0, "results": []}


@pytest.mark.parametrize("name,ctype,data", [
    ("x.png", "image/png", b"not an image at all"),
    ("x.svg", "image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>"),
    ("x.gif", "image/gif", b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"),
    ("x.png", "image/png", b""),
])
def test_decode_rejects_non_supported_files(api, name, ctype, data):
    assert upload(api, data, name, ctype).status_code == 400


def test_decode_rejects_oversized_file_and_pixel_bombs(api, settings):
    settings.SCANNER_MAX_IMAGE_BYTES = 1000
    assert upload(api, render_qr("https://example.com/menu", {}, "png")).status_code == 400
    settings.SCANNER_MAX_IMAGE_BYTES = 5_000_000
    settings.SCANNER_MAX_IMAGE_PIXELS = 1_000_000
    buf = io.BytesIO()
    Image.new("1", (3000, 3000)).save(buf, format="PNG")  # tiny file, 9M pixels
    assert len(buf.getvalue()) < 100_000
    assert upload(api, buf.getvalue()).status_code == 400


def test_decode_stores_nothing(api, settings):
    upload(api, render_qr("https://example.com/menu", {}, "png"))
    assert not settings.MEDIA_ROOT.exists() or not any(settings.MEDIA_ROOT.rglob("*"))


def test_decode_requires_an_image_field(api):
    assert api.post(URL, {}, format="multipart").status_code == 400
    assert api.post(URL, {"image": "text"}, format="multipart").status_code == 400
