import io
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from PIL import Image

from apps.audit.models import AuditLog
from apps.qr_codes import services
from apps.qr_codes.models import QRCode, QRDestinationHistory
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db


def _png(size=(300, 200), color=(200, 30, 30), fmt="PNG", **save_kw):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt, **save_kw)
    return buf.getvalue()


# ---- ownership / isolation (Scenario 13) -----------------------------------------------
def test_user_isolation_on_every_endpoint(auth_client, other_client):
    qid = make_qr(auth_client).data["id"]
    base = f"/api/v1/qr/{qid}/"
    assert other_client.get(base).status_code == 404
    assert other_client.patch(base, {"name": "hacked"}, format="json").status_code == 404
    assert other_client.delete(base).status_code == 404
    for action in ("pause", "activate", "disable"):
        assert other_client.post(f"{base}{action}/").status_code == 404
    assert other_client.get(f"{base}history/").status_code == 404
    assert other_client.get(f"{base}image/png/").status_code == 404
    up = SimpleUploadedFile("l.png", _png(), content_type="image/png")
    assert other_client.post(f"{base}logo/", {"logo": up}, format="multipart").status_code == 404
    assert other_client.get("/api/v1/qr/").data["count"] == 0
    assert QRCode.objects.get(pk=qid).name == "Menu"


def test_list_filter_search_and_pagination(auth_client):
    make_qr(auth_client, name="Alpha menu")
    make_qr(auth_client, name="Beta flyer", code_mode="static", qr_type="text", data={"text": "x"})
    assert auth_client.get("/api/v1/qr/").data["count"] == 2
    assert auth_client.get("/api/v1/qr/?code_mode=static").data["count"] == 1
    assert auth_client.get("/api/v1/qr/?search=alpha").data["count"] == 1
    assert auth_client.get("/api/v1/qr/?ordering=name").data["results"][0]["name"] == "Alpha menu"


# ---- destination updates (Scenario 2) ----------------------------------------------------
def test_destination_change_keeps_image_and_updates_resolution(auth_client, api):
    created = make_qr(auth_client).data
    qid, token = created["id"], created["public_token"]
    before = auth_client.get(f"/api/v1/qr/{qid}/image/png/").content

    r = auth_client.patch(f"/api/v1/qr/{qid}/", {
        "current_destination": "https://example.org/new", "change_reason": "New menu"}, format="json")
    assert r.status_code == 200 and r.data["current_destination"] == "https://example.org/new"

    after = auth_client.get(f"/api/v1/qr/{qid}/image/png/").content
    assert before == after  # printed code never changes
    assert api.get(f"/api/v1/scanner/verify/{token}/").data["destination"] == "https://example.org/new"

    hist = auth_client.get(f"/api/v1/qr/{qid}/history/").data["results"]
    assert [h["new_destination"] for h in hist] == ["https://example.org/new", "https://example.com/menu"]
    assert hist[0]["previous_destination"] == "https://example.com/menu"
    assert hist[0]["change_reason"] == "New menu"
    assert AuditLog.objects.filter(action="qr.destination_changed").count() == 1


def test_same_destination_adds_no_history_and_unsafe_destination_rejected(auth_client):
    qid = make_qr(auth_client).data["id"]
    auth_client.patch(f"/api/v1/qr/{qid}/", {"current_destination": "https://example.com/menu"}, format="json")
    assert QRDestinationHistory.objects.filter(qr_code_id=qid).count() == 1
    bad = auth_client.patch(f"/api/v1/qr/{qid}/", {"current_destination": "javascript:alert(1)"}, format="json")
    assert bad.status_code == 400


def test_static_code_destination_cannot_change(auth_client):
    qid = make_qr(auth_client, code_mode="static").data["id"]
    r = auth_client.patch(f"/api/v1/qr/{qid}/", {"current_destination": "https://evil.example"}, format="json")
    assert r.status_code == 400
    assert QRCode.objects.get(pk=qid).encoded_payload == "https://example.com/menu"


def test_patch_cannot_touch_protected_fields(auth_client, other_user):
    created = make_qr(auth_client).data
    auth_client.patch(f"/api/v1/qr/{created['id']}/", {
        "owner": str(other_user.pk), "public_token": "x" * 24, "status": "disabled",
        "encoded_payload": "https://evil", "name": "Renamed"}, format="json")
    qr = QRCode.objects.get(pk=created["id"])
    assert qr.name == "Renamed" and qr.owner != other_user
    assert qr.public_token == created["public_token"] and qr.status == "active"
    assert qr.encoded_payload == created["encoded_payload"]


# ---- lifecycle & public resolution ----------------------------------------------------------
def test_pause_activate_disable_flow(auth_client, api):
    created = make_qr(auth_client).data
    qid, token = created["id"], created["public_token"]
    verify = lambda: api.get(f"/api/v1/scanner/verify/{token}/").data

    assert verify()["state"] == "active" and verify()["destination"]
    auth_client.post(f"/api/v1/qr/{qid}/pause/")
    v = verify()
    assert v["state"] == "paused" and v["destination"] is None  # never the former destination
    assert "example.com" not in str(v)
    assert auth_client.post(f"/api/v1/qr/{qid}/activate/").data["status"] == "active"
    assert verify()["destination"]

    auth_client.post(f"/api/v1/qr/{qid}/disable/", {"reason": "retired"}, format="json")
    v = verify()
    assert v["state"] == "disabled" and v["destination"] is None
    assert auth_client.post(f"/api/v1/qr/{qid}/activate/").status_code == 400
    assert auth_client.post(f"/api/v1/qr/{qid}/pause/").status_code == 400


def test_expiry_blocks_resolution_and_reactivation(auth_client, api):
    created = make_qr(auth_client, expires_at=(timezone.now() + timedelta(days=1)).isoformat()).data
    QRCode.objects.filter(pk=created["id"]).update(expires_at=timezone.now() - timedelta(minutes=1))
    v = api.get(f"/api/v1/scanner/verify/{created['public_token']}/").data
    assert v["state"] == "expired" and v["destination"] is None
    assert auth_client.get(f"/api/v1/qr/{created['id']}/").data["effective_status"] == "expired"
    assert auth_client.post(f"/api/v1/qr/{created['id']}/pause/").status_code == 200
    assert auth_client.post(f"/api/v1/qr/{created['id']}/activate/").status_code == 400
    future = (timezone.now() + timedelta(days=2)).isoformat()
    auth_client.patch(f"/api/v1/qr/{created['id']}/", {"expires_at": future}, format="json")
    assert auth_client.post(f"/api/v1/qr/{created['id']}/activate/").status_code == 200


def test_staff_disabled_code_cannot_be_restored_by_owner(auth_client, user, api):
    created = make_qr(auth_client).data
    qr = QRCode.objects.get(pk=created["id"])
    services.disable_qr(qr, user=user, reason="Reported", by_staff=True)
    assert auth_client.post(f"/api/v1/qr/{qr.pk}/activate/").status_code == 403
    assert auth_client.patch(f"/api/v1/qr/{qr.pk}/", {"name": "x"}, format="json").status_code == 403
    assert api.get(f"/api/v1/scanner/verify/{created['public_token']}/").data["state"] == "disabled"
    services.staff_restore_qr(QRCode.objects.get(pk=qr.pk), user=user)
    assert api.get(f"/api/v1/scanner/verify/{created['public_token']}/").data["state"] == "active"


def test_delete_removes_code_and_token_stops_resolving(auth_client, api):
    created = make_qr(auth_client).data
    assert auth_client.delete(f"/api/v1/qr/{created['id']}/").status_code == 204
    assert api.get(f"/api/v1/scanner/verify/{created['public_token']}/").status_code == 404
    assert AuditLog.objects.filter(action="qr.deleted").exists()


def test_verify_public_endpoint_behaviour(auth_client, api, user):
    created = make_qr(auth_client).data
    token = created["public_token"]
    assert api.get("/api/v1/scanner/verify/short/").status_code == 404
    assert api.get("/api/v1/scanner/verify/" + "A" * 24 + "/").status_code == 404
    r = api.get(f"/api/v1/scanner/verify/{token}/")
    assert r.status_code == 200 and r["Cache-Control"] == "no-store"
    assert r.data["requires_user_confirmation"] is True
    assert r.data["security"]["status"] == "assessment_not_available"
    # publisher name is shown only for a verified email
    assert r.data["qr"]["publisher"] is None
    user.email_verified = True
    user.save()
    assert api.get(f"/api/v1/scanner/verify/{token}/").data["qr"]["publisher"] == "Ada"
    assert QRCode.objects.get(pk=created["id"]).last_scanned_at is not None
    # static codes have no public token and never resolve
    st = make_qr(auth_client, code_mode="static").data
    assert st["public_token"] is None


# ---- logo upload --------------------------------------------------------------------------------
def test_logo_upload_valid_strips_metadata_and_raises_error_correction(auth_client):
    qid = make_qr(auth_client, style={"error_correction": "L"}).data["id"]
    exif = Image.Exif()
    exif[0x010E] = "secret description"
    jpg = _png(fmt="JPEG", exif=exif)
    up = SimpleUploadedFile("logo.jpg", jpg, content_type="image/jpeg")
    r = auth_client.post(f"/api/v1/qr/{qid}/logo/", {"logo": up}, format="multipart")
    assert r.status_code == 200 and r.data["has_logo"] is True
    assert r.data["style"]["error_correction"] == "H"
    qr = QRCode.objects.get(pk=qid)
    stored = Image.open(qr.logo.path)
    assert stored.format == "PNG" and not stored.getexif()


@pytest.mark.parametrize("name,content", [
    ("evil.png", b"<script>alert(1)</script>"),
    ("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>"),
    ("fake.png", b"GIF89a" + b"\x00" * 20),
    ("empty.png", b""),
])
def test_logo_upload_rejects_non_images(auth_client, name, content):
    qid = make_qr(auth_client).data["id"]
    up = SimpleUploadedFile(name, content, content_type="image/png")
    r = auth_client.post(f"/api/v1/qr/{qid}/logo/", {"logo": up}, format="multipart")
    assert r.status_code == 400


def test_logo_too_large_rejected(auth_client, settings):
    settings.QR_MAX_LOGO_BYTES = 500
    qid = make_qr(auth_client).data["id"]
    up = SimpleUploadedFile("big.png", _png((400, 400)), content_type="image/png")
    assert auth_client.post(f"/api/v1/qr/{qid}/logo/", {"logo": up}, format="multipart").status_code == 400


def test_logo_requires_high_error_correction_and_can_be_removed(auth_client):
    qid = make_qr(auth_client).data["id"]
    up = SimpleUploadedFile("l.png", _png(), content_type="image/png")
    auth_client.post(f"/api/v1/qr/{qid}/logo/", {"logo": up}, format="multipart")
    bad = auth_client.patch(f"/api/v1/qr/{qid}/", {"style": {"error_correction": "L"}}, format="json")
    assert bad.status_code == 400
    ok = auth_client.patch(f"/api/v1/qr/{qid}/", {"style": {"error_correction": "Q"}}, format="json")
    assert ok.status_code == 200
    assert auth_client.delete(f"/api/v1/qr/{qid}/logo/").data["has_logo"] is False


def test_style_patch_validates_merged_colours(auth_client):
    qid = make_qr(auth_client, style={"fg_color": "#0B1F3A"}).data["id"]
    bad = auth_client.patch(f"/api/v1/qr/{qid}/", {"style": {"bg_color": "#0C2040"}}, format="json")
    assert bad.status_code == 400


# ---- campaigns -------------------------------------------------------------------------------------
def test_campaign_crud_is_owner_scoped(auth_client, other_client):
    c = auth_client.post("/api/v1/campaigns/", {"name": "Summer"}, format="json")
    assert c.status_code == 201
    assert auth_client.post("/api/v1/campaigns/", {"name": "summer"}, format="json").status_code == 400
    assert other_client.get(f"/api/v1/campaigns/{c.data['id']}/").status_code == 404
    qr = make_qr(auth_client, campaign=c.data["id"]).data
    assert auth_client.get(f"/api/v1/qr/?campaign={c.data['id']}").data["count"] == 1
    assert auth_client.get(f"/api/v1/campaigns/{c.data['id']}/").data["qr_count"] == 1
    auth_client.delete(f"/api/v1/campaigns/{c.data['id']}/")
    assert auth_client.get(f"/api/v1/qr/{qr['id']}/").data["campaign"] is None
