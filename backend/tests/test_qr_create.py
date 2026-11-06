import re
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.audit.models import AuditLog
from apps.core.models import AppConfiguration
from apps.qr_codes.models import QRCode, QRDestinationHistory
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db


def test_create_static_url(auth_client):
    r = make_qr(auth_client, code_mode="static")
    assert r.status_code == 201
    assert r.data["encoded_payload"] == "https://example.com/menu"
    assert r.data["public_token"] is None and r.data["public_url"] is None
    assert r.data["style"]["error_correction"] == "M"
    assert AuditLog.objects.filter(action="qr.created").exists()


def test_create_dynamic_uses_random_token_and_records_history(auth_client, settings):
    r = make_qr(auth_client)
    assert r.status_code == 201
    token = r.data["public_token"]
    assert len(token) >= 24 and re.fullmatch(r"[A-Za-z0-9_-]+", token)
    assert r.data["encoded_payload"] == f"{settings.REDIRECT_BASE_URL}/r/{token}"
    assert r.data["current_destination"] == "https://example.com/menu"
    assert str(r.data["id"]) not in r.data["encoded_payload"]
    h = QRDestinationHistory.objects.get(qr_code_id=r.data["id"])
    assert h.previous_destination == "" and h.new_destination == "https://example.com/menu"


def test_dynamic_tokens_are_unique_and_unpredictable(auth_client):
    tokens = [make_qr(auth_client).data["public_token"] for _ in range(40)]
    assert len(set(tokens)) == 40
    # no shared prefix/sequence: first 6 chars differ between most codes
    assert len({t[:6] for t in tokens}) > 35


@pytest.mark.parametrize("bad", [
    "javascript:alert(1)", "data:text/html,<script>1</script>", "file:///etc/passwd",
    "ftp://example.com/x", "//evil.com", "example.com", "https://user:pw@example.com/",
    "https://exa mple.com", "https://", "myapp://open",
])
def test_unsafe_or_malformed_urls_rejected(auth_client, bad):
    r = make_qr(auth_client, code_mode="static", data={"url": bad})
    assert r.status_code == 400, bad
    assert r.data["error"]["code"] == "validation_error"


def test_idn_hostname_is_stored_as_punycode(auth_client):
    r = make_qr(auth_client, code_mode="static", data={"url": "https://bücher.example/Pfad?q=1"})
    assert r.status_code == 201
    assert r.data["encoded_payload"] == "https://xn--bcher-kva.example/Pfad?q=1"


def test_non_url_types_cannot_be_dynamic(auth_client):
    for qr_type, data in [("phone", {"phone": "+2348012345678"}),
                          ("wifi", {"ssid": "Home", "password": "secret123"}),
                          ("text", {"text": "hello"})]:
        r = make_qr(auth_client, qr_type=qr_type, data=data, code_mode="dynamic")
        assert r.status_code == 400 and "code_mode" in r.data["error"]["details"]


def test_all_static_types_build_expected_payloads(auth_client):
    def payload(qr_type, data):
        r = make_qr(auth_client, qr_type=qr_type, data=data, code_mode="static")
        assert r.status_code == 201, r.data
        return r.data["encoded_payload"]

    assert payload("phone", {"phone": "+234 801-234-5678"}) == "tel:+2348012345678"
    assert payload("email", {"address": "a@b.co", "subject": "Hi there", "body": "x&y"}) == \
        "mailto:a@b.co?subject=Hi%20there&body=x%26y"
    assert payload("whatsapp", {"phone": "+2348012345678", "message": "Hello you"}) == \
        "https://wa.me/2348012345678?text=Hello%20you"
    assert payload("social", {"platform": "github", "handle": "octocat"}) == "https://github.com/octocat"
    assert payload("text", {"text": "plain"}) == "plain"
    assert payload("file", {"url": "https://example.com/menu.pdf"}) == "https://example.com/menu.pdf"
    assert payload("landing", {"url": "https://example.com/landing"}) == "https://example.com/landing"
    assert payload("wifi", {"ssid": "My;Net", "password": 'p:a"ss', "security": "WPA"}) == \
        'WIFI:T:WPA;S:My\\;Net;P:p\\:a\\"ss;H:false;;'
    assert payload("wifi", {"ssid": "Open", "security": "nopass"}) == "WIFI:T:nopass;S:Open;P:;H:false;;"
    v = payload("vcard", {"first_name": "Ada", "last_name": "Lovelace", "phone": "+441234567890",
                          "email": "ada@example.com", "organization": "Analytical, Ltd"})
    assert v.startswith("BEGIN:VCARD\nVERSION:3.0") and v.endswith("END:VCARD")
    assert "FN:Ada Lovelace" in v and "ORG:Analytical\\, Ltd" in v


def test_vcard_and_wifi_reject_injection(auth_client):
    r = make_qr(auth_client, qr_type="vcard", code_mode="static",
                data={"first_name": "Ada\nEND:VCARD\nBEGIN:VCARD", "last_name": "X"})
    assert r.status_code == 400
    r = make_qr(auth_client, qr_type="wifi", code_mode="static",
                data={"ssid": "Net\r\nP:evil", "password": "x1234567"})
    assert r.status_code == 400


def test_invalid_type_specific_data(auth_client):
    assert make_qr(auth_client, qr_type="phone", code_mode="static", data={"phone": "abc"}).status_code == 400
    assert make_qr(auth_client, qr_type="wifi", code_mode="static", data={"ssid": "x"}).status_code == 400
    assert make_qr(auth_client, qr_type="social", code_mode="static",
                   data={"platform": "github", "handle": "../evil"}).status_code == 400


def test_expiry_must_be_future(auth_client):
    past = (timezone.now() - timedelta(days=1)).isoformat()
    assert make_qr(auth_client, expires_at=past).status_code == 400


def test_cannot_assign_other_users_campaign(auth_client, other_client):
    camp = other_client.post("/api/v1/campaigns/", {"name": "Theirs"}, format="json").data["id"]
    assert make_qr(auth_client, campaign=camp).status_code == 400


def test_low_contrast_and_inverted_colours_rejected(auth_client):
    low = make_qr(auth_client, style={"fg_color": "#777777", "bg_color": "#888888"})
    assert low.status_code == 400
    inverted = make_qr(auth_client, style={"fg_color": "#FFFFFF", "bg_color": "#000000"})
    assert inverted.status_code == 400
    ok = make_qr(auth_client, style={"fg_color": "#0B1F3A", "bg_color": "#F4FBFB"})
    assert ok.status_code == 201


def test_oversized_payload_rejected(auth_client):
    long_url = "https://example.com/" + "a" * 1500
    r = make_qr(auth_client, code_mode="static", data={"url": long_url},
                style={"error_correction": "H"})
    assert r.status_code == 400


def test_active_dynamic_limit_is_enforced_by_backend(auth_client):
    AppConfiguration.objects.create(key="default_entitlements", value={"qr.dynamic.active_limit": 2})
    a = make_qr(auth_client)
    make_qr(auth_client)
    blocked = make_qr(auth_client)
    assert blocked.status_code == 403 and blocked.data["error"]["code"] == "limit_reached"
    # static codes are not counted; pausing frees a slot; reactivating respects the limit
    assert make_qr(auth_client, code_mode="static").status_code == 201
    auth_client.post(f"/api/v1/qr/{a.data['id']}/pause/")
    c = make_qr(auth_client)
    assert c.status_code == 201
    assert auth_client.post(f"/api/v1/qr/{a.data['id']}/activate/").status_code == 403


def test_feature_flags_gate_creation_and_exports(auth_client):
    AppConfiguration.objects.create(key="default_entitlements", value={
        "qr.dynamic.create": False, "qr.svg_export": False, "qr.pdf_export": False})
    assert make_qr(auth_client).status_code == 403
    qr = make_qr(auth_client, code_mode="static").data["id"]
    assert auth_client.get(f"/api/v1/qr/{qr}/image/png/").status_code == 200
    assert auth_client.get(f"/api/v1/qr/{qr}/image/svg/").status_code == 403
    assert auth_client.get(f"/api/v1/qr/{qr}/image/pdf/").status_code == 403


def test_requires_authentication(api):
    assert api.post("/api/v1/qr/", {}, format="json").status_code == 401
    assert api.get("/api/v1/qr/").status_code == 401
