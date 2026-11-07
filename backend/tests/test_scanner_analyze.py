import socket

import pytest

from tests.conftest import make_qr

pytestmark = pytest.mark.django_db
URL = "/api/v1/scanner/analyze/"


def analyze(api, content):
    r = api.post(URL, {"content": content}, format="json")
    assert r.status_code == 200, r.data
    return r.data


# ---- dangerous / unsupported schemes (Module D) ------------------------------------------
@pytest.mark.parametrize("content", [
    "javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html;base64,PHNjcmlwdD4=",
    "file:///etc/passwd", "vbscript:msgbox(1)", "blob:https://x/1", "intent://scan#Intent;end",
    "about:blank", "ms-msdt:/id PCWDiagnostic",
])
def test_dangerous_schemes_are_blocked(api, content):
    a = analyze(api, content)
    assert a["kind"] == "blocked_scheme"
    assert a["actions"]["blocked"] and not a["actions"]["can_open"] and a["actions"]["action"] is None
    assert a["actions"]["block_reason"]


@pytest.mark.parametrize("content", ["myapp://open?x=1", "ftp://example.com/x", "market://details?id=a", "C:\\Windows\\x.exe"])
def test_unsupported_schemes_are_blocked(api, content):
    a = analyze(api, content)
    assert a["kind"] == "unsupported_scheme" and a["actions"]["blocked"]


def test_every_result_requires_user_confirmation_and_notes_no_assessment(api):
    for content in ["https://example.com", "tel:+2348012345678", "hello", "WIFI:S:x;T:nopass;;"]:
        a = analyze(api, content)
        assert a["actions"]["requires_user_confirmation"] is True
        assert a["security"]["status"] == "assessment_not_available"


# ---- URLs --------------------------------------------------------------------------------------
def test_plain_https_url(api):
    a = analyze(api, "https://Example.COM/path?q=1")
    assert a["kind"] == "url" and not a["actions"]["blocked"]
    assert a["url"]["host"] == "example.com" and a["url"]["uses_https"] is True
    assert a["actions"]["action"] == "open_url"
    assert a["actions"]["open_target"] == "https://example.com/path?q=1"
    assert a["observations"] == []   # no verdict, no noise for an ordinary URL


def test_http_is_a_fact_not_a_threat(api):
    a = analyze(api, "http://example.com/")
    assert a["url"]["uses_https"] is False and not a["actions"]["blocked"]
    assert "safe" not in str(a).lower()


def test_bare_domain_is_treated_as_https_with_observation(api):
    a = analyze(api, "www.example.com/menu")
    assert a["kind"] == "url" and a["url"]["normalized"] == "https://www.example.com/menu"
    assert any(o["code"] == "assumed_scheme" for o in a["observations"])


def test_plain_words_and_filenames_are_text(api):
    assert analyze(api, "Table 12")["kind"] == "text"
    assert analyze(api, "version 1.2 final")["kind"] == "text"


def test_idn_homograph_is_surfaced(api):
    a = analyze(api, "https://аpple.com/login")  # first letter is Cyrillic
    codes = {o["code"] for o in a["observations"]}
    assert {"internationalised_domain", "mixed_scripts"} <= codes
    assert a["url"]["host"].startswith("xn--") and a["url"]["is_idn"] and a["url"]["mixed_scripts"]
    assert a["url"]["display_host"] == "аpple.com"


def test_embedded_credentials_blocked(api):
    a = analyze(api, "https://paypal.com@evil.example/login")
    assert a["actions"]["blocked"] and "credentials" in a["actions"]["block_reason"].lower()
    assert any(o["code"] == "embedded_credentials" for o in a["observations"])
    assert a["actions"]["open_target"] is None


def test_percent_encoded_host_blocked(api):
    a = analyze(api, "https://%65xample.com/")
    assert a["actions"]["blocked"]


@pytest.mark.parametrize("url", ["https://192.168.0.1/admin", "http://[::1]/", "http://2130706433/", "http://0x7f000001/"])
def test_ip_hosts_are_flagged(api, url):
    a = analyze(api, url)
    assert any(o["code"] == "ip_address_host" for o in a["observations"]), url
    assert a["url"]["is_ip_address"]


def test_redirect_parameter_flagged(api):
    a = analyze(api, "https://example.com/go?next=https%3A%2F%2Fevil.example%2Fx")
    assert any(o["code"] == "redirect_parameter" for o in a["observations"])
    assert not analyze(api, "https://example.com/go?next=/account")["observations"]


def test_malformed_urls_blocked(api):
    for bad in ["https://", "https://exa mple.com/", "https://example.com:99999/"]:
        a = analyze(api, bad)
        assert a["actions"]["blocked"] or a["kind"] == "text", bad


# ---- other payload types --------------------------------------------------------------------------
def test_phone_and_email_previews(api):
    p = analyze(api, "tel:+234 801-234-5678")
    assert p["kind"] == "phone" and p["preview"]["number"] == "+2348012345678"
    assert p["actions"]["action"] == "call"
    assert analyze(api, "tel:not-a-number")["kind"] == "text"
    m = analyze(api, "mailto:a@b.co?subject=Hi&cc=x@y.z&body=Yo")
    assert m["kind"] == "email" and m["preview"]["to"] == "a@b.co" and m["preview"]["subject"] == "Hi"
    assert m["preview"]["ignored_parameters"] == ["cc"]
    assert any(o["code"] == "extra_mail_parameters" for o in m["observations"])


def test_wifi_preview_does_not_echo_password(api):
    a = analyze(api, r"WIFI:T:WPA;S:My\;Net;P:s3cr3t\:pass;H:true;;")
    assert a["kind"] == "wifi"
    assert a["preview"] == {"ssid": "My;Net", "security": "WPA", "hidden": True, "password_present": True}
    assert "s3cr3t" not in str(a["preview"])
    open_net = analyze(api, "WIFI:T:nopass;S:Cafe;;")
    assert any(o["code"] == "open_network" for o in open_net["observations"])
    assert analyze(api, "WIFI:garbage")["kind"] == "text"


def test_vcard_preview(api):
    card = "BEGIN:VCARD\nVERSION:3.0\nN:Lovelace;Ada;;;\nFN:Ada Lovelace\nORG:Analytical\nTEL:+441234567890\nEMAIL:ada@example.com\nURL:https://example.com\nEND:VCARD"
    a = analyze(api, card)
    assert a["kind"] == "vcard" and a["preview"]["name"] == "Ada Lovelace"
    assert a["preview"]["phones"] == ["+441234567890"] and a["preview"]["urls"] == ["https://example.com"]
    assert a["actions"]["action"] == "save_contact"


def test_text_preview_strips_control_characters(api):
    a = analyze(api, "hello\x00\x07 world")
    assert a["kind"] == "text" and a["preview"]["text"] == "hello world"
    assert a["actions"]["can_open"] is False


def test_empty_and_oversized_content_rejected(api):
    assert api.post(URL, {"content": ""}, format="json").status_code == 400
    assert api.post(URL, {"content": "x" * 5000}, format="json").status_code == 400
    assert api.post(URL, {}, format="json").status_code == 400


def test_analysis_never_touches_the_network(api, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for content in ["https://example.com/x", "https://аpple.com", "http://192.168.1.1/"]:
        analyze(api, content)


def test_public_scanner_needs_no_account_and_is_not_cached(api):
    r = api.post(URL, {"content": "https://example.com"}, format="json")
    assert r.status_code == 200 and r["Cache-Control"] == "no-store"
    # a stale/garbage token must not break an anonymous endpoint
    r = api.post(URL, {"content": "hi"}, format="json", HTTP_AUTHORIZATION="Bearer garbage")
    assert r.status_code == 200


# ---- ScanSentry-managed links (Scenarios 2-3) ----------------------------------------------------------
def test_managed_link_resolves_to_current_destination(auth_client, api):
    qr = make_qr(auth_client).data
    a = analyze(api, qr["encoded_payload"])
    assert a["scansentry"]["managed"] and a["scansentry"]["state"] == "active"
    assert a["scansentry"]["qr"]["name"] == "Menu"
    assert a["actions"]["open_target"] == "https://example.com/menu"
    assert a["actions"]["can_open"] and a["actions"]["requires_user_confirmation"]
    assert a["destination_analysis"]["url"]["host"] == "example.com"

    auth_client.patch(f"/api/v1/qr/{qr['id']}/", {"current_destination": "https://example.org/new"}, format="json")
    assert analyze(api, qr["encoded_payload"])["actions"]["open_target"] == "https://example.org/new"


def test_managed_link_destination_observations_are_included(auth_client, api):
    qr = make_qr(auth_client, data={"url": "https://аpple.com/x"}).data
    a = analyze(api, qr["encoded_payload"])
    assert any(o["code"] == "mixed_scripts" for o in a["observations"])


@pytest.mark.parametrize("action,state", [("pause", "paused"), ("disable", "disabled")])
def test_inactive_managed_link_cannot_be_opened(auth_client, api, action, state):
    qr = make_qr(auth_client).data
    auth_client.post(f"/api/v1/qr/{qr['id']}/{action}/")
    a = analyze(api, qr["encoded_payload"])
    assert a["scansentry"]["state"] == state and a["scansentry"]["destination"] is None
    assert a["actions"]["can_open"] is False and a["actions"]["open_target"] is None
    assert "example.com" not in str(a["scansentry"]) and "example.com/menu" not in str(a["actions"])


def test_unregistered_managed_link_is_blocked_and_flagged(api, settings):
    a = analyze(api, f"{settings.REDIRECT_BASE_URL}/r/" + "A" * 24)
    assert a["scansentry"] == {"managed": True, "state": "not_found"}
    assert a["actions"]["blocked"]
    assert any(o["code"] == "unregistered_scansentry_link" for o in a["observations"])


def test_lookalike_host_with_same_path_is_not_treated_as_managed(auth_client, api):
    qr = make_qr(auth_client).data
    fake = qr["encoded_payload"].replace("localhost", "scansentry-login.example")
    a = analyze(api, fake)
    assert a["scansentry"] is None and a["url"]["host"] == "scansentry-login.example"
