import io

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from apps.core.models import AppConfiguration
from apps.qr_codes.models import QRCode
from apps.qr_codes.rendering import render_qr
from apps.security_engine import service as sec
from apps.security_engine.models import SecurityCheck
from tests.conftest import enable_provider, make_qr

pytestmark = pytest.mark.django_db
ANALYZE = "/api/v1/scanner/analyze/"
BAD = "ss-malware-test.example.com"
OK = "ss-harmless-test.example.com"


def scan(api, content, **extra):
    return api.post(ANALYZE, {"content": content, **extra}, format="json")


@pytest.fixture
def world(senv):
    senv.publish(BAD)
    senv.publish(OK, "93.184.216.35")
    enable_provider("test_fixture")
    return senv


# ---- the scanner stays fast and offline unless asked ---------------------------------------------------------------------
def test_default_scan_makes_no_network_requests_and_says_no_assessment(api, world):
    a = scan(api, f"https://{BAD}/x").data
    assert a["security"]["status"] == "assessment_not_available" and a["actions"]["can_open"] is True
    assert world.world.net.connections == [] and world.world.dns.address_calls == []


# ---- assessment on demand ----------------------------------------------------------------------------------------------------------
def test_assess_blocks_a_known_malicious_destination(api, world):
    a = scan(api, f"https://{BAD}/x?u=1", assess=True).data
    assert a["security"]["status"] == "known_malicious" and a["security"]["label"] == "Known malicious"
    assert a["security"]["risk_score"] == 100 and a["security"]["check_id"]
    assert a["actions"]["blocked"] and not a["actions"]["can_open"] and a["actions"]["open_target"] is None
    assert "will not forward" in a["actions"]["block_reason"] and a["actions"]["requires_user_confirmation"]


def test_a_cached_malicious_finding_keeps_blocking_even_without_assess(api, world):
    scan(api, f"https://{BAD}/x", assess=True)
    world.world.net.connections.clear()
    a = scan(api, f"https://{BAD}/x?v=2").data               # same destination (query ignored), no assess flag
    assert a["security"]["status"] == "known_malicious" and a["actions"]["blocked"]
    # the cached finding is per destination URL: a different path is not assumed bad until it is assessed
    other = scan(api, f"https://{BAD}/other-page").data
    assert other["security"]["status"] == "assessment_not_available" and not other["actions"]["blocked"]
    assert world.world.net.connections == []                  # served from the cached finding, no new network use


def test_assess_on_a_healthy_destination_never_says_safe(api, world):
    a = scan(api, f"https://{OK}/", assess=True).data
    assert a["security"]["status"] == "no_known_threat_detected" and a["actions"]["can_open"] is True
    assert a["actions"]["open_target"] == f"https://{OK}/" and a["actions"]["requires_user_confirmation"] is True
    assert "safe" not in str(a["security"]).lower()


def test_assess_is_ignored_for_non_web_content(api, world):
    for content in ("tel:+2348012345678", "hello", "WIFI:S:x;T:nopass;;"):
        assert scan(api, content, assess=True).data["security"]["status"] == "assessment_not_available"


def test_a_failed_assessment_is_reported_without_blocking_or_pretending(api, world, monkeypatch):
    monkeypatch.setattr(sec, "analyze", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    a = scan(api, f"https://{OK}/", assess=True).data
    assert a["security"]["status"] == "assessment_unavailable" and a["actions"]["requires_user_confirmation"]
    assert a["actions"]["blocked"] is False


def test_assess_on_a_dangerous_scheme_is_not_applicable_but_still_blocked(api, world):
    a = scan(api, "javascript:alert(1)", assess=True).data
    assert a["kind"] == "blocked_scheme" and a["actions"]["blocked"]


def test_image_decode_can_assess(api, world):
    png = render_qr(f"https://{BAD}/pay", {}, "png")
    r = api.post("/api/v1/scanner/decode/", {"image": SimpleUploadedFile("q.png", png, content_type="image/png"),
                                             "assess": "true"}, format="multipart")
    a = r.data["results"][0]["analysis"]
    assert a["security"]["status"] == "known_malicious" and a["actions"]["blocked"]


# ---- ScanSentry-managed QR codes: the redirect policy -------------------------------------------------------------------------------
def dynamic(auth_client, host):
    return make_qr(auth_client, data={"url": f"https://{host}/landing"}).data


def verify(api, qr, **q):
    return api.get(f"/api/v1/scanner/verify/{qr['public_token']}/", q).data


def test_verification_blocks_a_malicious_destination_and_never_reveals_it(api, auth_client, world):
    qr = dynamic(auth_client, BAD)
    assert verify(api, qr)["state"] == "active"                       # nothing is known yet (no assessment run)
    v = verify(api, qr, assess="1")
    assert v["state"] == "blocked" and v["destination"] is None and "will not forward" in v["message"]
    assert v["security"]["status"] == "known_malicious" and BAD not in str(v)
    again = verify(api, qr)                                            # later scans stay blocked via the cached finding
    assert again["state"] == "blocked" and again["destination"] is None


def test_blocked_scan_does_not_count_as_a_delivered_scan(api, auth_client, world):
    qr = dynamic(auth_client, BAD)
    verify(api, qr, assess="1")
    assert QRCode.objects.get(pk=qr["id"]).last_scanned_at is None


def test_scanning_a_managed_code_with_a_malicious_destination_through_the_scanner(api, auth_client, world):
    qr = dynamic(auth_client, BAD)
    a = scan(api, qr["encoded_payload"], assess=True).data
    assert a["scansentry"]["state"] == "blocked" and a["security"]["status"] == "known_malicious"
    assert a["actions"]["blocked"] and a["actions"]["open_target"] is None and BAD not in str(a["actions"])


def test_healthy_managed_destination_passes_with_security_summary(api, auth_client, world):
    qr = dynamic(auth_client, OK)
    v = verify(api, qr, assess="true")
    assert v["state"] == "active" and v["destination"] == f"https://{OK}/landing"
    assert v["security"]["status"] == "no_known_threat_detected" and v["requires_user_confirmation"] is True


def test_destination_changes_are_covered_because_the_check_is_per_destination(api, auth_client, world):
    qr = dynamic(auth_client, OK)
    assert verify(api, qr, assess="1")["state"] == "active"
    auth_client.patch(f"/api/v1/qr/{qr['id']}/", {"current_destination": f"https://{BAD}/new"}, format="json")
    assert verify(api, qr, assess="1")["state"] == "blocked"


def test_auto_disable_policy_disables_the_code_and_the_owner_cannot_undo_it(api, auth_client, world):
    AppConfiguration.objects.create(key="security.auto_disable_malicious", value=True)
    qr = dynamic(auth_client, BAD)
    verify(api, qr, assess="1")
    row = QRCode.objects.get(pk=qr["id"])
    assert row.status == "disabled" and row.disabled_by_staff and "malicious" in row.status_reason
    assert auth_client.post(f"/api/v1/qr/{qr['id']}/activate/").status_code == 403
    assert verify(api, qr)["state"] == "disabled"


def test_without_auto_disable_the_code_stays_active_for_owner_review(api, auth_client, world):
    qr = dynamic(auth_client, BAD)
    verify(api, qr, assess="1")
    assert QRCode.objects.get(pk=qr["id"]).status == "active"


def test_malicious_findings_are_kept_longer_than_ordinary_ones(api, world):
    scan(api, f"https://{BAD}/", assess=True)
    scan(api, f"https://{OK}/", assess=True)
    bad = SecurityCheck.objects.get(normalised_domain=BAD)
    ok = SecurityCheck.objects.get(normalised_domain=OK)
    assert (bad.cache_expires_at - bad.checked_at).total_seconds() >= 24 * 3600 - 5
    assert (ok.cache_expires_at - ok.checked_at).total_seconds() <= 1800 + 5


# ---- scheduled re-checks ---------------------------------------------------------------------------------------------------------------------
def test_recheck_command_assesses_each_distinct_active_destination_and_applies_policy(auth_client, other_client, world, capsys):
    AppConfiguration.objects.create(key="security.auto_disable_malicious", value=True)
    bad1, bad2 = dynamic(auth_client, BAD), dynamic(other_client, BAD)            # same bad destination, two owners
    ok1, ok2 = dynamic(auth_client, OK), dynamic(other_client, OK)
    paused = dynamic(auth_client, "paused-site.com")
    auth_client.post(f"/api/v1/qr/{paused['id']}/pause/")
    static = make_qr(auth_client, code_mode="static", data={"url": f"https://{BAD}/static"}).data
    call_command("recheck_destinations")
    out = capsys.readouterr().out
    assert "Checked 2 destination(s); 1 known malicious." in out and f"MALICIOUS https://{BAD}/landing" in out
    status = lambda q: QRCode.objects.get(pk=q["id"]).status
    assert status(bad1) == status(bad2) == "disabled" and status(ok1) == status(ok2) == "active"
    assert status(paused) == "paused" and status(static) == "active"             # skipped entirely
    assert SecurityCheck.objects.filter(source_type="recheck").count() == 2


def test_recheck_survives_a_failing_destination_and_respects_the_limit(auth_client, world, monkeypatch, capsys):
    dynamic(auth_client, BAD)
    dynamic(auth_client, OK)
    real = sec.analyze

    def flaky(content, **kw):
        if BAD in content:
            raise RuntimeError("boom")
        return real(content, **kw)
    monkeypatch.setattr(sec, "analyze", flaky)
    call_command("recheck_destinations")
    cap = capsys.readouterr()
    assert "FAILED" in cap.err and "Checked 1 destination(s); 0 known malicious." in cap.out
    call_command("recheck_destinations", "--limit", "0")
    assert "Checked 0 destination(s)" in capsys.readouterr().out
