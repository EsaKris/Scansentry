import io

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.admin.sites import site
from PIL import Image
from rest_framework.throttling import ScopedRateThrottle

from apps.abuse_reports import services
from apps.abuse_reports.models import AbuseReport
from apps.audit.models import AuditLog
from apps.qr_codes.models import QRCode
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db
URL = "/api/v1/scanner/report/"
DESC = "This sticker was pasted over the official payment code."


def report(api, **body):
    body.setdefault("category", "malicious_sticker")
    body.setdefault("description", DESC)
    return api.post(URL, body, format="json")


def test_anonymous_url_report(api):
    r = report(api, url="https://evil.example/pay")
    assert r.status_code == 201
    rep = AbuseReport.objects.get()
    assert rep.submitted_url == "https://evil.example/pay" and rep.reporter is None
    assert rep.review_status == "new" and rep.qr_code is None
    assert len(rep.reporter_hash) == 64 and "127.0.0.1" not in rep.reporter_hash  # raw IP not stored


def test_report_by_qr_token_links_the_code(auth_client, api):
    qr = make_qr(auth_client).data
    assert report(api, qr_token=qr["public_token"], category="unexpected_destination").status_code == 201
    assert AbuseReport.objects.get().qr_code_id is not None


def test_report_validation(api):
    assert report(api).status_code == 400                                        # no target
    assert report(api, url="javascript:alert(1)").status_code == 400
    assert report(api, qr_token="A" * 24).status_code == 400                     # unknown token
    assert report(api, url="https://x.example", category="nope").status_code == 400
    assert report(api, url="https://x.example", description="short").status_code == 400
    assert AbuseReport.objects.count() == 0


def test_same_reporter_duplicate_is_stored_once_with_identical_response(api):
    first = report(api, url="https://evil.example/pay")
    again = report(api, url="https://evil.example/pay")
    assert first.status_code == again.status_code == 201 and first.data == again.data
    assert AbuseReport.objects.count() == 1
    # a different category on the same target is a separate report
    report(api, url="https://evil.example/pay", category="impersonation")
    assert AbuseReport.objects.count() == 2


def test_different_reporters_are_linked_as_duplicates(api):
    from rest_framework.test import APIClient
    report(api, url="https://evil.example/pay")
    other = APIClient()
    other.defaults["REMOTE_ADDR"] = "203.0.113.9"
    report(other, url="https://evil.example/pay")
    first, second = AbuseReport.objects.order_by("created_at")
    assert first.duplicate_of is None and second.duplicate_of_id == first.id
    assert first.duplicates.count() == 1


def test_authenticated_reporter_is_attached(auth_client, user):
    report(auth_client, url="https://evil.example/pay")
    assert AbuseReport.objects.get().reporter_id == user.id


def test_stale_token_does_not_block_anonymous_report(api):
    r = api.post(URL, {"url": "https://evil.example", "category": "other", "description": DESC},
                 format="json", HTTP_AUTHORIZATION="Bearer garbage")
    assert r.status_code == 201


def test_report_is_rate_limited(api, monkeypatch):
    from django.core.cache import cache
    cache.clear()
    monkeypatch.setitem(ScopedRateThrottle.THROTTLE_RATES, "abuse_report", "2/hour")
    codes = [report(api, url=f"https://evil{i}.example/").status_code for i in range(4)]
    assert codes[:2] == [201, 201] and 429 in codes[2:]


def test_evidence_image_is_sanitised_and_bad_files_rejected(api, settings):
    exif = Image.Exif()
    exif[0x010E] = "gps secrets"
    buf = io.BytesIO()
    Image.new("RGB", (200, 200), "red").save(buf, format="JPEG", exif=exif)
    up = SimpleUploadedFile("proof.jpg", buf.getvalue(), content_type="image/jpeg")
    r = api.post(URL, {"url": "https://evil.example", "category": "other", "description": DESC,
                       "evidence": up}, format="multipart")
    assert r.status_code == 201
    rep = AbuseReport.objects.get()
    stored = Image.open(rep.evidence_file.path)
    assert stored.format == "PNG" and not stored.getexif()

    bad = SimpleUploadedFile("proof.png", b"<script>alert(1)</script>", content_type="image/png")
    r = api.post(URL, {"url": "https://evil2.example", "category": "other", "description": DESC,
                       "evidence": bad}, format="multipart")
    assert r.status_code == 400 and AbuseReport.objects.count() == 1


def test_reports_alone_never_change_a_code_or_declare_anything_malicious(auth_client, api):
    from rest_framework.test import APIClient
    qr = make_qr(auth_client).data
    for i in range(6):
        c = APIClient()
        c.defaults["REMOTE_ADDR"] = f"198.51.100.{i + 1}"
        report(c, qr_token=qr["public_token"], category="suspicious_qr")
    assert AbuseReport.objects.count() == 6
    assert QRCode.objects.get(pk=qr["id"]).status == "active"
    v = api.get(f"/api/v1/scanner/verify/{qr['public_token']}/").data
    assert v["state"] == "active" and v["destination"]
    assert "malicious" not in str(v).lower()


def test_moderator_review_is_audited_and_staff_can_disable_linked_code(auth_client, user, db):
    from django.contrib.auth import get_user_model
    from apps.qr_codes import services as qr_services
    qr = make_qr(auth_client).data
    from rest_framework.test import APIClient
    anon = APIClient()
    report(anon, qr_token=qr["public_token"], category="impersonation")
    rep = AbuseReport.objects.get()
    staff = get_user_model().objects.create_user("mod@example.com", "Str0ng-Passphrase-42", is_staff=True)
    services.review_report(rep, reviewer=staff, status="actioned", notes="confirmed", resolution="disabled")
    rep.refresh_from_db()
    assert rep.review_status == "actioned" and rep.reviewer_id == staff.id and rep.reviewed_at
    assert AuditLog.objects.filter(action="abuse_report.reviewed").exists()
    qr_services.disable_qr(rep.qr_code, user=staff, reason="After review", by_staff=True)
    assert auth_client.post(f"/api/v1/qr/{qr['id']}/activate/").status_code == 403


def test_admin_pages_load_for_superuser(client, db):
    from django.contrib.auth import get_user_model
    su = get_user_model().objects.create_superuser("root@example.com", "Str0ng-Passphrase-42")
    client.force_login(su)
    for path in ["/admin/abuse_reports/abusereport/", "/admin/qr_codes/qrcode/",
                 "/admin/qr_codes/campaign/", "/admin/audit/auditlog/", "/admin/core/appconfiguration/",
                 "/admin/accounts/user/", "/admin/organizations/organization/"]:
        assert client.get(path).status_code == 200, path
