import csv
import io
from datetime import datetime, timedelta, timezone

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone as djtz
from rest_framework.test import APIClient

from apps.analytics import ua
from apps.analytics.models import ScanEvent
from apps.analytics.service import geo, record_scan, visitor_hash
from apps.core.models import AppConfiguration
from apps.qr_codes.models import Campaign, QRCode
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"


# ---- user-agent classification ---------------------------------------------------------------------------------
@pytest.mark.parametrize("agent,device,browser,bot", [
    (IPHONE, "mobile", "safari", False), (ANDROID, "mobile", "chrome", False),
    ("Mozilla/5.0 (Linux; Android 13; SM-T500) AppleWebKit/537.36 Chrome/119.0 Safari/537.36", "tablet", "chrome", False),
    ("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", "tablet", "safari", False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", "desktop", "chrome", False),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0", "desktop", "edge", False),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "desktop", "firefox", False),
    ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 SamsungBrowser/23.0 Chrome/115.0 Mobile Safari/537.36", "mobile", "samsung", False),
    ("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 OPR/105.0", "desktop", "opera", False),
    ("", "unknown", "other", False), ("SomeCustomClient/1.0", "desktop", "other", False),
    ("WhatsApp/2.23.20.0 A", "unknown", "other", True),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "unknown", "other", True),
    ("Slackbot-LinkExpanding 1.0", "unknown", "other", True), ("TelegramBot (like TwitterBot)", "unknown", "other", True),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "unknown", "other", True),
    ("curl/8.4.0", "unknown", "other", True), ("python-requests/2.31", "unknown", "other", True),
    ("Mozilla/5.0 HeadlessChrome/120", "unknown", "other", True),
])
def test_user_agent_classification(agent, device, browser, bot):
    r = ua.classify(agent)
    assert (r["device"], r["browser"], r["is_bot"]) == (device, browser, bot)


# ---- recording (privacy) -------------------------------------------------------------------------------------------------
def verify(api, qr, ip="203.0.113.7", agent=IPHONE, **extra):
    return api.get(f"/api/v1/scanner/verify/{qr['public_token']}/", extra, HTTP_USER_AGENT=agent, REMOTE_ADDR=ip)


def test_a_scan_is_recorded_without_ip_user_agent_or_url(api, auth_client):
    qr = make_qr(auth_client, data={"url": "https://example.com/menu?table=SECRET5"}).data
    assert verify(api, qr).status_code == 200
    ev = ScanEvent.objects.get()
    assert ev.qr_code_id and ev.outcome == "delivered" and ev.device_category == "mobile" and ev.browser_category == "safari"
    assert ev.scanner_type == "link" and not ev.is_bot and len(ev.visitor_hash) == 16
    stored = " ".join(str(getattr(ev, f.name)) for f in ScanEvent._meta.fields)
    for leak in ("203.0.113.7", "iPhone", "Mozilla", "SECRET5", "example.com"):
        assert leak not in stored
    assert {f.name for f in ScanEvent._meta.fields} >= {"approximate_country", "approximate_region", "scanner_type",
                                                          "security_status_at_scan", "device_category", "browser_category"}
    assert "ip" not in " ".join(f.name for f in ScanEvent._meta.fields).replace("ip_", "x")


def test_visitor_hash_is_keyed_stable_per_day_and_rotates(rf, settings):
    now = datetime(2026, 11, 8, 12, tzinfo=timezone.utc)
    mk = lambda ip, agent: rf.get("/", HTTP_USER_AGENT=agent, REMOTE_ADDR=ip)
    a = visitor_hash(mk("1.2.3.4", "UA"), now)
    assert a == visitor_hash(mk("1.2.3.4", "UA"), now) and len(a) == 16
    assert a != visitor_hash(mk("1.2.3.5", "UA"), now) and a != visitor_hash(mk("1.2.3.4", "UA2"), now)
    assert a != visitor_hash(mk("1.2.3.4", "UA"), now + timedelta(days=1))     # cannot be linked across days
    settings.SECRET_KEY = "another-secret-key-for-testing-hmac-0123456789"
    assert a != visitor_hash(mk("1.2.3.4", "UA"), now)                         # keyed: not a plain hash of the IP


def test_same_device_scanning_the_same_code_twice_quickly_counts_once(api, auth_client, settings):
    qr = make_qr(auth_client).data
    verify(api, qr)
    verify(api, qr)
    assert ScanEvent.objects.count() == 1
    verify(api, qr, ip="203.0.113.99")                                          # a different device
    assert ScanEvent.objects.count() == 2
    settings.ANALYTICS_DEDUPE_SECONDS = 0
    verify(api, qr)
    assert ScanEvent.objects.count() == 3


def test_link_preview_bots_are_stored_flagged_and_excluded_from_analytics(api, auth_client):
    qr = make_qr(auth_client).data
    verify(api, qr, agent="WhatsApp/2.23.20.0 A", ip="198.51.100.1")
    verify(api, qr, ip="198.51.100.2")
    assert ScanEvent.objects.filter(is_bot=True).count() == 1
    assert auth_client.get("/api/v1/analytics/overview/").data["totals"]["scans"] == 1


@pytest.mark.parametrize("via,expected", [("camera", "camera"), ("upload", "upload"), ("link", "link"), ("weird", "link"), ("", "link")])
def test_scanner_type_hint_is_validated(api, auth_client, via, expected):
    qr = make_qr(auth_client).data
    verify(api, qr, **({"via": via} if via else {}))
    assert ScanEvent.objects.get().scanner_type == expected


def test_outcomes_are_recorded_for_every_state(api, auth_client):
    paused, disabled, expired = (make_qr(auth_client).data for _ in range(3))
    auth_client.post(f"/api/v1/qr/{paused['id']}/pause/")
    auth_client.post(f"/api/v1/qr/{disabled['id']}/disable/")
    QRCode.objects.filter(pk=expired["id"]).update(expires_at=djtz.now() - timedelta(minutes=1))
    for i, q in enumerate((paused, disabled, expired)):
        verify(api, q, ip=f"198.51.100.{i + 10}")
    assert sorted(ScanEvent.objects.values_list("outcome", flat=True)) == ["disabled", "expired", "paused"]


def test_unknown_tokens_are_not_recorded(api):
    assert api.get("/api/v1/scanner/verify/" + "A" * 24 + "/").status_code == 404
    assert ScanEvent.objects.count() == 0


def test_security_status_at_scan_and_blocked_outcome(api, auth_client, senv):
    from tests.conftest import enable_provider
    senv.publish("ss-malware-test.example.com")
    enable_provider("test_fixture")
    qr = make_qr(auth_client, data={"url": "https://ss-malware-test.example.com/x"}).data
    verify(api, qr, assess="1")
    ev = ScanEvent.objects.get()
    assert ev.outcome == "blocked" and ev.security_status_at_scan == "known_malicious"


def test_scanner_analyze_and_decode_record_events(api, auth_client):
    from django.core.files.uploadedfile import SimpleUploadedFile
    from apps.qr_codes.rendering import render_qr
    qr = make_qr(auth_client).data
    api.post("/api/v1/scanner/analyze/", {"content": qr["encoded_payload"]}, format="json", REMOTE_ADDR="198.51.100.20")
    api.post("/api/v1/scanner/analyze/", {"content": "https://other.example.org/", "scanner_type": "upload"}, format="json", REMOTE_ADDR="198.51.100.21")
    png = render_qr("tel:+2348012345678", {}, "png")
    api.post("/api/v1/scanner/decode/", {"image": SimpleUploadedFile("q.png", png, content_type="image/png")}, format="multipart", REMOTE_ADDR="198.51.100.22")
    managed = ScanEvent.objects.get(qr_code__isnull=False)
    assert managed.outcome == "delivered" and managed.scanner_type == "camera"
    external = ScanEvent.objects.filter(qr_code__isnull=True).order_by("scanned_at")
    assert [(e.outcome, e.scanner_type, e.content_kind) for e in external] == [("analyzed", "upload", "url"), ("analyzed", "upload", "phone")]
    assert api.post("/api/v1/scanner/analyze/", {"content": "x", "scanner_type": "hover"}, format="json").status_code == 400


def test_analytics_failures_never_break_scanning(api, auth_client, monkeypatch):
    qr = make_qr(auth_client).data
    monkeypatch.setattr(ScanEvent.objects, "create", lambda **k: (_ for _ in ()).throw(RuntimeError("db down")))
    r = verify(api, qr)
    assert r.status_code == 200 and r.data["state"] == "active"


def test_events_are_deleted_with_their_qr_code(api, auth_client):
    qr = make_qr(auth_client).data
    verify(api, qr)
    auth_client.delete(f"/api/v1/qr/{qr['id']}/")
    assert ScanEvent.objects.count() == 0


# ---- geography: only what the operator's CDN supplies -----------------------------------------------------------------------------
def test_country_is_off_by_default_and_never_taken_from_unconfigured_headers(api, auth_client):
    qr = make_qr(auth_client).data
    api.get(f"/api/v1/scanner/verify/{qr['public_token']}/", HTTP_CF_IPCOUNTRY="NG", HTTP_USER_AGENT=IPHONE)
    assert ScanEvent.objects.get().approximate_country == ""       # header ignored until the operator configures it


def test_country_and_region_are_recorded_only_from_the_configured_headers_and_sanitised(rf, settings):
    settings.GEO_COUNTRY_HEADER, settings.GEO_REGION_HEADER = "CF-IPCountry", "X-Region"
    mk = lambda c, r="": rf.get("/", HTTP_CF_IPCOUNTRY=c, HTTP_X_REGION=r)
    assert geo(mk("ng", "Benue")) == ("NG", "Benue")
    for bad in ("XX", "T1", "Nigeria", "N", "N1", "<s>", ""):
        assert geo(mk(bad))[0] == "", bad
    assert geo(mk("NG", "Lagos\r\nX-Evil: 1"))[1] == "LagosX-Evil: 1"          # control characters removed
    assert len(geo(mk("NG", "x" * 200))[1]) == 64


# ---- analytics API --------------------------------------------------------------------------------------------------------------------
NOW = djtz.now()


def mk(qr_id, days_ago=0, hours=12, **kw):
    when = (NOW - timedelta(days=days_ago)).replace(hour=hours, minute=0, second=0, microsecond=0)
    base = dict(qr_code_id=qr_id, scanned_at=when, outcome="delivered", device_category="mobile", browser_category="chrome",
                scanner_type="link", visitor_hash=f"h{days_ago}{hours}{len(kw)}{id(kw) % 1000}", approximate_country="NG")
    base.update(kw)
    return ScanEvent.objects.create(**base)


def get(client, path, **params):
    return client.get(path, params)


def test_overview_totals_trend_and_isolation(auth_client, other_client):
    a = make_qr(auth_client, name="Menu").data["id"]
    b = make_qr(auth_client, name="Flyer", code_mode="static", qr_type="text", data={"text": "x"}).data["id"]
    theirs = make_qr(other_client, name="Theirs").data["id"]
    for i in range(6):
        mk(a, days_ago=1, visitor_hash=f"u{i % 3}")                              # 6 scans, 3 unique, this period
    mk(b, days_ago=2, device_category="desktop", visitor_hash="d1")
    for i in range(2):
        mk(a, days_ago=40, visitor_hash=f"old{i}")                               # previous period (days=30 -> 30..60 days ago)
    mk(theirs, days_ago=1)                                                       # someone else's: never visible
    mk(a, days_ago=1, is_bot=True, visitor_hash="bot")
    r = get(auth_client, "/api/v1/analytics/overview/", days=30)
    assert r.status_code == 200
    t = r.data["totals"]
    assert t["scans"] == 7 and t["unique_estimate"] == 4 and t["previous_period_scans"] == 2 and t["change_percent"] == 250.0
    assert r.data["codes"] == {"total": 2, "active_dynamic": 1, "paused": 0, "disabled": 0}
    assert [c["name"] for c in r.data["top_codes"]] == ["Menu", "Flyer"] and r.data["top_codes"][0]["scans"] == 6
    assert {d["key"]: d["scans"] for d in r.data["devices"]} == {"mobile": 6, "desktop": 1}
    assert other_client.get("/api/v1/analytics/overview/").data["totals"]["scans"] == 1


def test_empty_state_and_no_previous_period(auth_client):
    r = get(auth_client, "/api/v1/analytics/overview/")
    assert r.data["totals"]["scans"] == 0 and r.data["totals"]["change_percent"] is None and r.data["top_codes"] == []


def test_time_series_is_zero_filled_and_counts_uniques(auth_client):
    q = make_qr(auth_client).data["id"]
    mk(q, days_ago=1, visitor_hash="a"); mk(q, days_ago=1, visitor_hash="a"); mk(q, days_ago=1, visitor_hash="b")
    mk(q, days_ago=3, visitor_hash="c")
    r = get(auth_client, "/api/v1/analytics/scans/", days=7)
    series = r.data["series"]
    assert len(series) == 7 and sum(p["scans"] for p in series) == 4
    by_day = {p["period"]: p for p in series}
    d1 = (NOW - timedelta(days=1)).date().isoformat()
    assert by_day[d1]["scans"] == 3 and by_day[d1]["unique_estimate"] == 2
    assert sum(1 for p in series if p["scans"] == 0) == 5
    assert "privacy_note" in r.data and "no IP address" in r.data["privacy_note"]


def test_granularity_week_and_month(auth_client):
    q = make_qr(auth_client).data["id"]
    for d in (1, 10, 40):
        mk(q, days_ago=d)
    w = get(auth_client, "/api/v1/analytics/scans/", days=60, granularity="week")
    m = get(auth_client, "/api/v1/analytics/scans/", days=60, granularity="month")
    assert sum(p["scans"] for p in w.data["series"]) == 3 and sum(p["scans"] for p in m.data["series"]) == 3
    assert all(datetime.fromisoformat(p["period"]).weekday() == 0 for p in w.data["series"])
    assert all(p["period"].endswith("-01") for p in m.data["series"]) and 2 <= len(m.data["series"]) <= 3


def test_time_zone_changes_which_day_an_event_belongs_to(auth_client):
    q = make_qr(auth_client).data["id"]
    day = (NOW - timedelta(days=2)).replace(hour=23, minute=30, second=0, microsecond=0)
    ScanEvent.objects.create(qr_code_id=q, scanned_at=day, outcome="delivered", visitor_hash="z")
    utc = {p["period"] for p in get(auth_client, "/api/v1/analytics/scans/", days=5).data["series"] if p["scans"]}
    lagos = {p["period"] for p in get(auth_client, "/api/v1/analytics/scans/", days=5, tz="Africa/Lagos").data["series"] if p["scans"]}
    assert utc == {day.date().isoformat()} and lagos == {(day + timedelta(days=1)).date().isoformat()}      # Lagos is UTC+1


def test_explicit_date_range(auth_client):
    q = make_qr(auth_client).data["id"]
    mk(q, days_ago=5); mk(q, days_ago=20)
    frm, to = (NOW - timedelta(days=6)).date().isoformat(), (NOW - timedelta(days=4)).date().isoformat()
    r = get(auth_client, "/api/v1/analytics/scans/", **{"from": frm, "to": to})
    assert r.data["totals"]["scans"] == 1 and len(r.data["series"]) == 3


def test_breakdowns_for_advanced_analytics(auth_client):
    q = make_qr(auth_client).data["id"]
    mk(q, browser_category="safari", approximate_country="NG", approximate_region="Benue", security_status_at_scan="suspicious", visitor_hash="1")
    mk(q, browser_category="chrome", approximate_country="GH", device_category="desktop", scanner_type="camera", visitor_hash="2")
    mk(q, browser_category="chrome", approximate_country="", outcome="blocked", security_status_at_scan="known_malicious", visitor_hash="3")
    r = get(auth_client, "/api/v1/analytics/scans/")
    b = r.data["breakdowns"]
    assert {x["key"]: x["scans"] for x in b["browser"]} == {"chrome": 2, "safari": 1}
    assert {x["key"]: x["scans"] for x in b["country"]} == {"NG": 1, "GH": 1, "unknown": 1}
    assert b["region"] == [{"key": "Benue", "scans": 1}] and {x["key"] for x in b["scanner_type"]} == {"link", "camera"}
    assert {x["key"]: x["scans"] for x in b["outcome"]} == {"delivered": 2, "blocked": 1}
    assert r.data["totals"]["security_warnings_shown"] == 2 and r.data["totals"]["disabled_or_inactive_activity"] == 1
    assert r.data["locked"] == []


def test_advanced_sections_and_export_are_enforced_by_the_backend(auth_client):
    q = make_qr(auth_client).data["id"]
    mk(q)
    AppConfiguration.objects.create(key="default_entitlements", value={"qr.analytics.advanced": False})
    r = get(auth_client, "/api/v1/analytics/scans/")
    assert r.status_code == 200 and set(r.data["breakdowns"]) == {"device", "scanner_type", "outcome"}
    assert "country" in r.data["locked"] and "export" in r.data["locked"]
    assert get(auth_client, "/api/v1/analytics/scans/", export="csv").status_code == 403
    assert get(auth_client, "/api/v1/analytics/qr-performance/").data["campaigns"] is None
    AppConfiguration.objects.filter(key="default_entitlements").update(value={"qr.analytics.basic": False})
    assert get(auth_client, "/api/v1/analytics/overview/").status_code == 403


def test_qr_performance_and_campaign_comparison(auth_client):
    c1 = auth_client.post("/api/v1/campaigns/", {"name": "Summer"}, format="json").data["id"]
    a = make_qr(auth_client, name="A", campaign=c1).data["id"]
    b = make_qr(auth_client, name="B", campaign=c1).data["id"]
    c = make_qr(auth_client, name="C").data["id"]
    for i in range(3):
        mk(a, visitor_hash=f"a{i}")
    mk(b, visitor_hash="b0", outcome="paused", security_status_at_scan="suspicious")
    mk(c, visitor_hash="c0"); mk(c, visitor_hash="c1")
    r = get(auth_client, "/api/v1/analytics/qr-performance/")
    codes = {x["name"]: x for x in r.data["codes"]}
    assert [x["name"] for x in r.data["codes"]] == ["A", "C", "B"]
    assert codes["A"]["scans"] == 3 and codes["A"]["unique_estimate"] == 3 and codes["B"]["security_warnings_shown"] == 1
    assert codes["B"]["disabled_or_inactive_activity"] == 1
    camps = {x["campaign"]: x for x in r.data["campaigns"]}
    assert camps["Summer"]["scans"] == 4 and camps["Summer"]["codes"] == 2 and camps["(no campaign)"]["scans"] == 2


def test_single_code_analytics_is_owner_only(auth_client, other_client):
    q = make_qr(auth_client, name="Mine").data["id"]
    mk(q); mk(q, days_ago=1)
    r = get(auth_client, f"/api/v1/qr/{q}/analytics/", days=7)
    assert r.status_code == 200 and r.data["qr"]["name"] == "Mine" and r.data["totals"]["scans"] == 2
    assert other_client.get(f"/api/v1/qr/{q}/analytics/").status_code == 404
    assert other_client.get(f"/api/v1/analytics/scans/?qr={q}").status_code == 404
    assert get(auth_client, "/api/v1/analytics/scans/", qr=q).data["totals"]["scans"] == 2


def test_csv_export_is_formula_injection_safe(auth_client):
    q = make_qr(auth_client, name="=HYPERLINK(\"http://evil\")").data["id"]
    mk(q)
    r = get(auth_client, "/api/v1/analytics/qr-performance/", export="csv")
    assert r.status_code == 200 and r["Content-Type"].startswith("text/csv") and "attachment" in r["Content-Disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode())))
    assert rows[0][0] == "name" and rows[1][0].startswith("'=") and rows[1][4] == "1"
    s = get(auth_client, "/api/v1/analytics/scans/", export="csv")
    assert s.content.decode().splitlines()[0] == "period,scans,unique_estimate"
    one = get(auth_client, f"/api/v1/qr/{q}/analytics/", export="csv")
    assert one.status_code == 200 and "scans" in one.content.decode()


@pytest.mark.parametrize("params", [{"days": 0}, {"days": 1000}, {"tz": "Mars/Base"}, {"granularity": "hour"},
                                     {"from": "2026-12-01", "to": "2026-01-01"}, {"from": "2020-01-01", "to": "2026-01-01"},
                                     {"qr": "not-a-uuid"}, {"export": "xml"}])
def test_bad_parameters_are_rejected(auth_client, params):
    assert get(auth_client, "/api/v1/analytics/scans/", **params).status_code == 400


def test_analytics_require_authentication(api):
    for path in ("overview/", "scans/", "qr-performance/"):
        assert api.get(f"/api/v1/analytics/{path}").status_code == 401
