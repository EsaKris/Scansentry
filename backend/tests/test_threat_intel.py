import json
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.threat_intel import providers as P
from apps.threat_intel import service as T
from apps.threat_intel.models import ThreatIndicator, ThreatProvider
from tests.conftest import enable_provider
from tests.netfakes import http_response

pytestmark = pytest.mark.django_db
WR_IP = "142.250.0.1"


def q(url="https://evil.test-host.com/pay", host="evil.test-host.com", reg="test-host.com"):
    return P.ThreatQuery(url=url, host=host, registrable=reg)


def webrisk(senv, handler, monkeypatch, key="test-key"):
    monkeypatch.setenv("THREAT_INTEL_API_KEY", key) if key else monkeypatch.delenv("THREAT_INTEL_API_KEY", raising=False)
    enable_provider("google_web_risk", retry_attempts=2)
    return senv.world.site("webrisk.googleapis.com", WR_IP, https=handler)


def check(senv, **kw):
    return T.check_url(kw.pop("query", q()), guard=senv.world.guard)


def one(outcome, provider):
    return [r for r in outcome.results if r.provider == provider][0]


# ---- fixture provider (controlled test data) -------------------------------------------------------------------------
@pytest.mark.parametrize("host,status,categories", [
    ("ss-malware-test.example.com", "ok", ["malware"]), ("ss-phish-test.example.com", "ok", ["phishing"]),
    ("ss-suspicious-test.example.com", "ok", ["suspicious"]), ("ss-harmless-test.example.com", "ok", []),
    ("unlisted.example.org", "ok", []),
])
def test_fixture_provider_returns_known_test_verdicts(senv, host, status, categories):
    enable_provider("test_fixture")
    o = T.check_url(P.ThreatQuery(url=f"https://{host}/", host=host, registrable="example.com"), guard=senv.world.guard)
    r = one(o, "test_fixture")
    assert r.status == status and [f.category for f in r.findings] == categories


def test_fixture_indicators_are_reserved_documentation_names():
    data = json.loads(P.FIXTURE_PATH.read_text())
    assert all(i["host"].endswith(".example.com") for i in data["indicators"])


def test_only_the_local_provider_runs_by_default(senv):
    o = check(senv)
    assert [r.provider for r in o.results] == ["local_blocklist"] and o.providers_enabled == 1


def test_disabled_providers_are_never_called(senv, monkeypatch):
    srv = webrisk(senv, lambda r: http_response(200, "{}"), monkeypatch)
    ThreatProvider.objects.filter(key="google_web_risk").update(enabled=False)
    check(senv)
    assert srv.requests == []


# ---- local blocklist ------------------------------------------------------------------------------------------------------
def indicator(**kw):
    now = timezone.now()
    base = dict(indicator="test-host.com", indicator_type="domain", threat_category="phishing",
                provider="local_blocklist", severity="critical", source_reference="case-12",
                first_seen_at=now, last_seen_at=now, checked_at=now)
    base.update(kw)
    return ThreatIndicator.objects.create(**base)


def test_local_blocklist_matches_domain_registrable_and_exact_url(senv):
    indicator(indicator="test-host.com")
    indicator(indicator="other.org", indicator_type="domain", threat_category="malware")
    indicator(indicator="https://x.example.net/bad", indicator_type="url", threat_category="malware")
    f = one(check(senv), "local_blocklist").findings
    assert [x.category for x in f] == ["phishing"] and f[0].reference == "case-12"
    exact = P.ThreatQuery(url="https://x.example.net/bad", host="x.example.net", registrable="example.net")
    assert [x.category for x in one(T.check_url(exact, guard=senv.world.guard), "local_blocklist").findings] == ["malware"]
    assert one(T.check_url(q(url="https://x.example.net/ok", host="x.example.net", reg="example.net"), guard=senv.world.guard),
               "local_blocklist").findings == []


def test_local_blocklist_ignores_expired_and_inactive_entries(senv):
    indicator(expires_at=timezone.now() - timedelta(hours=1))
    indicator(threat_category="malware", active=False)
    assert one(check(senv), "local_blocklist").findings == []


def test_findings_saved_from_external_providers_are_not_reserved_as_blocklist(senv):
    indicator(provider="google_web_risk", threat_category="malware")      # evidence/history, not a local entry
    assert one(check(senv), "local_blocklist").findings == []


# ---- Google Web Risk adapter ---------------------------------------------------------------------------------------------------
def wr_threat(types):
    return lambda r: http_response(200, json.dumps({"threat": {"threatTypes": types}} if types else {}),
                                   {"Content-Type": "application/json"})


@pytest.mark.parametrize("types,expected", [
    (["MALWARE"], [("malware", "critical")]), (["SOCIAL_ENGINEERING"], [("phishing", "critical")]),
    (["UNWANTED_SOFTWARE"], [("unwanted_software", "medium")]),
    (["MALWARE", "SOCIAL_ENGINEERING"], [("malware", "critical"), ("phishing", "critical")]), ([], []),
])
def test_web_risk_results_are_mapped(senv, monkeypatch, types, expected):
    webrisk(senv, wr_threat(types), monkeypatch)
    r = one(check(senv), "google_web_risk")
    assert r.status == "ok" and [(f.category, f.severity) for f in r.findings] == expected


def test_web_risk_key_goes_in_a_header_not_the_url_and_the_query_string_is_not_sent(senv, monkeypatch):
    srv = webrisk(senv, wr_threat([]), monkeypatch)
    check(senv, query=P.ThreatQuery(url="https://evil.test-host.com/pay", host="evil.test-host.com", registrable="test-host.com"))
    req = srv.requests[0]
    line = req.split("\r\n")[0]
    assert line.startswith("GET /v1/uris:search?threatTypes=MALWARE") and "uri=https%3A%2F%2Fevil.test-host.com%2Fpay" in line
    assert "test-key" not in line and "x-goog-api-key: test-key" in req.lower()


def test_missing_credentials_are_reported_not_ignored(senv, monkeypatch):
    srv = webrisk(senv, wr_threat([]), monkeypatch, key=None)
    r = one(check(senv), "google_web_risk")
    assert r.status == "not_configured" and r.findings == [] and srv.requests == []


@pytest.mark.parametrize("status,expected", [(429, "rate_limited"), (401, "error"), (403, "error"), (400, "error"), (500, "error"), (503, "error")])
def test_web_risk_failures_are_never_clean(senv, monkeypatch, status, expected):
    webrisk(senv, lambda r: http_response(status, "{}"), monkeypatch)
    r = one(check(senv), "google_web_risk")
    assert r.status == expected and r.findings == [] and r.error


def test_credential_rejection_message_does_not_leak_the_key(senv, monkeypatch):
    webrisk(senv, lambda r: http_response(403, '{"error":"key test-key invalid"}'), monkeypatch)
    r = one(check(senv), "google_web_risk")
    assert "test-key" not in r.error and "credentials" in r.error


def test_web_risk_garbage_response_is_an_error(senv, monkeypatch):
    webrisk(senv, lambda r: http_response(200, "<html>not json</html>"), monkeypatch)
    r = one(check(senv), "google_web_risk")
    assert r.status == "error" and "parsed" in r.error


def test_web_risk_timeout_is_reported(senv, monkeypatch):
    srv = webrisk(senv, wr_threat([]), monkeypatch)
    srv.delay = 2.0
    senv.world.guard.connect_timeout = 0.3
    assert one(check(senv), "google_web_risk").status == "timeout"


def test_transient_errors_are_retried_up_to_the_configured_attempts(senv, monkeypatch):
    calls = {"n": 0}

    def flaky(r):
        calls["n"] += 1
        return http_response(503, "{}") if calls["n"] == 1 else wr_threat(["MALWARE"])(r)
    webrisk(senv, flaky, monkeypatch)
    r = one(check(senv), "google_web_risk")
    assert calls["n"] == 2 and r.status == "ok" and r.findings[0].category == "malware"


def test_permanent_errors_are_not_retried(senv, monkeypatch):
    calls = {"n": 0}

    def limited(r):
        calls["n"] += 1
        return http_response(429, "{}")
    webrisk(senv, limited, monkeypatch)
    check(senv)
    assert calls["n"] == 1


def test_an_adapter_crash_is_an_error_not_a_clean_result(senv, monkeypatch):
    webrisk(senv, wr_threat([]), monkeypatch)
    monkeypatch.setattr(P.GoogleWebRiskProvider, "check", lambda self, q, s: (_ for _ in ()).throw(RuntimeError("bug")))
    r = one(check(senv), "google_web_risk")
    assert r.status == "error" and "RuntimeError" in r.error and r.findings == []


# ---- health metrics, rate limits, caching, persistence ------------------------------------------------------------------------------
def test_usage_and_health_metrics_are_recorded(senv, monkeypatch):
    webrisk(senv, wr_threat([]), monkeypatch)
    check(senv)
    p = ThreatProvider.objects.get(key="google_web_risk")
    assert p.request_count == 1 and p.error_count == 0 and p.last_success_at is not None
    senv.world.net.servers[(WR_IP, 443)].handler = lambda r: http_response(500, "{}")
    check(senv, query=q(url="https://other.com/", host="other.com", reg="other.com"))
    p.refresh_from_db()
    assert p.error_count == 2 and p.last_error_at is not None and "HTTP 500" in p.last_error


def test_provider_rate_limit_is_enforced_locally(senv, monkeypatch):
    srv = webrisk(senv, wr_threat([]), monkeypatch)
    ThreatProvider.objects.filter(key="google_web_risk").update(rate_limit_per_minute=1)
    first = one(check(senv), "google_web_risk")
    second = one(check(senv, query=q(url="https://b.com/", host="b.com", reg="b.com")), "google_web_risk")
    assert first.status == "ok" and second.status == "rate_limited" and len(srv.requests) == 1


def test_provider_results_can_be_cached_when_the_terms_allow(senv, monkeypatch):
    srv = webrisk(senv, wr_threat(["MALWARE"]), monkeypatch)
    ThreatProvider.objects.filter(key="google_web_risk").update(config={"cache_ttl_seconds": 60})
    check(senv)
    second = one(check(senv), "google_web_risk")
    assert second.cached and second.findings[0].category == "malware" and len(srv.requests) == 1


def test_no_caching_by_default(senv, monkeypatch):
    srv = webrisk(senv, wr_threat([]), monkeypatch)
    check(senv)
    check(senv)
    assert len(srv.requests) == 2


def test_positive_findings_are_stored_with_provider_reference_and_timestamp_without_duplicates(senv, monkeypatch):
    webrisk(senv, wr_threat(["SOCIAL_ENGINEERING"]), monkeypatch)
    check(senv)
    first = ThreatIndicator.objects.get(provider="google_web_risk")
    assert first.threat_category == "phishing" and first.source_reference == "webrisk:SOCIAL_ENGINEERING"
    assert first.indicator == "https://evil.test-host.com/pay" and first.expires_at > first.checked_at
    check(senv)
    assert ThreatIndicator.objects.filter(provider="google_web_risk").count() == 1


def test_clean_results_store_nothing(senv, monkeypatch):
    webrisk(senv, wr_threat([]), monkeypatch)
    check(senv)
    assert ThreatIndicator.objects.count() == 0


def test_outcome_confirms_only_malware_and_phishing(senv, monkeypatch):
    webrisk(senv, wr_threat(["UNWANTED_SOFTWARE"]), monkeypatch)
    o = check(senv)
    assert o.findings and o.confirmed == []
    senv.world.net.servers[(WR_IP, 443)].handler = wr_threat(["MALWARE"])
    assert [f["category"] for f in check(senv, query=q(url="https://z.com/", host="z.com", reg="z.com")).confirmed] == ["malware"]
