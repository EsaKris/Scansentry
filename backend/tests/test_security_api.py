import json

import pytest

from apps.core.models import AppConfiguration
from apps.security_engine import service as sec
from apps.security_engine.models import SecurityCheck, SecurityRule
from apps.threat_intel.models import ThreatIndicator, ThreatProvider
from tests.conftest import enable_provider
from tests.netfakes import http_response, redirect

pytestmark = pytest.mark.django_db
URL = "/api/v1/security/analyze/"
FORBIDDEN_WORDS = ("100% safe", "completely safe", "guaranteed safe", "is safe to", "risk-free")


def analyze(client, url, **extra):
    return client.post(URL, {"url": url, **extra}, format="json")


def keys(resp):
    return {f["rule"] for f in resp.data["findings"]}


def dump_everything() -> str:
    parts = []
    for c in SecurityCheck.objects.all():
        parts.append(json.dumps([c.submitted_url, c.normalised_url, c.rule_results, c.threat_findings,
                                 c.redirect_trace, c.explanation, c.scoring, c.missing_checks, c.provider_errors], default=str))
    for t in ThreatIndicator.objects.all():
        parts.append(t.indicator)
    return " ".join(parts)


# ---- Scenario 4: a controlled URL triggers documented rules and is explained ------------------------------------------
def test_suspicious_destination_is_explained_with_evidence_and_no_secrets_stored(api, senv):
    enable_provider("test_fixture")
    r = analyze(api, "http://paypal-secure-login.com/verify?token=SECRET99#frag77")
    assert r.status_code == 200 and r["Cache-Control"] == "no-store"
    d = r.data
    assert d["classification"] == "suspicious" and d["classification_label"] == "Suspicious"
    assert {"url.brand_keyword_combo", "tls.no_https"} <= keys(r)
    weights = [f["weight"] for f in d["findings"]]
    assert weights == sorted(weights, reverse=True)
    f = next(x for x in d["findings"] if x["rule"] == "url.brand_keyword_combo")
    assert f["reason_code"] == "brand_keyword_combo" and f["evidence"]["matches"][0]["brand"] == "paypal.com" and f["version"] == 1
    ex = d["explanation"]
    assert ex["source"] == "rule_based" and ex["classification"] == "suspicious" and "warning signs" in ex["summary"]
    assert ex["recommended_actions"] and any("passwords or payment" in a for a in ex["recommended_actions"])
    assert d["destination"]["submitted_url"] == "http://paypal-secure-login.com/verify"
    assert "SECRET99" not in dump_everything() and "SECRET99" not in json.dumps(d, default=str)
    assert "frag77" not in dump_everything()
    assert d["scoring"]["risk_version"] == "risk-1" and d["scoring"]["ruleset_hash"] and d["scoring"]["thresholds"]["high_risk"] == 65
    assert "not been validated" in d["scoring"]["note"] and len(d["limitations"]) >= 3


def test_homograph_destination_is_flagged_strongly(api, senv):
    senv.publish("xn--pple-43d.com")
    r = analyze(api, "https://аpple.com/login")
    assert {"url.mixed_scripts", "url.punycode_idn", "url.lookalike_brand"} <= keys(r)
    assert r.data["classification"] == "high_risk"        # mixed alphabets + brand look-alike: strong, independent signals
    assert r.data["destination"]["domain"] == "xn--pple-43d.com"


# ---- Scenario 8: threat intelligence ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("host,rule,category,ref", [
    ("ss-malware-test.example.com", "intel.known_malware", "malware", "fixture-mal-001"),
    ("ss-phish-test.example.com", "intel.known_phishing", "phishing", "fixture-phi-001"),
])
def test_known_malicious_indicator_updates_the_assessment_and_records_evidence(api, senv, host, rule, category, ref):
    senv.publish(host)
    enable_provider("test_fixture")
    r = analyze(api, f"https://{host}/pay")
    d = r.data
    assert d["classification"] == "known_malicious" and d["risk_score"] == 100 and rule in keys(r)
    ti = d["threat_intelligence"]
    assert any(p["provider"] == "test_fixture" and p["status"] == "ok" for p in ti["providers"])
    assert ti["findings"][0]["category"] == category and ti["findings"][0]["reference"] == ref
    row = ThreatIndicator.objects.get(provider="test_fixture")
    assert row.threat_category == category and row.source_reference == ref and row.checked_at and row.expires_at
    assert "will not forward" in d["policy"] and "will not forward" in d["explanation"]["summary"]
    assert next(f for f in d["findings"] if f["rule"] == rule)["evidence"]["sources"][0]["reference"] == ref


def test_harmless_fixture_indicator_with_a_healthy_domain_is_no_known_threat_but_never_safe(api, senv):
    senv.publish("ss-harmless-test.example.com")
    enable_provider("test_fixture")
    r = analyze(api, "https://ss-harmless-test.example.com/")
    d = r.data
    assert d["classification"] == "no_known_threat_detected" and d["classification_label"] == "No known threat detected"
    assert d["completion_status"] == "complete" and d["missing_checks"] == [] and d["confidence"] == "high"
    assert "not a guarantee" in d["explanation"]["summary"]
    blob = json.dumps(d, default=str).lower()
    assert not any(w in blob for w in FORBIDDEN_WORDS)


def test_suspicious_listing_from_a_provider_is_moderate_not_malicious(api, senv):
    senv.publish("ss-suspicious-test.example.com")
    enable_provider("test_fixture")
    r = analyze(api, "https://ss-suspicious-test.example.com/")
    assert "intel.suspicious_listing" in keys(r) and r.data["classification"] != "known_malicious"


def test_local_blocklist_entries_apply(api, senv):
    from django.utils import timezone
    senv.publish("blocked-shop.com")
    now = timezone.now()
    ThreatIndicator.objects.create(indicator="blocked-shop.com", indicator_type="domain", threat_category="phishing",
                                   provider="local_blocklist", severity="critical", first_seen_at=now, last_seen_at=now, checked_at=now)
    r = analyze(api, "https://blocked-shop.com/")
    assert r.data["classification"] == "known_malicious"


# ---- Scenario 7: providers/checks unavailable ---------------------------------------------------------------------------------
def test_provider_outage_is_reported_and_never_becomes_a_clean_result(api, senv, monkeypatch):
    senv.publish("shop.com")
    monkeypatch.setenv("THREAT_INTEL_API_KEY", "test-key")
    enable_provider("google_web_risk")
    srv = senv.world.site("webrisk.googleapis.com", "142.250.0.1", https=lambda r: http_response(503, "{}"))
    r = analyze(api, "https://shop.com/")
    d = r.data
    assert d["classification"] == "needs_further_verification" and d["classification"] != "no_known_threat_detected"
    assert d["completion_status"] == "partial" and d["confidence"] != "high"
    checks = {m["check"] for m in d["missing_checks"]}
    assert {"threat_intelligence", "threat_intel:google_web_risk"} <= checks
    assert any(e["provider"] == "google_web_risk" and e["status"] == "error" for e in d["provider_errors"])
    assert any("could not be completed" in x for x in d["explanation"]["limitations"])
    assert len(srv.requests) == 2          # retried once, then reported
    assert ThreatProvider.objects.get(key="google_web_risk").error_count == 2


def test_no_external_provider_enabled_means_further_verification_not_clean(api, senv):
    senv.publish("shop.com")
    d = analyze(api, "https://shop.com/").data
    assert d["classification"] == "needs_further_verification"
    assert any(m["check"] == "threat_intelligence" and "No external threat-intelligence provider is enabled" in m["reason"] for m in d["missing_checks"])


def test_local_rules_still_run_when_everything_external_is_down(api, senv, monkeypatch):
    monkeypatch.setattr(sec.domain_service, "assess", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    d = analyze(api, "https://аpple.com/").data
    assert d["classification"] == "high_risk"                                # local rules carried the verdict
    assert {"url.mixed_scripts"} <= {f["rule"] for f in d["findings"]}
    assert any(m["check"] == "domain" for m in d["missing_checks"]) and d["domain"] is None


def test_nothing_assessable_is_assessment_unavailable(api, senv, monkeypatch):
    monkeypatch.setattr(sec.domain_service, "assess", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    d = analyze(api, "https://shop.com/").data
    assert d["classification"] == "assessment_unavailable" and d["classification_label"] == "Assessment unavailable"
    assert d["risk_score"] == 0 and d["confidence"] == "low"


def test_a_crashing_rule_lowers_confidence_and_is_listed(api, senv, monkeypatch):
    from apps.security_engine import rules as R
    senv.publish("shop.com")
    enable_provider("test_fixture")
    d0 = R.REGISTRY["url.ip_host"]
    monkeypatch.setitem(R.REGISTRY, "url.ip_host", R.RuleDef(**{**d0.__dict__, "detect": lambda c, p: 1 / 0}))
    d = analyze(api, "https://shop.com/").data
    assert d["rule_errors"][0]["rule"] == "url.ip_host" and any(m["check"] == "rules" for m in d["missing_checks"])
    assert d["confidence"] != "high" and d["completion_status"] == "partial"


# ---- URLs that must not reach the network -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("url,expected_rule,cls", [
    ("javascript:alert(document.cookie)", "url.dangerous_scheme", "high_risk"),
    ("data:text/html;base64,PHNjcmlwdD4=", "url.dangerous_scheme", "high_risk"),
    ("myapp://open?token=abc123", "url.unsupported_scheme", "low"),
    ("https://paypal.com@evil-host.com/x", "url.credentials_in_url", "suspicious"),
    ("https://%65xample.com/", "url.encoded_host", "suspicious"),
])
def test_dangerous_or_malformed_links_are_assessed_without_any_network_activity(api, senv, monkeypatch, url, expected_rule, cls):
    monkeypatch.setenv("THREAT_INTEL_API_KEY", "k")
    enable_provider("google_web_risk")
    srv = senv.world.site("webrisk.googleapis.com", "142.250.0.1", https=lambda r: http_response(200, "{}"))
    d = analyze(api, url).data
    assert expected_rule in {f["rule"] for f in d["findings"]}
    if cls != "low":
        assert d["classification"] == cls
    assert senv.world.net.connections == [] and senv.world.dns.address_calls == [] and srv.requests == []
    assert "abc123" not in dump_everything()


def test_ip_address_urls_are_flagged_and_domain_assessment_is_not_applicable(api, senv):
    enable_provider("test_fixture")
    r = analyze(api, "http://93.184.216.34/login")
    assert {"url.ip_host", "tls.no_https"} <= keys(r) and r.data["domain"] is None
    assert not any(m["check"].startswith("domain") for m in r.data["missing_checks"])


# ---- redirect tracing (shorteners only) ---------------------------------------------------------------------------------------------
def shortener(senv, target, host="bit.ly"):
    return senv.world.site(host, "67.199.248.10", https=lambda r: redirect(target))


def test_shortened_link_is_traced_and_the_destination_is_assessed(api, senv):
    senv.publish("paypa1.com")
    shortener(senv, "https://paypa1.com/x?secret=Q1")
    enable_provider("test_fixture")
    r = analyze(api, "https://bit.ly/abc")
    d = r.data
    assert {"url.shortener", "url.lookalike_brand"} <= keys(r) and d["classification"] == "suspicious"
    tr = d["redirect_trace"]
    assert tr["completed"] and [h["status"] for h in tr["hops"]] == [302, 200] and tr["final_url_redacted"] == "https://paypa1.com/x"
    assert d["destination"]["domain"] == "paypa1.com"
    assert "secret=Q1" not in dump_everything() and "Q1" not in json.dumps(d, default=str)
    targets = {p.get("target") for p in d["threat_intelligence"]["providers"]} or {None}
    assert d["domain"]["assessment_id"]


def test_each_hop_and_the_final_url_are_checked_with_threat_intel(api, senv):
    senv.publish("ss-malware-test.example.com")
    shortener(senv, "https://ss-malware-test.example.com/dl")
    enable_provider("test_fixture")
    d = analyze(api, "https://bit.ly/zzz").data
    assert d["classification"] == "known_malicious"      # the destination, not the shortener, is what matters


def test_shortener_trace_failure_is_reported_as_missing_not_clean(api, senv):
    senv.world.dns.set("bit.ly", "A", ["67.199.248.10"])        # nothing listening
    enable_provider("test_fixture")
    d = analyze(api, "https://bit.ly/abc").data
    assert any(m["check"] == "redirect_trace" for m in d["missing_checks"])
    assert d["classification"] != "no_known_threat_detected" and d["redirect_trace"]["completed"] is False


def test_redirect_to_an_internal_address_is_blocked_and_flagged(api, senv):
    shortener(senv, "http://169.254.169.254/latest/meta-data/")
    senv.world.net.add("169.254.169.254", 80, lambda r: http_response(200, "SECRET-METADATA"))
    enable_provider("test_fixture")
    r = analyze(api, "https://bit.ly/abc")
    assert "redirect.suspicious_chain" in keys(r) and r.data["redirect_trace"]["error"] == "blocked_destination"
    assert ("169.254.169.254", 80) not in senv.world.net.connections
    assert "SECRET-METADATA" not in json.dumps(r.data, default=str)


def test_redirect_loop_and_long_chain_are_flagged(api, senv):
    shortener(senv, "https://bit.ly/abc")
    enable_provider("test_fixture")
    assert "redirect.suspicious_chain" in keys(analyze(api, "https://bit.ly/abc"))
    # chain across three unrelated domains
    for src, dst in [("tinyurl.com", "https://a-site.com/1"), ("a-site.com", "https://b-site.com/2"), ("b-site.com", "https://c-site.com/3")]:
        senv.world.site(src, f"93.184.216.{len(src)}", https=lambda r, dst=dst: redirect(dst))
    senv.publish("c-site.com", "93.184.217.9")
    assert "redirect.suspicious_chain" in keys(analyze(api, "https://tinyurl.com/q"))


def test_trace_can_be_switched_off_per_request_and_only_runs_for_shorteners(api, senv):
    shortener(senv, "https://elsewhere.com/")
    enable_provider("test_fixture")
    d = analyze(api, "https://bit.ly/abc", trace=False).data
    assert d["redirect_trace"] is None
    senv.publish("plain-site.com")
    assert analyze(api, "https://plain-site.com/start").data["redirect_trace"] is None


def test_tracing_can_be_disabled_by_the_administrator(api, senv):
    shortener(senv, "https://elsewhere.com/")
    AppConfiguration.objects.create(key="security.trace_shorteners", value=False)
    assert analyze(api, "https://bit.ly/abc").data["redirect_trace"] is None


# ---- privacy -----------------------------------------------------------------------------------------------------------------------------------
def test_threat_providers_never_receive_query_strings_or_fragments(api, senv, monkeypatch):
    senv.publish("shop.com")
    monkeypatch.setenv("THREAT_INTEL_API_KEY", "k")
    enable_provider("google_web_risk")
    srv = senv.world.site("webrisk.googleapis.com", "142.250.0.1", https=lambda r: http_response(200, "{}"))
    analyze(api, "https://shop.com/account/reset?token=TOPSECRET#abc")
    sent = " ".join(srv.requests)
    assert "TOPSECRET" not in sent and "abc" not in sent.split("\r\n")[0] and "shop.com%2Faccount%2Freset" in sent


# ---- caching / configuration ----------------------------------------------------------------------------------------------------------------------
def test_results_are_cached_and_configuration_changes_invalidate_the_cache(api, senv):
    senv.publish("shop.com")
    enable_provider("test_fixture")
    first = analyze(api, "https://shop.com/x?a=1").data
    second = analyze(api, "https://shop.com/x?a=2").data         # query differs, assessment is by destination
    assert second["cached"] is True and second["id"] == first["id"] and SecurityCheck.objects.count() == 1
    SecurityRule.objects.filter(key="url.shortener").update(weight=11)
    assert analyze(api, "https://shop.com/x").data["id"] != first["id"]


def test_incomplete_assessments_are_cached_only_briefly(api, senv):
    senv.publish("shop.com")
    c = SecurityCheck.objects.get(pk=analyze(api, "https://shop.com/").data["id"])
    assert c.completion_status == "partial" and (c.cache_expires_at - c.checked_at).total_seconds() <= 300 + 1


def test_cache_minutes_is_admin_configurable(api, senv):
    senv.publish("shop.com")
    enable_provider("test_fixture")
    AppConfiguration.objects.create(key="security.cache_minutes", value=2)
    c = SecurityCheck.objects.get(pk=analyze(api, "https://shop.com/").data["id"])
    assert abs((c.cache_expires_at - c.checked_at).total_seconds() - 120) < 2


# ---- input / access ----------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("value", ["tel:+2348012345678", "mailto:a@b.co", "hello world", "WIFI:S:x;T:nopass;;", "BEGIN:VCARD\nFN:A\nEND:VCARD"])
def test_non_web_content_is_not_applicable(api, senv, value):
    r = analyze(api, value)
    assert r.status_code == 400 and "web links" in json.dumps(r.data)


def test_input_validation_and_detail_endpoint(api, senv):
    assert api.post(URL, {}, format="json").status_code == 400
    assert analyze(api, "").status_code == 400
    assert analyze(api, "https://example.com/" + "a" * 3000).status_code == 400
    senv.publish("shop.com")
    d = analyze(api, "https://shop.com/").data
    got = api.get(f"/api/v1/security/checks/{d['id']}/")
    assert got.status_code == 200 and got.data["classification"] == d["classification"]
    assert api.get("/api/v1/security/checks/00000000-0000-0000-0000-000000000000/").status_code == 404
    assert api.get("/api/v1/security/checks/not-a-uuid/").status_code == 404


def test_no_response_ever_claims_a_destination_is_safe(api, senv):
    senv.publish("ss-harmless-test.example.com")
    enable_provider("test_fixture")
    for url in ["https://ss-harmless-test.example.com/", "http://paypal-secure-login.com/", "https://аpple.com/", "javascript:1"]:
        blob = json.dumps(analyze(api, url).data, default=str).lower()
        assert not any(w in blob for w in FORBIDDEN_WORDS), url


def test_signed_in_requests_are_attributed(auth_client, user, senv):
    senv.publish("shop.com")
    c = SecurityCheck.objects.get(pk=analyze(auth_client, "https://shop.com/").data["id"])
    assert c.requested_by_id == user.id


# ---- provider administration --------------------------------------------------------------------------------------------------------------------------------
def test_provider_status_endpoint_is_admin_only_and_never_returns_secrets(api, auth_client, user, monkeypatch):
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient
    monkeypatch.setenv("THREAT_INTEL_API_KEY", "super-secret-key-123")
    assert api.get("/api/v1/security/providers/").status_code == 401
    assert auth_client.get("/api/v1/security/providers/").status_code == 403
    staff = get_user_model().objects.create_user("staff@example.com", "Str0ng-Passphrase-42", is_staff=True)
    c = APIClient()
    tok = c.post("/api/v1/auth/login/", {"email": staff.email, "password": "Str0ng-Passphrase-42"}).data["access"]
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {tok}")
    r = c.get("/api/v1/security/providers/")
    assert r.status_code == 200 and "super-secret-key-123" not in json.dumps(r.data)
    wr = next(p for p in r.data["providers"] if p["key"] == "google_web_risk")
    assert wr["credential_configured"] is True and wr["enabled"] is False and "commercially licensed" in wr["licensing_note"].lower()
    local = next(p for p in r.data["providers"] if p["key"] == "local_blocklist")
    assert local["external_source"] is False and local["credential_configured"] is None


def test_admin_pages_load_and_rule_edits_are_audited(client, db):
    from django.contrib.auth import get_user_model
    from apps.audit.models import AuditLog
    su = get_user_model().objects.create_superuser("root@example.com", "Str0ng-Passphrase-42")
    client.force_login(su)
    for path in ["/admin/security_engine/securityrule/", "/admin/security_engine/securitycheck/",
                 "/admin/threat_intel/threatprovider/", "/admin/threat_intel/threatindicator/"]:
        assert client.get(path).status_code == 200, path
    rule = SecurityRule.objects.get(key="url.shortener")
    page = client.get(f"/admin/security_engine/securityrule/{rule.pk}/change/")
    assert page.status_code == 200
    resp = client.post(f"/admin/security_engine/securityrule/{rule.pk}/change/", {
        "severity": "medium", "enabled": "on", "weight": "20", "params": "{}"})
    assert resp.status_code == 302
    rule.refresh_from_db()
    assert rule.weight == 20 and AuditLog.objects.filter(action="security_rule.changed").exists()
