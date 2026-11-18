import pytest

from apps.core.models import AppConfiguration
from apps.domain_intel.normalize import InvalidDomainInput, normalize_domain_input
from apps.scanner.analysis import analyze_content
from apps.security_engine import rules as R
from apps.security_engine import scoring
from apps.security_engine.lookalike import find_brand_keyword, find_lookalikes, levenshtein, skeleton
from apps.security_engine.models import SecurityRule
from apps.threat_intel.models import ThreatProvider

pytestmark = pytest.mark.django_db


def ctx_for(raw, *, domain=None, threat=None, trace=None, original_host=None):
    a = analyze_content(raw)
    facts = a["url"]
    host = (facts or {}).get("host")
    try:
        nd = normalize_domain_input(host) if host else None
    except InvalidDomainInput:
        nd = None
    return R.RuleContext(
        raw=raw, kind=a["kind"], url=facts, observations=a["observations"], normalized=(facts or {}).get("normalized"),
        host=host, display_host=(facts or {}).get("display_host"), registrable=nd.registrable if nd else None,
        display_registrable=nd.registrable.encode().decode("idna") if nd else None,
        scheme=(facts or {}).get("scheme"), domain=domain, threat={"findings": threat or []}, trace=trace,
        original_host=original_host, **R.load_lists())


def fired(raw, **kw):
    results = R.evaluate(ctx_for(raw, **kw), R.effective_rules())
    return {r["rule"] for r in results if r.get("status") == "triggered"}


# ---- registry / configuration ------------------------------------------------------------------------------
def test_every_rule_has_the_required_metadata_and_is_synced_to_the_database():
    assert len(R.REGISTRY) >= 20
    for d in R.REGISTRY.values():
        assert d.key and d.name and d.description and d.category and d.recommended_action
        assert d.strength in ("weak", "moderate", "strong") and d.severity in ("low", "medium", "high", "critical") and d.version >= 1
    assert SecurityRule.objects.count() == len(R.REGISTRY)


def test_default_threat_providers_exist_and_only_the_local_one_is_enabled():
    enabled = set(ThreatProvider.objects.filter(enabled=True).values_list("key", flat=True))
    assert enabled == {"local_blocklist"}
    assert ThreatProvider.objects.get(key="google_web_risk").credential_ref == "THREAT_INTEL_API_KEY"


def test_pre_spec_weak_indicators_are_actually_weak():
    for key in ("domain.recently_registered", "url.shortener", "tls.no_https", "url.unusual_tld", "url.punycode_idn"):
        assert R.REGISTRY[key].strength == "weak", key


def test_admin_can_disable_a_rule_and_change_its_weight_without_a_deploy():
    assert "url.shortener" in fired("https://bit.ly/abc")
    SecurityRule.objects.filter(key="url.shortener").update(enabled=False)
    assert "url.shortener" not in fired("https://bit.ly/abc")
    SecurityRule.objects.filter(key="url.shortener").update(enabled=True, weight=33)
    res = [r for r in R.evaluate(ctx_for("https://bit.ly/abc"), R.effective_rules()) if r["rule"] == "url.shortener"]
    assert res[0]["weight"] == 33


def test_ruleset_hash_changes_when_configuration_changes():
    h1 = R.ruleset_hash(R.effective_rules())
    SecurityRule.objects.filter(key="url.ip_host").update(weight=99)
    assert R.ruleset_hash(R.effective_rules()) != h1


def test_sync_updates_code_owned_fields_but_never_admin_tuning(monkeypatch):
    SecurityRule.objects.filter(key="url.ip_host").update(weight=77, name="old name", version=0)
    R.sync_rules()
    row = SecurityRule.objects.get(key="url.ip_host")
    assert row.weight == 77 and row.name == R.REGISTRY["url.ip_host"].name and row.version == 1


def test_threshold_params_are_configurable():
    assert "url.excessive_subdomains" not in fired("https://a.b.c.example.com/")
    SecurityRule.objects.filter(key="url.excessive_subdomains").update(params={"min_labels": 3})
    assert "url.excessive_subdomains" in fired("https://a.b.c.example.com/")


def test_a_crashing_rule_is_reported_as_an_error_not_as_not_triggered(monkeypatch):
    def boom(c, p):
        raise RuntimeError("bug")
    d = R.REGISTRY["url.ip_host"]
    monkeypatch.setitem(R.REGISTRY, "url.ip_host", R.RuleDef(**{**d.__dict__, "detect": boom}))
    results = R.evaluate(ctx_for("http://8.8.8.8/"), R.effective_rules())
    err = [r for r in results if r["rule"] == "url.ip_host"][0]
    assert err["status"] == "error" and err["error"] == "RuntimeError"


# ---- individual rules ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("url,rule_key", [
    ("javascript:alert(1)", "url.dangerous_scheme"), ("data:text/html,x", "url.dangerous_scheme"),
    ("myapp://open", "url.unsupported_scheme"),
    ("https://paypal.com@evil.example.org/", "url.credentials_in_url"),
    ("https://%65xample.com/", "url.encoded_host"),
    ("http://8.8.8.8/login", "url.ip_host"), ("http://[2001:4860:4860::8888]/", "url.ip_host"),
    ("http://2130706433/", "url.obfuscated_ip"), ("http://0x7f000001/", "url.obfuscated_ip"),
    ("https://bücher.de/", "url.punycode_idn"),
    ("https://аpple.com/", "url.mixed_scripts"),
    ("https://paypa1.com/", "url.lookalike_brand"), ("https://paypal.com.evil-site.io/", "url.lookalike_brand"),
    ("https://paypal-secure-login.com/", "url.brand_keyword_combo"),
    ("https://a.b.c.d.example.com/", "url.excessive_subdomains"),
    ("https://example.com/a%252fb", "url.encoding_unusual"), ("https://example.com/a%00b", "url.encoding_unusual"),
    ("https://example.com/\u202eexe.txt", "url.encoding_unusual"),
    ("https://example.com/go?url=https%3A%2F%2Fevil.example.org", "url.redirect_parameter"),
    ("https://bit.ly/abc", "url.shortener"), ("https://tinyurl.com/x", "url.shortener"),
    ("https://free-prizes.click/", "url.unusual_tld"),
    ("http://example.com/", "tls.no_https"),
])
def test_rule_fires(url, rule_key):
    assert rule_key in fired(url), url


@pytest.mark.parametrize("url", [
    "https://www.example.com/", "https://login.paypal.com/", "https://www.paypal.com/signin", "https://paypal.com/",
    "https://accounts.google.com/", "https://pineapple-login.com/", "https://applepie-recipes.com/",
    "https://mail.google.com/mail/u/0/", "https://docs.microsoft.com/en-us/", "https://example.co.uk/",
])
def test_legitimate_urls_trigger_no_impersonation_or_structure_rules(url):
    hits = fired(url)
    assert not (hits & {"url.lookalike_brand", "url.brand_keyword_combo", "url.mixed_scripts", "url.ip_host",
                        "url.credentials_in_url", "url.encoding_unusual"}), (url, hits)


def test_domain_age_rule_is_a_threshold_and_age_unknown_never_fires():
    young = {"registration": {"age_days": 10, "status": "REGISTERED_ACTIVE"}}
    old = {"registration": {"age_days": 4000, "status": "REGISTERED_ACTIVE"}}
    unknown = {"registration": {"age_days": None, "status": "LOOKUP_UNAVAILABLE"}}
    assert "domain.recently_registered" in fired("https://example.com/", domain=young)
    assert "domain.recently_registered" not in fired("https://example.com/", domain=old)
    assert "domain.recently_registered" not in fired("https://example.com/", domain=unknown)


def test_registry_hold_and_certificate_rules_use_domain_facts():
    held = {"registration": {"status": "REGISTRAR_HOLD"}, "tls": {"status": "VALID"}}
    assert "domain.registry_hold" in fired("https://example.com/", domain=held)
    assert "domain.registry_hold" not in fired("https://example.com/", domain={"registration": {"status": "REGISTERED_ACTIVE"}})
    for status in ("EXPIRED", "HOSTNAME_MISMATCH", "SELF_SIGNED", "UNTRUSTED_CHAIN", "NOT_YET_VALID"):
        assert "tls.invalid_certificate" in fired("https://example.com/", domain={"tls": {"status": status, "message": "x"}})
    assert "tls.invalid_certificate" not in fired("https://example.com/", domain={"tls": {"status": "VALID"}})
    assert "tls.no_https" in fired("https://example.com/", domain={"tls": {"status": "NO_HTTPS"}})


def test_threat_intel_rules_map_categories():
    f = lambda cat: [{"provider": "p", "category": cat, "severity": "critical", "reference": "r1", "detail": ""}]
    assert "intel.known_malware" in fired("https://example.com/", threat=f("malware"))
    assert "intel.known_phishing" in fired("https://example.com/", threat=f("phishing"))
    assert "intel.unwanted_software" in fired("https://example.com/", threat=f("unwanted_software"))
    assert "intel.suspicious_listing" in fired("https://example.com/", threat=f("suspicious"))
    assert not fired("https://example.com/", threat=[]) & {"intel.known_malware", "intel.known_phishing"}


def test_redirect_chain_rule():
    assert "redirect.suspicious_chain" in fired("https://bit.ly/x", trace={"error": "redirect_loop"}, original_host="bit.ly")
    assert "redirect.suspicious_chain" in fired("https://bit.ly/x", trace={"error": "blocked_destination"}, original_host="bit.ly")
    assert "redirect.suspicious_chain" in fired("https://bit.ly/x", trace={"distinct_registrable_domains": 3, "hop_count": 3}, original_host="bit.ly")
    assert "redirect.suspicious_chain" not in fired("https://bit.ly/x", trace={"distinct_registrable_domains": 2, "hop_count": 2}, original_host="bit.ly")


def test_shortener_rule_uses_the_original_host_after_a_trace():
    assert "url.shortener" in fired("https://example.com/", original_host="bit.ly")


def test_brand_list_is_admin_editable():
    assert "url.lookalike_brand" in fired("https://paypa1.com/")
    assert "url.lookalike_brand" not in fired("https://mybanc.com/")
    AppConfiguration.objects.create(key="security.brand_domains", value=["mybank.com"])
    assert R.load_lists()["brands"] == ["mybank.com"]
    assert "url.lookalike_brand" in fired("https://mybanc.com/")          # new brand now protected
    assert "url.lookalike_brand" not in fired("https://paypa1.com/")      # old default list replaced


def test_shortener_and_tld_lists_are_admin_editable():
    AppConfiguration.objects.create(key="security.url_shorteners", value=["go.example.org"])
    AppConfiguration.objects.create(key="security.unusual_tlds", value=["shop"])
    assert "url.shortener" not in fired("https://bit.ly/x") and "url.shortener" in fired("https://go.example.org/x")
    assert "url.unusual_tld" in fired("https://store.shop/") and "url.unusual_tld" not in fired("https://x.click/")


# ---- look-alike helpers ------------------------------------------------------------------------------------------------------
def test_skeleton_and_distance():
    assert skeleton("paypa1") == skeleton("paypal") and skeleton("раypal") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert levenshtein("paypal", "paypall") == 1 and levenshtein("a", "a") == 0 and levenshtein("kitten", "sitting") == 3


@pytest.mark.parametrize("host,reg,kind", [
    ("paypa1.com", "paypa1.com", "homoglyph"), ("раypal.com", "раypal.com", "homoglyph"),
    ("paypall.com", "paypall.com", "typosquat"), ("microsft.com", "microsft.com", "typosquat"),
    ("paypal.com.evil.io", "evil.io", "brand_in_subdomain"),
])
def test_find_lookalikes_kinds(host, reg, kind):
    from apps.security_engine.lookalike import DEFAULT_BRANDS
    hits = find_lookalikes(host, reg, DEFAULT_BRANDS)
    assert hits and hits[0]["kind"] == kind


def test_lookalike_ignores_the_brands_own_domain_and_short_names():
    from apps.security_engine.lookalike import DEFAULT_BRANDS
    assert find_lookalikes("login.paypal.com", "paypal.com", DEFAULT_BRANDS) == []
    assert find_lookalikes("ups1.com", "ups1.com", ["ups.com"]) == []        # too short for fuzzy matching
    assert find_brand_keyword("paypal.com", "paypal.com", ["paypal.com"]) == []


# ---- scoring: the "never severe from weak indicators alone" guarantee ---------------------------------------------------------
def R_(rule, strength, weight):
    return {"rule": rule, "strength": strength, "weight": weight, "status": "triggered"}


def test_many_weak_indicators_can_reach_suspicious_but_never_high_risk():
    weak = [R_(f"w{i}", "weak", 12) for i in range(10)]        # 120 raw points
    sc = scoring.score_rules(weak)
    assert sc["raw_points"] == 120 and sc["score"] == 49 and sc["band"] == "suspicious"
    assert any("weak indicators" in n for n in sc["notes"])
    assert scoring.classify(sc, intel_ok=True, domain_status="complete") == "suspicious"


def test_a_single_weak_indicator_is_not_even_suspicious():
    sc = scoring.score_rules([R_("w", "weak", 12)])
    assert sc["band"] == "low" and scoring.classify(sc, intel_ok=True, domain_status="complete") == "no_known_threat_detected"


@pytest.mark.parametrize("items,band", [
    ([("moderate", 25)], "low"), ([("moderate", 25), ("weak", 12)], "suspicious"),
    ([("strong", 45)], "suspicious"), ([("strong", 45), ("moderate", 25)], "high_risk"),
    ([("moderate", 25)] * 3, "high_risk"), ([("moderate", 30), ("moderate", 30)], "suspicious"),
    ([("strong", 70)], "high_risk"),
])
def test_score_bands(items, band):
    sc = scoring.score_rules([R_(f"r{i}", s, w) for i, (s, w) in enumerate(items)])
    assert sc["band"] == band


def test_high_risk_needs_a_strong_indicator_or_two_moderate_ones():
    sc = scoring.score_rules([R_("m", "moderate", 90)])     # one heavy-weighted moderate rule
    assert sc["band"] == "suspicious" and sc["score"] <= 64


def test_confirmed_threat_forces_known_malicious_and_score_100():
    sc = scoring.score_rules([R_("intel.known_phishing", "strong", 100)])
    assert sc["score"] == 100 and sc["confirmed_threat"]
    assert scoring.classify(sc, intel_ok=False, domain_status="failed") == "known_malicious"


def test_known_malicious_cannot_come_from_a_score_alone():
    sc = scoring.score_rules([R_("a", "strong", 90), R_("b", "strong", 90)])
    assert scoring.classify(sc, intel_ok=True, domain_status="complete") == "high_risk"


@pytest.mark.parametrize("intel_ok,domain,expected", [
    (True, "complete", "no_known_threat_detected"), (True, "partial", "no_known_threat_detected"),
    (True, "not_applicable", "no_known_threat_detected"), (True, "failed", "needs_further_verification"),
    (False, "complete", "needs_further_verification"), (False, "partial", "needs_further_verification"),
    (False, "failed", "assessment_unavailable"), (False, "not_run", "assessment_unavailable"),
    (True, "not_run", "no_known_threat_detected"),
])
def test_clean_classification_requires_an_answering_threat_source(intel_ok, domain, expected):
    sc = scoring.score_rules([])
    assert scoring.classify(sc, intel_ok=intel_ok, domain_status=domain) == expected


def test_thresholds_are_configurable_and_confidence_reflects_coverage():
    AppConfiguration.objects.create(key="security.risk_thresholds", value={"suspicious": 20})
    assert scoring.score_rules([R_("m", "moderate", 25)])["band"] == "suspicious"
    assert scoring.confidence(intel_ok=True, domain_status="complete", trace_ok=True, rule_errors=0) == "high"
    assert scoring.confidence(intel_ok=False, domain_status="partial", trace_ok=True, rule_errors=0) == "low"
    assert scoring.confidence(intel_ok=True, domain_status="failed", trace_ok=True, rule_errors=0) == "medium"


def test_a_failed_trace_or_crashed_rule_blocks_a_clean_verdict_and_caps_confidence():
    sc = scoring.score_rules([])
    assert scoring.classify(sc, intel_ok=True, domain_status="complete") == "no_known_threat_detected"
    assert scoring.classify(sc, intel_ok=True, domain_status="complete", trace_failed=True) == "needs_further_verification"
    assert scoring.classify(sc, intel_ok=True, domain_status="complete", rule_errors=1) == "needs_further_verification"
    assert scoring.confidence(intel_ok=True, domain_status="complete", trace_ok=False, rule_errors=0) == "medium"
    assert scoring.confidence(intel_ok=True, domain_status="complete", trace_ok=True, rule_errors=2) == "medium"
    # but real evidence still wins over missing checks
    strong = scoring.score_rules([R_("a", "strong", 45), R_("b", "moderate", 25)])
    assert scoring.classify(strong, intel_ok=False, domain_status="failed", trace_failed=True) == "high_risk"
