import json
from datetime import datetime, timedelta, timezone

import pytest
from django.core.cache import cache

from apps.core.models import AppConfiguration
from apps.domain_intel import status as st
from apps.domain_intel.dnscheck import DnsAnswer, check_dns
from apps.domain_intel.netsafe import FetchResult
from apps.domain_intel.normalize import InvalidDomainInput, normalize_domain_input
from apps.domain_intel.rdap import lookup_rdap, parse_rdap_domain
from apps.domain_intel.scoring import age_group, compute_health, confidence_from
from apps.domain_intel.website import check_website
from tests.netfakes import FakeDns, World, http_response, redirect

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
PUBLIC = "93.184.216.34"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()


# ---- normalisation -----------------------------------------------------------------------------------
@pytest.mark.parametrize("value,host,registrable", [
    ("example.com", "example.com", "example.com"),
    ("EXAMPLE.com.", "example.com", "example.com"),
    ("https://www.Example.com:8443/a/b?c=d#e", "www.example.com", "example.com"),
    ("login.secure.example.co.uk/path", "login.secure.example.co.uk", "example.co.uk"),
    ("http://sub.example.com.ng", "sub.example.com.ng", "example.com.ng"),
    ("https://bücher.de/straße", "xn--bcher-kva.de", "xn--bcher-kva.de"),
    ("user.github.io", "user.github.io", "github.io"),
    ("  example.org  ", "example.org", "example.org"),
])
def test_normalize_valid(value, host, registrable):
    n = normalize_domain_input(value)
    assert (n.host, n.registrable) == (host, registrable)


def test_normalize_idn_exposes_both_forms():
    n = normalize_domain_input("https://аpple.com")   # Cyrillic а
    assert n.is_idn and n.host.startswith("xn--") and n.display_host == "аpple.com"


@pytest.mark.parametrize("bad", [
    "", "   ", "localhost", "foo.local", "printer.lan", "db.internal", "x.test", "a.invalid", "x.onion",
    "127.0.0.1", "http://10.0.0.1/", "http://[::1]/", "2130706433", "0x7f000001", "http://169.254.169.254/",
    "justoneword", "ftp://example.com", "javascript:alert(1)", "exa mple.com", "http://", "com", "co.uk",
    "a" * 64 + ".com", "x" * 260 + ".com", "bad_char!.com", "exa\x00mple.com", "http://example.com:99999",
])
def test_normalize_rejects_non_public_or_malformed(bad):
    with pytest.raises(InvalidDomainInput):
        normalize_domain_input(bad)


# ---- registration status mapping (Scenario 6) ------------------------------------------------------------
@pytest.mark.parametrize("flags,expected", [
    (["client hold"], st.REGISTRAR_HOLD), (["clientHold"], st.REGISTRAR_HOLD),
    (["server hold"], st.REGISTRY_HOLD), (["serverHold"], st.REGISTRY_HOLD),
    (["serverHold", "clientHold"], st.REGISTRY_HOLD),
    (["redemption period"], st.REDEMPTION_PERIOD), (["pendingRestore"], st.REDEMPTION_PERIOD),
    (["pending delete"], st.PENDING_DELETION), (["pendingDelete", "serverHold"], st.PENDING_DELETION),
    (["inactive"], st.INACTIVE_OR_UNDELEGATED),
    (["ok"], st.REGISTERED_ACTIVE), (["active"], st.REGISTERED_ACTIVE), ([], st.REGISTERED_ACTIVE),
    (["client transfer prohibited"], st.REGISTERED_ACTIVE),
    (["server transfer prohibited", "client delete prohibited", "client update prohibited"], st.REGISTERED_ACTIVE),
    (["clientTransferProhibited", "clientHold"], st.REGISTRAR_HOLD),
])
def test_status_mapping(flags, expected):
    assert st.classify_registration(flags, now=NOW)[0] == expected


def test_transfer_lock_is_never_called_a_suspension():
    cls, why = st.classify_registration(["clientTransferProhibited", "serverTransferProhibited"], now=NOW)
    assert cls == st.REGISTERED_ACTIVE and "do not mean suspension" in why


def test_expired_only_when_the_expiry_date_is_evidence():
    past, future = NOW - timedelta(days=30), NOW + timedelta(days=30)
    assert st.classify_registration(["ok"], expires_at=past, now=NOW)[0] == st.EXPIRED_OR_NOT_RENEWED
    assert st.classify_registration(["ok"], expires_at=future, now=NOW)[0] == st.REGISTERED_ACTIVE
    assert st.classify_registration(["ok"], expires_at=None, now=NOW)[0] == st.REGISTERED_ACTIVE
    # a hold is more specific than "expired"
    assert st.classify_registration(["serverHold"], expires_at=past, now=NOW)[0] == st.REGISTRY_HOLD


# ---- RDAP parsing -----------------------------------------------------------------------------------------------
SAMPLE = {
    "objectClassName": "domain", "ldhName": "EXAMPLE.COM",
    "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
               {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:44Z"},
               {"eventAction": "last update of RDAP database", "eventDate": "2026-11-07T00:00:00Z"}],
    "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "A.IANA-SERVERS.NET"}],
    "secureDNS": {"delegationSigned": True},
    "entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                           ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]]]}],
}


def test_parse_rdap_full_record():
    d = parse_rdap_domain(SAMPLE, now=NOW)
    assert d["created_at"].startswith("1995-08-14") and d["expires_at"].startswith("2027-08-13")
    assert d["updated_at"].startswith("2025-08-14")
    assert d["age_days"] == (NOW - datetime(1995, 8, 14, 4, tzinfo=timezone.utc)).days
    assert d["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert d["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert d["raw_status_flags"] == SAMPLE["status"] and d["status"] == st.REGISTERED_ACTIVE
    assert d["dnssec_signed"] is True and d["not_disclosed"] == []
    assert "does not prove" in d["age_note"]


def test_parse_redacted_rdap_returns_unknown_not_invented_values():
    d = parse_rdap_domain({"ldhName": "X.NG", "status": ["active"], "events": [], "entities": []}, now=NOW)
    assert d["created_at"] is None and d["age_days"] is None and d["registrar"] is None
    assert set(d["not_disclosed"]) == {"registration_date", "expiration_date", "registrar"}


def test_reregistration_resets_the_effective_age_and_is_reported():
    data = {**SAMPLE, "events": SAMPLE["events"] + [{"eventAction": "reregistration", "eventDate": "2026-10-01T00:00:00Z"}]}
    d = parse_rdap_domain(data, now=NOW)
    assert d["age_days"] == 37 and d["reregistered_at"].startswith("2026-10-01") and d["created_at"].startswith("1995")


def test_parse_tolerates_garbage_fields():
    d = parse_rdap_domain({"events": [{"eventAction": "registration", "eventDate": "not a date"}, "junk" and {}],
                           "status": None, "nameservers": None, "entities": None}, now=NOW)
    assert d["created_at"] is None and d["nameservers"] == []


# ---- RDAP lookup flow ----------------------------------------------------------------------------------------------
BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["org"], ["http://insecure.example/"]]]}


class StubGuard:
    def __init__(self, table):
        self.table, self.calls = table, []

    def fetch(self, url, **kw):
        self.calls.append(url)
        r = self.table.get(url)
        return r() if callable(r) else (r or FetchResult(url=url, error="dns_failure", error_detail="no stub"))


def ok(url, body, status=200):
    return FetchResult(url=url, final_url=url, status=status, body=json.dumps(body).encode() if not isinstance(body, bytes) else body)


BOOT_URL = "https://data.iana.org/rdap/dns.json"
COM_URL = "https://rdap.verisign.com/com/v1/domain/example.com"


def test_rdap_success_uses_bootstrap_and_registrable_domain():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, SAMPLE)})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert r["ok"] and r["status"] == st.REGISTERED_ACTIVE and r["source"] == COM_URL
    assert r["data"]["registrar"] and g.calls == [BOOT_URL, COM_URL]


def test_rdap_bootstrap_is_cached():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, SAMPLE)})
    lookup_rdap("example.com", "com", g, now=NOW)
    lookup_rdap("example.com", "com", g, now=NOW)
    assert g.calls.count(BOOT_URL) == 1


def test_rdap_hold_status_flows_through():
    held = {**SAMPLE, "status": ["client hold", "client transfer prohibited"]}
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, held)})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert r["status"] == st.REGISTRAR_HOLD and r["data"]["raw_status_flags"] == held["status"]


def test_rdap_404_is_not_found_with_registry_evidence():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, b"{}", 404)})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert r["ok"] and r["status"] == st.NOT_FOUND and r["data"]["created_at"] is None


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_rdap_server_trouble_is_lookup_unavailable(status):
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, b"{}", status)})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert not r["ok"] and r["status"] == st.LOOKUP_UNAVAILABLE and r["data"] is None


def test_rdap_network_error_is_lookup_unavailable():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP),
                   COM_URL: FetchResult(url=COM_URL, error="timeout", error_detail="slow")})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert r["status"] == st.LOOKUP_UNAVAILABLE and "timeout" in r["error"]


def test_rdap_unparseable_and_odd_statuses_are_unknown():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, b"<html>nope</html>")})
    assert lookup_rdap("example.com", "com", g, now=NOW)["status"] == st.UNKNOWN
    cache.clear()
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, b"{}", 403)})
    assert lookup_rdap("example.com", "com", g, now=NOW)["status"] == st.UNKNOWN


def test_tld_without_rdap_is_unknown_not_a_guess():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP)})
    r = lookup_rdap("example.zz", "zz", g, now=NOW)
    assert r["status"] == st.UNKNOWN and r["rdap_supported"] is False and r["data"] is None
    assert g.calls == [BOOT_URL]


def test_insecure_rdap_servers_in_bootstrap_are_ignored():
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP)})
    assert lookup_rdap("example.org", "org", g, now=NOW)["rdap_supported"] is False


def test_bootstrap_failure_is_lookup_unavailable():
    g = StubGuard({BOOT_URL: FetchResult(url=BOOT_URL, error="timeout", error_detail="x")})
    r = lookup_rdap("example.com", "com", g, now=NOW)
    assert r["status"] == st.LOOKUP_UNAVAILABLE and r["data"] is None


def test_configured_fallback_provider_is_used_only_when_tld_unlisted(settings):
    settings.RDAP_PROVIDER_CONFIG = {"fallback_base": "https://rdap.fallback.test"}
    url = "https://rdap.fallback.test/domain/example.zz"
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), url: ok(url, SAMPLE)})
    r = lookup_rdap("example.zz", "zz", g, now=NOW)
    assert r["ok"] and r["source"] == url
    cache.clear()
    g = StubGuard({BOOT_URL: ok(BOOT_URL, BOOTSTRAP), COM_URL: ok(COM_URL, SAMPLE)})
    assert lookup_rdap("example.com", "com", g, now=NOW)["source"] == COM_URL


# ---- DNS health ---------------------------------------------------------------------------------------------------------
def dns_zone(extra=None):
    z = {("example.com", "A"): [PUBLIC], ("example.com", "AAAA"): ["2606:2800:220:1::1"],
         ("example.com", "NS"): ["a.ns.example.net.", "b.ns.example.net."]}
    z.update(extra or {})
    return FakeDns(z)


def test_healthy_dns_without_mx_is_not_penalised():
    r = check_dns("example.com", dns_zone())
    assert r["status"] == "resolves" and r["issues"] == [] and r["mx_present"] is False
    assert r["records"]["A"] == [PUBLIC] and r["dnssec_ds_present"] is False


def test_dns_variants():
    assert check_dns("example.com", dns_zone())["status"] == "resolves"
    assert check_dns("gone.example", FakeDns())["status"] == "nxdomain"
    no_addr = FakeDns({("x.example", "NS"): ["a.ns.", "b.ns."]})
    r = check_dns("x.example", no_addr)
    assert r["status"] == "no_address_records" and r["issues"][0]["code"] == "no_address_records"
    one_ns = FakeDns({("x.example", "A"): [PUBLIC], ("x.example", "NS"): ["only.ns."]})
    assert any(i["code"] == "single_nameserver" for i in check_dns("x.example", one_ns)["issues"])
    signed = dns_zone({("example.com", "DS"): ["12345 13 2 ABCDEF"]})
    assert check_dns("example.com", signed)["dnssec_ds_present"] is True
    cname = FakeDns({("www.x.example", "CNAME"): ["x.example."]})
    assert check_dns("www.x.example", cname)["status"] == "resolves"


def test_dns_total_failure_is_lookup_failed_not_nxdomain():
    z = {(n, t): DnsAnswer("timeout", error="t") for n in ("x.example",) for t in
         ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "DS")}
    r = check_dns("x.example", FakeDns(z))
    assert r["status"] == "lookup_failed" and r["issues"][0]["code"] == "dns_lookup_failed"


pytestmark = pytest.mark.django_db


# ---- scoring ---------------------------------------------------------------------------------------------------------------
GOOD_DNS = {"status": "resolves", "issues": [], "records": {"A": [PUBLIC], "AAAA": [], "CNAME": [], "NS": ["a", "b"]}}
GOOD_TLS = {"status": "VALID", "expiring_soon": False}
GOOD_WEB = {"hosting_status": st.WEBSITE_RESPONDING, "http_status": 200}


def test_perfect_health_scores_100_with_high_confidence():
    h = compute_health(reg_status=st.REGISTERED_ACTIVE, reg_data={"nameservers": ["a", "b"]},
                       dns=GOOD_DNS, tls=GOOD_TLS, website=GOOD_WEB)
    assert h["score"] == 100 and h["label"] == "good" and h["not_assessed"] == [] and h["coverage"] == 1.0
    assert confidence_from(h["coverage"]) == "high" and "honest" in h["note"]


def test_missing_components_are_excluded_not_treated_as_good_or_bad():
    h = compute_health(reg_status=st.LOOKUP_UNAVAILABLE, reg_data=None, dns=GOOD_DNS,
                       tls={"status": "UNAVAILABLE"}, website=None)
    assert "registration" in h["not_assessed"] and "tls" in h["not_assessed"] and "website" in h["not_assessed"]
    assert h["score"] is not None and h["coverage"] < 0.55 and confidence_from(h["coverage"]) == "low"
    nothing = compute_health(reg_status=st.UNKNOWN, reg_data=None, dns=None, tls=None, website=None)
    assert nothing["score"] is None and nothing["label"] is None


def test_unhealthy_domain_scores_low():
    h = compute_health(reg_status=st.REGISTRAR_HOLD, reg_data=None, dns={"status": "nxdomain", "issues": [], "records": {}},
                       tls={"status": "NO_HTTPS"}, website={"hosting_status": st.DNS_FAILURE})
    assert h["score"] < 30 and h["label"] == "poor"


def test_expired_certificate_and_error_pages_lower_health_without_zeroing_it():
    base = compute_health(reg_status=st.REGISTERED_ACTIVE, reg_data={"nameservers": ["a", "b"]}, dns=GOOD_DNS,
                          tls=GOOD_TLS, website=GOOD_WEB)["score"]
    expired = compute_health(reg_status=st.REGISTERED_ACTIVE, reg_data={"nameservers": ["a", "b"]}, dns=GOOD_DNS,
                             tls={"status": "EXPIRED"}, website={**GOOD_WEB, "http_status": 503})["score"]
    assert 40 < expired < base


def test_weights_are_configurable_and_versioned():
    AppConfiguration.objects.create(key="domain.health_weights", value={"registration": 100, "dns": 0, "tls": 0,
                                                                          "website": 0, "configuration": 0})
    h = compute_health(reg_status=st.REGISTERED_ACTIVE, reg_data=None, dns=None, tls=None, website=None)
    assert h["score"] == 100 and h["version"] == "health-1"


@pytest.mark.django_db
def test_age_groups_and_threshold_override():
    assert [age_group(x) for x in (None, 5, 29, 30, 179, 180, 1824, 1825, 9000)] == [
        "unknown", "newly_registered", "newly_registered", "recently_registered", "recently_registered",
        "established", "established", "long_established", "long_established"]
    AppConfiguration.objects.create(key="domain.age_thresholds_days", value={"newly_registered": 90})
    assert age_group(60) == "newly_registered"


# ---- website / hosting classification --------------------------------------------------------------------------------------
@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def web(world, host="site.example"):
    return check_website(host, world.guard)


def test_responding_site(world):
    world.site("site.example", https=lambda r: http_response(200, "<h1>Hello</h1>"))
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_RESPONDING and r["http_status"] == 200 and r["https_works"]
    assert r["https_certificate_verified"] is True and r["confidence"] == "high" and r["heuristic"] is None


@pytest.mark.parametrize("code", [403, 404, 500, 502, 503])
def test_error_status_alone_is_never_suspension(world, code):
    world.site("site.example", https=lambda r: http_response(code, "Error page", reason="Err"))
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_RESPONDING and r["http_status"] == code
    assert any("alone does not show suspension" in e for e in r["evidence"]) or code < 400


def test_strong_suspension_phrase_is_labelled_heuristic_with_medium_confidence(world):
    world.site("site.example", https=lambda r: http_response(403, "<h1>This Account has been Suspended</h1>"))
    r = web(world)
    assert r["hosting_status"] == st.HOSTING_SUSPENSION_INDICATOR_DETECTED
    assert r["heuristic"] is True and r["confidence"] == "medium" and "this account has been suspended" in r["evidence"][0]


def test_weak_phrase_needs_a_matching_status_and_is_only_suspected(world):
    world.site("site.example", https=lambda r: http_response(503, "Site suspended? contact your hosting provider"))
    r = web(world)
    assert r["hosting_status"] == st.HOSTING_SUSPENSION_SUSPECTED and r["confidence"] == "low"
    world2 = World(world.pki.tmp)
    world2.site("site.example", https=lambda r: http_response(200, "We suspended our newsletter last year"))
    assert web(world2)["hosting_status"] == st.WEBSITE_RESPONDING


def test_no_output_ever_claims_confirmed_suspension(world):
    world.site("site.example", https=lambda r: http_response(403, "This account has been suspended"))
    assert "confirmed" not in json.dumps(web(world)).lower()


def test_dns_failure_status(world):
    r = web(world, "nowhere.example")
    assert r["hosting_status"] == st.DNS_FAILURE and r["confidence"] == "high"


def test_unreachable_server_is_unavailable_not_suspended(world):
    world.dns.set("site.example", "A", [PUBLIC])  # resolves, nothing listening
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_UNAVAILABLE and r["https_works"] is False


def test_timeout_is_unavailable_not_suspended(world):
    world.site("site.example", https=lambda r: http_response(200, "late"))
    world.net.servers[(PUBLIC, 443)].delay = 2.0
    world.guard.connect_timeout = 0.3
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_UNAVAILABLE


def test_internal_address_is_not_contacted_and_marked_unassessed(world):
    world.dns.set("site.example", "A", ["10.0.0.9"])
    world.net.add("10.0.0.9", 443, lambda r: http_response(200, "internal"))
    r = web(world)
    assert r["hosting_status"] == st.HOSTING_UNKNOWN and r.get("blocked") and world.net.connections == []


def test_redirect_loop_is_reported(world):
    world.site("site.example", https=lambda r: redirect("https://site.example/"), http=lambda r: redirect("http://site.example/"))
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_UNAVAILABLE and r.get("redirect_loop")


def test_http_only_site_and_invalid_certificate_are_distinguished(world):
    world.site("site.example", http=lambda r: http_response(200, "plain http"))
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_RESPONDING and r["https_works"] is False
    w2 = World(world.pki.tmp)
    w2.site("site.example", https=lambda r: http_response(200, "ok"),
            tls_ctx=w2.pki.server_context(["site.example"], self_signed=True))
    r2 = web(w2)
    assert r2["https_works"] and r2["https_certificate_verified"] is False and r2["https_certificate_problem"]


def test_parked_page_is_noted_without_judging(world):
    world.site("site.example", https=lambda r: http_response(200, "<p>This domain is for sale!</p>"))
    r = web(world)
    assert r["hosting_status"] == st.WEBSITE_RESPONDING and "for sale" in r["parked_indicator"]


def test_only_the_site_root_is_requested(world):
    srv = world.net.add(PUBLIC, 443, lambda r: http_response(200, "ok"), world.pki.server_context(["site.example"]))
    world.dns.set("site.example", "A", [PUBLIC])
    check_website("site.example", world.guard)
    assert srv.requests and srv.requests[0].startswith("GET / HTTP/1.1")
