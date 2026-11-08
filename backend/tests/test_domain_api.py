import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework.throttling import AnonRateThrottle

from apps.core.models import AppConfiguration
from apps.domain_intel import service
from apps.domain_intel import status as st
from apps.domain_intel.dnscheck import DnsAnswer
from apps.domain_intel.models import DomainAssessment, DomainLookup
from apps.domain_intel.rdap import parse_rdap_domain
from tests.netfakes import World, http_response, request_line
from tests.test_domain_unit import SAMPLE

pytestmark = pytest.mark.django_db
URL = "/api/v1/domains/analyze/"
PUBLIC = "93.184.216.34"


def rdap_result(flags=None, **over):
    now = datetime.now(timezone.utc)
    data = parse_rdap_domain({**SAMPLE, **({"status": flags} if flags is not None else {}), **over}, now=now)
    return {"ok": True, "status": data["status"], "data": data, "source": "https://rdap.test/domain/shop.com",
            "error": None, "observed_at": now.isoformat()}


@pytest.fixture
def env(monkeypatch, tmp_path):
    cache.clear()
    w = World(tmp_path)
    monkeypatch.setattr(service, "build_dns_client", lambda: w.dns)
    monkeypatch.setattr(service, "build_guard", lambda dns=None: w.guard)
    state = {"rdap": rdap_result(), "calls": 0}

    def fake_rdap(registrable, tld, guard, now=None):
        state["calls"] += 1
        return state["rdap"]
    monkeypatch.setattr(service, "lookup_rdap", fake_rdap)
    return SimpleNamespace(world=w, state=state)


def publish(env, host="shop.com", body="<h1>Shop</h1>", status=200):
    w = env.world
    w.site(host, https=lambda r: http_response(status, body))
    w.dns.set(host, "NS", ["a.ns.example.net.", "b.ns.example.net."])
    return w


def analyze(client, value="shop.com", **extra):
    return client.post(URL, {"value": value, **extra}, format="json")


# ---- Scenario 5: registration report -----------------------------------------------------------------------
def test_full_assessment_report(api, env):
    w = publish(env)
    r = analyze(api, "https://shop.com/reset?token=SECRET123")
    assert r.status_code == 200 and r["Cache-Control"] == "no-store"
    d = r.data
    assert d["domain"] == "shop.com" and d["registrable_domain"] == "shop.com" and d["cached"] is False
    reg = d["registration"]
    assert reg["created_at"].year == 1995 and reg["age_days"] > 10000 and reg["age_group"] == "long_established"
    assert reg["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert reg["raw_status_flags"] == SAMPLE["status"] and reg["status"] == st.REGISTERED_ACTIVE
    assert reg["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"] and "does not prove" in reg["age_note"]
    assert d["dns"]["status"] == "resolves" and d["tls"]["status"] == "VALID"
    assert d["website"]["hosting_status"] == st.WEBSITE_RESPONDING and d["website"]["http_status"] == 200
    assert d["scores"]["domain_health"]["score"] == 100 and d["scores"]["security_risk"] is None
    assert d["completion_status"] == "complete" and d["missing_checks"] == [] and d["confidence"] == "high"
    assert len(d["limitations"]) >= 3
    obs = DomainAssessment.objects.get().observations
    assert sorted(o.observation_type for o in obs.all()) == ["dns", "http", "rdap", "tls"]
    # only the site root is requested: the user's path and query (which may hold secrets) never leave
    sent = [q for srv in w.net.servers.values() for q in srv.requests]
    assert sent and all(request_line(q) == "GET / HTTP/1.1" for q in sent)
    assert "SECRET123" not in json.dumps(sent)


def test_response_never_uses_a_safety_claim(api, env):
    publish(env)
    assert "safe" not in json.dumps(analyze(api).data, default=str).lower()


# ---- Scenario 6: hold vs lock ---------------------------------------------------------------------------------
@pytest.mark.parametrize("flags,expected", [
    (["client hold", "client transfer prohibited"], st.REGISTRAR_HOLD),
    (["server hold"], st.REGISTRY_HOLD),
    (["client transfer prohibited", "server transfer prohibited"], st.REGISTERED_ACTIVE),
])
def test_hold_and_lock_classification_through_the_api(api, env, flags, expected):
    publish(env)
    env.state["rdap"] = rdap_result(flags)
    reg = analyze(api).data["registration"]
    assert reg["status"] == expected and reg["raw_status_flags"] == flags
    if expected == st.REGISTERED_ACTIVE:
        assert "do not mean suspension" in reg["status_explanation"]


# ---- Scenario 7: incomplete data --------------------------------------------------------------------------------
def test_rdap_outage_is_reported_not_fabricated(api, env):
    publish(env)
    env.state["rdap"] = {"ok": False, "status": st.LOOKUP_UNAVAILABLE, "data": None, "source": None,
                         "error": "timeout: slow", "observed_at": datetime.now(timezone.utc).isoformat()}
    d = analyze(api).data
    reg = d["registration"]
    assert reg["status"] == st.LOOKUP_UNAVAILABLE and reg["created_at"] is None and reg["age_days"] is None
    assert reg["registrar"] is None and reg["age_group"] == "unknown" and reg["raw_status_flags"] == []
    assert d["completion_status"] == "partial" and d["missing_checks"][0]["check"] == "rdap"
    assert "registration" in d["scores"]["domain_health"]["not_assessed"]
    assert d["scores"]["domain_health"]["score"] is not None      # still scored from what was checked
    a = DomainAssessment.objects.get()
    assert (a.cache_expires_at - a.checked_at).total_seconds() <= 15 * 60 + 1   # short cache for incomplete data


def test_dns_outage_is_missing_not_nxdomain(api, env):
    w = publish(env)
    for t in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "DS"):
        w.dns.set("shop.com", t, DnsAnswer("timeout", error="t"))
    d = analyze(api).data
    assert d["dns"]["status"] == "lookup_failed"
    assert any(m["check"] == "dns" for m in d["missing_checks"]) and d["completion_status"] != "complete"


def test_a_crashing_check_becomes_a_provider_error_not_a_500_or_a_clean_result(api, env, monkeypatch):
    publish(env)
    monkeypatch.setattr(service, "check_dns", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    r = analyze(api)
    assert r.status_code == 200
    assert r.data["dns"] is None
    assert {"check": "dns", "error": "RuntimeError"} in r.data["provider_errors"]
    assert any(m["check"] == "dns" for m in r.data["missing_checks"]) and r.data["completion_status"] == "partial"


def test_slow_check_times_out_and_is_reported(api, env, monkeypatch, settings):
    publish(env)
    settings.DOMAIN_CHECK_TIMEOUT = 0.3
    monkeypatch.setattr(service, "check_dns", lambda *a, **k: time.sleep(1.5))
    start = time.monotonic()
    r = analyze(api)
    assert time.monotonic() - start < 1.2
    assert {"check": "dns", "error": "timeout"} in r.data["provider_errors"]


def test_no_checks_possible_is_a_failed_assessment_with_no_score(api, env):
    env.state["rdap"] = {"ok": False, "status": st.LOOKUP_UNAVAILABLE, "data": None, "source": None,
                         "error": "down", "observed_at": datetime.now(timezone.utc).isoformat()}
    d = analyze(api, "ghost-domain.com").data      # nothing published in DNS
    assert d["dns"]["status"] == "nxdomain"
    assert d["website"]["hosting_status"] == st.DNS_FAILURE
    assert d["scores"]["domain_health"]["score"] is not None   # nxdomain/dns failure are real, scoreable facts
    assert d["registration"]["status"] == st.LOOKUP_UNAVAILABLE


# ---- SSRF through the API ------------------------------------------------------------------------------------------------
def test_domain_resolving_to_an_internal_address_is_never_contacted(api, env):
    w = env.world
    w.dns.set("internal-looking.com", "A", ["169.254.169.254"])
    w.net.add("169.254.169.254", 80, lambda r: http_response(200, "metadata"))
    w.net.add("169.254.169.254", 443, lambda r: http_response(200, "metadata"), w.pki.server_context(["internal-looking.com"]))
    r = analyze(api, "internal-looking.com")
    assert r.status_code == 200 and w.net.connections == []
    assert r.data["tls"]["status"] == "UNAVAILABLE" and r.data["website"]["hosting_status"] == st.HOSTING_UNKNOWN
    checks = {m["check"] for m in r.data["missing_checks"]}
    assert {"tls", "website"} <= checks


@pytest.mark.parametrize("value", [
    "localhost", "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "10.0.0.1",
    "printer.local", "intranet", "file:///etc/passwd", "gopher://example.com", "javascript:alert(1)", "",
    "exa mple.com", "http://2130706433/",
])
def test_non_public_or_malformed_input_is_rejected_before_any_network_activity(api, env, value):
    r = analyze(api, value)
    assert r.status_code == 400 and r.data["error"]["code"] == "validation_error"
    assert env.world.net.connections == [] and env.world.dns.address_calls == [] and DomainAssessment.objects.count() == 0


def test_missing_or_oversized_input_rejected(api, env):
    assert api.post(URL, {}, format="json").status_code == 400
    assert analyze(api, "a" * 3000).status_code == 400


def test_idn_lookalike_is_reported_with_both_forms(api, env):
    publish(env, "xn--pple-43d.com")
    d = analyze(api, "https://аpple.com").data
    assert d["domain"] == "xn--pple-43d.com" and d["display_domain"] == "аpple.com"


# ---- caching, refresh, history ----------------------------------------------------------------------------------------------------
def test_results_are_cached_and_refresh_is_for_signed_in_users_only(api, auth_client, env):
    publish(env)
    first = analyze(api).data
    conns = len(env.world.net.connections)
    second = analyze(api).data
    assert second["cached"] is True and second["id"] == first["id"] and len(env.world.net.connections) == conns
    assert analyze(api, refresh=True).data["cached"] is True            # anonymous refresh ignored
    assert env.state["calls"] == 1
    env.state["rdap"] = rdap_result(["client hold"])
    fresh = analyze(auth_client, refresh=True).data
    assert fresh["cached"] is False and fresh["id"] != first["id"] and env.state["calls"] == 2
    assert fresh["registration"]["status"] == st.REGISTRAR_HOLD
    assert DomainAssessment.objects.count() == 2    # earlier run kept: history can be compared


def test_expired_cache_triggers_a_new_assessment(api, env):
    publish(env)
    first = analyze(api).data
    DomainAssessment.objects.update(cache_expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    assert analyze(api).data["id"] != first["id"]


def test_history_is_private_and_recorded(auth_client, other_client, api, env):
    publish(env)
    analyze(auth_client)
    analyze(auth_client)                      # cached
    analyze(api)                              # anonymous: not recorded
    h = auth_client.get("/api/v1/domains/history/")
    assert h.status_code == 200 and h.data["count"] == 2
    assert [x["served_from_cache"] for x in h.data["results"]] == [True, False]
    assert h.data["results"][0]["domain"] == "shop.com" and h.data["results"][0]["domain_health_score"] == 100
    assert other_client.get("/api/v1/domains/history/").data["count"] == 0
    assert api.get("/api/v1/domains/history/").status_code == 401
    assert auth_client.get("/api/v1/domains/history/?domain=nothere").data["count"] == 0
    assert DomainLookup.objects.count() == 2


def test_assessment_detail_by_id(api, env):
    publish(env)
    d = analyze(api).data
    got = api.get(f"/api/v1/domains/assessments/{d['id']}/")
    assert got.status_code == 200 and got.data["domain"] == "shop.com"
    assert got.data["registration"]["raw_status_flags"] == d["registration"]["raw_status_flags"]
    assert api.get("/api/v1/domains/assessments/00000000-0000-0000-0000-000000000000/").status_code == 404
    assert api.get("/api/v1/domains/assessments/not-a-uuid/").status_code == 404


# ---- limits ------------------------------------------------------------------------------------------------------------------------------
def test_anonymous_checker_is_rate_limited(api, env, monkeypatch):
    publish(env)
    from apps.domain_intel.views import DomainAnonThrottle
    monkeypatch.setitem(DomainAnonThrottle.THROTTLE_RATES, "domain_anon", "2/hour")
    cache.clear()
    codes = [analyze(api).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes[2:]


def test_plan_lookup_limits_are_enforced_on_the_backend(auth_client, api, env):
    publish(env)
    AppConfiguration.objects.create(key="default_entitlements", value={"domain.lookups.daily_limit": 2})
    assert analyze(auth_client).status_code == 200 and analyze(auth_client).status_code == 200
    blocked = analyze(auth_client)
    assert blocked.status_code == 403 and blocked.data["error"]["code"] == "limit_reached"
    assert analyze(api).status_code == 200      # the public checker has its own rate limit


def test_cache_duration_is_admin_configurable(api, env):
    publish(env)
    AppConfiguration.objects.create(key="domain.cache_hours", value=1)
    d = analyze(api).data
    a = DomainAssessment.objects.get()
    assert abs((a.cache_expires_at - a.checked_at).total_seconds() - 3600) < 2


# ---- admin -----------------------------------------------------------------------------------------------------------------------------------
def test_admin_can_inspect_assessments_read_only(client, api, env):
    from django.contrib.auth import get_user_model
    publish(env)
    a = analyze(api).data
    su = get_user_model().objects.create_superuser("root@example.com", "Str0ng-Passphrase-42")
    client.force_login(su)
    assert client.get("/admin/domain_intel/domainassessment/").status_code == 200
    page = client.get(f"/admin/domain_intel/domainassessment/{a['id']}/change/")
    assert page.status_code == 200 and b"client delete prohibited" in page.content
    assert client.get("/admin/domain_intel/domainlookup/").status_code == 200
    assert client.get("/admin/domain_intel/domainassessment/add/").status_code == 403


def test_assess_domain_command_prints_a_summary_and_rejects_bad_input(env, capsys):
    from django.core.management import call_command
    from django.core.management.base import CommandError
    publish(env)
    call_command("assess_domain", "shop.com")
    out = capsys.readouterr().out
    assert "Registration:      REGISTERED_ACTIVE" in out and "TLS:               VALID" in out
    call_command("assess_domain", "shop.com", "--json")
    assert json.loads(capsys.readouterr().out)["domain"] == "shop.com"
    with pytest.raises(CommandError):
        call_command("assess_domain", "127.0.0.1")
