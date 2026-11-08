import time
from datetime import datetime, timezone

import pytest

from apps.domain_intel.netsafe import BlockedDestination, ip_is_public
from apps.domain_intel.tlscheck import inspect_tls
from tests.netfakes import World, http_response, redirect, request_line

PUBLIC = "93.184.216.34"


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


# ---- address policy -----------------------------------------------------------------------------
@pytest.mark.parametrize("ip,expected", [
    ("93.184.216.34", True), ("8.8.8.8", True), ("2606:2800:220:1:248:1893:25c8:1946", True),
    ("127.0.0.1", False), ("127.1.2.3", False), ("10.0.0.5", False), ("172.16.5.5", False),
    ("192.168.1.1", False), ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False),
    ("224.0.0.1", False), ("255.255.255.255", False), ("192.0.2.1", False), ("198.18.0.1", False),
    ("::1", False), ("::", False), ("fe80::1", False), ("fc00::1", False), ("fd12:3456::1", False),
    ("ff02::1", False), ("::ffff:127.0.0.1", False), ("::ffff:10.1.1.1", False),
    ("::ffff:169.254.169.254", False), ("2002:7f00:0001::", False), ("64:ff9b::a00:1", False),
    ("not-an-ip", False), ("", False),
])
def test_ip_is_public(ip, expected):
    assert ip_is_public(ip) is expected


# ---- blocked destinations: refused AND never connected ----------------------------------------------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.8", "192.168.0.10", "169.254.169.254", "100.64.1.1",
                                "::1", "fd00::5", "::ffff:127.0.0.1"])
def test_host_resolving_to_internal_address_is_blocked_without_connecting(world, ip):
    world.dns.set("evil.example", "AAAA" if ":" in ip else "A", [ip])
    world.net.add(ip, 80, lambda r: http_response(200, "secret"))
    res = world.guard.fetch("http://evil.example/")
    assert res.error == "blocked_destination" and res.status is None
    assert world.net.connections == []


def test_one_private_record_among_public_ones_blocks_the_host(world):
    world.dns.set("mixed.example", "A", [PUBLIC, "10.0.0.1"])
    world.net.add(PUBLIC, 80, lambda r: http_response(200, "ok"))
    res = world.guard.fetch("http://mixed.example/")
    assert res.error == "blocked_destination" and world.net.connections == []


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
    "http://10.1.2.3/admin", "https://192.168.1.1/",
])
def test_ip_literal_internal_urls_blocked(world, url):
    res = world.guard.fetch(url)
    assert res.error == "blocked_destination" and world.net.connections == []


@pytest.mark.parametrize("url,why", [
    ("http://example.com:8080/", "port"), ("https://example.com:22/", "port"), ("http://example.com:6379/", "port"),
    ("ftp://example.com/", "scheme"), ("file:///etc/passwd", "scheme"), ("gopher://example.com/", "scheme"),
    ("http://user:pw@example.com/", "credentials"), ("http:///nohost", "host"),
])
def test_scheme_port_and_credential_policy(world, url, why):
    world.site("example.com", http=lambda r: http_response(200, "x"))
    res = world.guard.fetch(url)
    assert res.error == "blocked_destination", why
    assert world.net.connections == []


def test_unresolvable_host_reports_dns_failure(world):
    res = world.guard.fetch("http://nope.example/")
    assert res.error == "dns_failure" and world.net.connections == []


# ---- DNS rebinding --------------------------------------------------------------------------------------
def test_connection_is_pinned_to_the_validated_ip_so_rebinding_cannot_redirect_it(world):
    world.net.add(PUBLIC, 80, lambda r: http_response(200, "public"))
    world.net.add("127.0.0.1", 80, lambda r: http_response(200, "INTERNAL SECRET"))
    # first answer is public (passes validation); any later lookup would return loopback
    world.dns.address_script["rebind.example"] = [[PUBLIC], ["127.0.0.1"]]
    res = world.guard.fetch("http://rebind.example/")
    assert res.ok and res.text == "public"
    assert world.net.connections == [(PUBLIC, 80)]            # never touched loopback
    assert world.dns.address_calls.count("rebind.example") == 1  # resolved once, then pinned


def test_rebinding_on_a_redirect_hop_is_revalidated(world):
    world.site("a.example", http=lambda r: redirect("http://b.example/x"))
    world.dns.set("b.example", "A", ["127.0.0.1"])
    world.net.add("127.0.0.1", 80, lambda r: http_response(200, "INTERNAL"))
    res = world.guard.fetch("http://a.example/")
    assert res.error == "blocked_destination"
    assert ("127.0.0.1", 80) not in world.net.connections


# ---- redirects --------------------------------------------------------------------------------------------
def test_redirect_chain_to_final_page(world):
    world.site("a.example", "93.184.216.1", http=lambda r: redirect("https://b.example/start"))
    world.site("b.example", "93.184.216.2",
               https=lambda r: redirect("/landing") if "GET /start" in r else http_response(200, "landed"))
    res = world.guard.fetch("http://a.example/")
    assert res.ok and res.status == 200 and res.text == "landed"
    assert res.final_url == "https://b.example/landing"
    assert len(res.redirects) == 3


def test_redirect_loop_detected(world):
    world.site("loop.example", http=lambda r: redirect("http://loop.example/"))
    res = world.guard.fetch("http://loop.example/")
    assert res.error == "redirect_loop"


def test_too_many_redirects(world):
    counter = {"n": 0}

    def handler(r):
        counter["n"] += 1
        return redirect(f"http://deep.example/{counter['n']}")
    world.site("deep.example", http=handler)
    res = world.guard.fetch("http://deep.example/0")
    assert res.error == "too_many_redirects" and counter["n"] <= 7


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1/admin", "http://[::1]/",
    "http://example.org:8080/", "file:///etc/passwd", "gopher://example.org/", "ftp://example.org/x",
    "http://user:pw@example.org/",
])
def test_redirect_to_forbidden_target_is_blocked_before_connecting(world, target):
    world.site("start.example", http=lambda r: redirect(target))
    world.site("example.org", "93.184.216.9", http=lambda r: http_response(200, "ok"))
    world.net.add("169.254.169.254", 80, lambda r: http_response(200, "metadata"))
    world.net.add("127.0.0.1", 80, lambda r: http_response(200, "internal"))
    res = world.guard.fetch("http://start.example/")
    assert res.error == "blocked_destination"
    assert world.net.connections == [(PUBLIC, 80)]


# ---- limits ---------------------------------------------------------------------------------------------------
def test_response_size_is_capped(world):
    world.site("big.example", http=lambda r: http_response(200, "A" * 2_000_000))
    res = world.guard.fetch("http://big.example/", max_body=10_000)
    assert res.ok and len(res.body) == 10_000 and res.truncated


def test_slow_server_times_out(world):
    world.site("slow.example", http=lambda r: http_response(200, "late"))
    world.net.servers[(PUBLIC, 80)].delay = 2.0
    world.guard.connect_timeout = 0.3
    start = time.monotonic()
    res = world.guard.fetch("http://slow.example/")
    assert res.error == "timeout" and time.monotonic() - start < 1.5


def test_connection_refused_is_reported_not_raised(world):
    world.dns.set("closed.example", "A", [PUBLIC])
    res = world.guard.fetch("http://closed.example/")
    assert res.error == "connection_failed"


def test_requests_carry_no_cookies_or_credentials_and_identify_the_bot(world):
    srv = world.net.add(PUBLIC, 80, lambda r: http_response(200, "ok"))
    world.dns.set("hdr.example", "A", [PUBLIC])
    world.guard.fetch("http://hdr.example/p?q=1")
    req = srv.requests[0].lower()
    assert request_line(srv.requests[0]) == "GET /p?q=1 HTTP/1.1"
    assert "user-agent: scansentrybot" in req and "cookie" not in req and "authorization" not in req
    assert "accept-encoding: identity" in req


def test_invalid_certificate_still_reports_availability_but_flags_it(world):
    ctx = world.pki.server_context(["bad.example"], self_signed=True)
    world.site("bad.example", https=lambda r: http_response(200, "hello"), tls_ctx=ctx)
    res = world.guard.fetch("https://bad.example/")
    assert res.ok and res.tls_verified is False and res.tls_problem


def test_valid_certificate_marks_tls_verified(world):
    world.site("good.example", https=lambda r: http_response(200, "hello"))
    res = world.guard.fetch("https://good.example/")
    assert res.ok and res.tls_verified is True


# ---- TLS inspection ----------------------------------------------------------------------------------------------
def tls(world, host, **kw):
    return inspect_tls(host, world.guard, now=datetime.now(timezone.utc), **kw)


def test_tls_valid_certificate(world):
    world.site("ok.example", https=lambda r: b"")
    r = tls(world, "ok.example")
    assert r["status"] == "VALID" and r["https_available"] and not r["expiring_soon"]
    assert r["certificate"]["issuer_common_name"] == "Test CA"
    assert "ok.example" in r["certificate"]["san_dns_names"]
    assert 85 <= r["certificate"]["days_remaining"] <= 90 and r["protocol"].startswith("TLS")


def test_tls_expiring_soon(world):
    ctx = world.pki.server_context(["soon.example"], days_valid=5)
    world.site("soon.example", https=lambda r: b"", tls_ctx=ctx)
    r = tls(world, "soon.example")
    assert r["status"] == "VALID" and r["expiring_soon"] and "expires in" in r["message"]


def test_tls_expired_certificate(world):
    ctx = world.pki.server_context(["old.example"], not_before_days=-60, days_valid=-1)
    world.site("old.example", https=lambda r: b"", tls_ctx=ctx)
    r = tls(world, "old.example")
    assert r["status"] == "EXPIRED" and r["https_available"]
    assert r["certificate"]["days_remaining"] < 0          # details still reported


def test_tls_not_yet_valid_certificate(world):
    ctx = world.pki.server_context(["future.example"], not_before_days=10, days_valid=100)
    world.site("future.example", https=lambda r: b"", tls_ctx=ctx)
    assert tls(world, "future.example")["status"] == "NOT_YET_VALID"


def test_tls_hostname_mismatch(world):
    ctx = world.pki.server_context(["other.example"])
    world.site("wrong.example", https=lambda r: b"", tls_ctx=ctx)
    r = tls(world, "wrong.example")
    assert r["status"] == "HOSTNAME_MISMATCH"
    assert r["certificate"]["san_dns_names"] == ["other.example"]


def test_tls_self_signed_and_unknown_issuer(world):
    ss = world.pki.server_context(["self.example"], self_signed=True)
    world.site("self.example", "93.184.216.5", https=lambda r: b"", tls_ctx=ss)
    r = tls(world, "self.example")
    assert r["status"] == "SELF_SIGNED" and r["certificate"]["self_issued"]


def test_tls_no_https_when_port_closed(world):
    world.dns.set("plain.example", "A", [PUBLIC])
    r = tls(world, "plain.example")
    assert r["status"] == "NO_HTTPS" and r["https_available"] is False


def test_tls_never_connects_to_internal_hosts(world):
    world.dns.set("meta.example", "A", ["169.254.169.254"])
    world.net.add("169.254.169.254", 443, lambda r: b"", world.pki.server_context(["meta.example"]))
    r = tls(world, "meta.example")
    assert r["status"] == "UNAVAILABLE" and r.get("blocked") and world.net.connections == []


def test_tls_unresolvable_host_is_unavailable_not_invalid(world):
    r = tls(world, "ghost.example")
    assert r["status"] == "UNAVAILABLE" and r["certificate"] is None
