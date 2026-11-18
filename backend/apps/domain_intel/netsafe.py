"""SSRF-safe outbound HTTP(S) and TLS inspection.

Rules enforced on every request AND every redirect hop:
  * scheme must be http/https; port must be in the allow-list (80/443 by default)
  * no credentials in the URL
  * the host is resolved by us, and EVERY returned address must be globally routable
    (private, loopback, link-local incl. cloud metadata, CGNAT, ULA, multicast, reserved are refused,
    IPv4-in-IPv6 encodings are unwrapped first)
  * the connection is pinned to the validated IP (the hostname is never re-resolved by the socket
    layer, which defeats DNS rebinding); the original host is used for Host/SNI/cert checks
  * redirects are followed manually (max N), loops are detected, each hop is re-validated
  * connect/read timeouts, a total deadline, and a hard cap on response bytes
  * no cookies, no scripts executed, no content decoding, no rendering
"""
import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from django.conf import settings

USER_AGENT = "ScanSentryBot/1.0 (URL safety assessment; +https://scansentry.example/bot)"
REDIRECT_CODES = {301, 302, 303, 307, 308}
KEEP_HEADERS = ("server", "content-type", "location", "x-powered-by", "retry-after")


class BlockedDestination(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NoAddress(Exception):
    pass


# ---- address policy -------------------------------------------------------------------------
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        elif addr.sixtofour:
            addr = addr.sixtofour
        elif addr.teredo:
            addr = addr.teredo[1]
        elif addr in _NAT64:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return bool(addr.is_global and not addr.is_multicast)


def default_connector(ip: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((ip, port), timeout=timeout)


def verified_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---- pinned connections ------------------------------------------------------------------------
class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout, connector):
        super().__init__(host, port, timeout=timeout)
        self._ip, self._connector, self._t = ip, connector, timeout

    def connect(self):
        self.sock = self._connector(self._ip, self.port, self._t)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, timeout, connector, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip, self._connector, self._t, self._ctx = ip, connector, timeout, context

    def connect(self):
        raw = self._connector(self._ip, self.port, self._t)
        try:
            self.sock = self._ctx.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


# ---- results --------------------------------------------------------------------------------------
@dataclass
class FetchResult:
    url: str
    final_url: str | None = None
    status: int | None = None
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    redirects: list = field(default_factory=list)   # [{"url","status","location","ip"}]
    error: str | None = None            # blocked_destination|dns_failure|timeout|connection_failed|
                                        # tls_error|redirect_loop|too_many_redirects|invalid_url
    error_detail: str = ""
    tls_verified: bool | None = None    # False when the site only answered with certificate checks off
    tls_problem: str = ""
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")


class NetGuard:
    def __init__(self, dns_client, *, connector=None, context_factory=None, connect_timeout=None,
                 total_timeout=None, max_redirects=None, max_body=None, allowed_ports=(80, 443)):
        self.dns = dns_client
        self.connector = connector or default_connector
        self.context_factory = context_factory or verified_context
        self.connect_timeout = connect_timeout or settings.NETGUARD_CONNECT_TIMEOUT
        self.total_timeout = total_timeout or settings.NETGUARD_TOTAL_TIMEOUT
        self.max_redirects = settings.NETGUARD_MAX_REDIRECTS if max_redirects is None else max_redirects
        self.max_body = max_body or settings.NETGUARD_MAX_BODY_BYTES
        self.allowed_ports = tuple(allowed_ports)

    # -- policy -------------------------------------------------------------------------------
    def resolve_public(self, host: str) -> list[str]:
        """All addresses for host; raises BlockedDestination if ANY is non-public, NoAddress if none."""
        try:  # IP literals are validated directly; they never go through DNS
            ipaddress.ip_address(host.strip("[]"))
            addrs = [host.strip("[]")]
        except ValueError:
            addrs = self.dns.addresses(host)
        if not addrs:
            raise NoAddress(host)
        bad = [a for a in addrs if not ip_is_public(a)]
        if bad:
            raise BlockedDestination("The host resolves to a non-public network address.")
        return addrs

    def validate_target(self, url: str, *, require_https: bool = False):
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or (require_https and scheme != "https"):
            raise BlockedDestination("Only http(s) destinations are allowed.")
        if "@" in parts.netloc:
            raise BlockedDestination("Credentials in URLs are not allowed.")
        host = parts.hostname
        if not host:
            raise BlockedDestination("The URL has no host.")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            raise BlockedDestination("The URL has an invalid port.")
        if port not in self.allowed_ports:
            raise BlockedDestination(f"Port {port} is not permitted.")
        return parts, scheme, host, port

    def _connect(self, scheme, host, port, ips, ctx):
        last = None
        for ip in ips:
            conn = (_PinnedHTTPS(host, port, ip, self.connect_timeout, self.connector, ctx)
                    if scheme == "https" else
                    _PinnedHTTP(host, port, ip, self.connect_timeout, self.connector))
            try:
                conn.connect()
                return conn, ip
            except (OSError, ssl.SSLError) as exc:
                last = exc
                conn.close()
                if isinstance(exc, ssl.SSLError):
                    raise
        raise last or OSError("no address could be reached")

    # -- fetch ---------------------------------------------------------------------------------------
    def fetch(self, url: str, *, accept="text/html,*/*;q=0.5", max_body=None, require_https=False,
              read_body=True, method="GET", body=None, headers=None) -> FetchResult:
        """GET by default. Non-GET requests (used for provider APIs) never follow redirects."""
        result = FetchResult(url=url)
        deadline = time.monotonic() + self.total_timeout
        limit = max_body or self.max_body
        seen: set[str] = set()
        current = url

        for _ in range(self.max_redirects + 1):
            if current in seen:
                result.error, result.error_detail = "redirect_loop", "The redirect chain loops."
                return result
            seen.add(current)
            try:
                parts, scheme, host, port = self.validate_target(current, require_https=require_https)
                ips = self.resolve_public(host)
            except BlockedDestination as exc:
                result.error, result.error_detail = "blocked_destination", exc.reason
                return result
            except NoAddress:
                result.error, result.error_detail = "dns_failure", "The host name did not resolve."
                return result
            if time.monotonic() > deadline:
                result.error, result.error_detail = "timeout", "The overall time limit was reached."
                return result

            ctx = self.context_factory() if scheme == "https" else None
            try:
                try:
                    conn, ip = self._connect(scheme, host, port, ips, ctx)
                except ssl.SSLCertVerificationError as exc:
                    result.tls_verified, result.tls_problem = False, exc.verify_message or str(exc)
                    conn, ip = self._connect(scheme, host, port, ips, unverified_context())
                else:
                    if scheme == "https":
                        result.tls_verified = True if result.tls_verified is None else result.tls_verified
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                req_headers = {"Host": parts.netloc.rsplit("@", 1)[-1], "User-Agent": USER_AGENT,
                               "Accept": accept, "Accept-Encoding": "identity", "Connection": "close"}
                req_headers.update(headers or {})
                conn.request(method, path, body=body, headers=req_headers)
                resp = conn.getresponse()
                status = resp.status
                headers = {k.lower(): v[:300] for k, v in resp.getheaders() if k.lower() in KEEP_HEADERS}
                body = b""
                if read_body and not (method == "GET" and status in REDIRECT_CODES):
                    while len(body) < limit and time.monotonic() < deadline:
                        chunk = resp.read(min(4096, limit - len(body)))
                        if not chunk:
                            break
                        body += chunk
                    result.truncated = len(body) >= limit
                conn.close()
            except socket.timeout:
                result.error, result.error_detail = "timeout", "The server did not respond in time."
                return result
            except ssl.SSLError as exc:
                result.error, result.error_detail = "tls_error", exc.__class__.__name__
                return result
            except (OSError, http.client.HTTPException) as exc:
                result.error, result.error_detail = "connection_failed", exc.__class__.__name__
                return result

            hop = {"url": current, "status": status, "ip": ip, "location": headers.get("location")}
            result.redirects.append(hop)
            if method == "GET" and status in REDIRECT_CODES and headers.get("location"):
                if len(result.redirects) > self.max_redirects:
                    result.error, result.error_detail = "too_many_redirects", "Too many redirects."
                    return result
                current = urljoin(current, headers["location"])
                continue
            result.final_url, result.status, result.headers, result.body = current, status, headers, body
            return result

        result.error, result.error_detail = "too_many_redirects", "Too many redirects."
        return result
