"""A fake internet for network-safety tests: scripted DNS, in-memory servers (plain and TLS),
and a record of every connection attempt."""
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from apps.domain_intel.dnscheck import DnsAnswer
from apps.domain_intel.netsafe import NetGuard


# ---- DNS ------------------------------------------------------------------------------------------
class FakeDns:
    """zone: {(name, rtype): DnsAnswer | list[str]}.  addr_script lets a test change answers per call."""

    def __init__(self, zone=None):
        self.zone = {}
        for (name, rtype), v in (zone or {}).items():
            self.zone[(name, rtype)] = v
        self.address_script = {}          # host -> list of address-lists, consumed one per call
        self.address_calls = []

    def set(self, name, rtype, value):
        self.zone[(name, rtype)] = value

    def resolve(self, name, rtype):
        v = self.zone.get((name, rtype))
        if v is None:
            if any(n == name for (n, _t) in self.zone):
                return DnsAnswer("nodata")
            return DnsAnswer("nxdomain")
        if isinstance(v, DnsAnswer):
            return v
        return DnsAnswer("ok", list(v))

    def addresses(self, host):
        self.address_calls.append(host)
        script = self.address_script.get(host)
        if script:
            return script.pop(0) if len(script) > 1 else script[0]
        out = []
        for rtype in ("A", "AAAA"):
            a = self.resolve(host, rtype)
            if a.status == "ok":
                out.extend(a.records)
        return out


# ---- servers ----------------------------------------------------------------------------------------
class FakeServer:
    def __init__(self, handler=None, tls_ctx=None, delay=0.0):
        self.handler, self.tls_ctx, self.delay = handler, tls_ctx, delay
        self.requests: list[str] = []

    def serve(self, sock):
        try:
            if self.tls_ctx is not None:
                sock = self.tls_ctx.wrap_socket(sock, server_side=True)
            if self.handler is None:
                time.sleep(0.2)
                return
            data = b""
            sock.settimeout(3)
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                data += chunk
            text = data.decode("latin-1")
            self.requests.append(text)
            if self.delay:
                time.sleep(self.delay)
            sock.sendall(self.handler(text))
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass


class FakeNetwork:
    def __init__(self):
        self.servers: dict[tuple[str, int], FakeServer] = {}
        self.connections: list[tuple[str, int]] = []
        self._lock = threading.Lock()

    def add(self, ip, port, handler=None, tls_ctx=None, delay=0.0) -> FakeServer:
        srv = FakeServer(handler, tls_ctx, delay)
        self.servers[(ip, port)] = srv
        return srv

    def connect(self, ip, port, timeout):
        with self._lock:
            self.connections.append((ip, port))
        srv = self.servers.get((ip, port))
        if srv is None:
            raise ConnectionRefusedError(111, "refused")
        client, server = socket.socketpair()
        client.settimeout(timeout)
        threading.Thread(target=srv.serve, args=(server,), daemon=True).start()
        return client


def http_response(status=200, body="", headers=None, reason="OK") -> bytes:
    body_b = body.encode() if isinstance(body, str) else body
    h = {"Content-Length": str(len(body_b)), "Content-Type": "text/html", "Connection": "close"}
    h.update(headers or {})
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    return head.encode() + body_b


def redirect(location, status=302) -> bytes:
    return http_response(status, "", {"Location": location}, "Found")


def request_line(text: str) -> str:
    return text.split("\r\n", 1)[0]


# ---- certificates ---------------------------------------------------------------------------------
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class Pki:
    """A throwaway CA that can issue valid, expired, not-yet-valid, wrong-host and self-signed certs."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(_name("Test CA")).issuer_name(_name("Test CA"))
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - timedelta(days=3650)).not_valid_after(now + timedelta(days=3650))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
                     .sign(self.key, hashes.SHA256()))
        self.ca_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        self._n = 0

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cadata=self.ca_pem.decode())

    def server_context(self, hostnames, *, days_valid=90, not_before_days=-1, self_signed=False,
                       issuer_cn=None) -> ssl.SSLContext:
        """days_valid / not_before_days are relative to now (negative = in the past)."""
        now = datetime.now(timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = _name(hostnames[0])
        issuer = subject if self_signed else _name(issuer_cn or "Test CA")
        signer = key if self_signed else self.key
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now + timedelta(days=not_before_days))
                   .not_valid_after(now + timedelta(days=days_valid))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False))
        cert = builder.sign(signer, hashes.SHA256())
        self._n += 1
        cf, kf = self.tmp / f"c{self._n}.pem", self.tmp / f"k{self._n}.pem"
        cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cf, kf)
        return ctx


class World:
    """DNS + network + a guard wired to them. Trusts only the test CA."""

    def __init__(self, tmp_path):
        self.dns = FakeDns()
        self.net = FakeNetwork()
        self.pki = Pki(tmp_path)
        self.guard = NetGuard(self.dns, connector=self.net.connect, context_factory=self.pki.client_context,
                              connect_timeout=1.0, total_timeout=4.0, max_redirects=5)

    def site(self, host, ip="93.184.216.34", *, http=None, https=None, tls_ctx=None):
        """Publish a host: DNS A record plus optional http (port 80) / https (port 443) handlers."""
        self.dns.set(host, "A", [ip])
        if http is not None:
            self.net.add(ip, 80, http)
        if https is not None:
            self.net.add(ip, 443, https, tls_ctx or self.pki.server_context([host]))
