"""TLS certificate inspection through the SSRF guard (pinned, public-IP-only connections)."""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from .netsafe import BlockedDestination, NetGuard, NoAddress, unverified_context

EXPIRING_SOON_DAYS = 14

# OpenSSL X509_V_ERR_* codes -> our status
_VERIFY_CODES = {
    10: "EXPIRED", 9: "NOT_YET_VALID", 62: "HOSTNAME_MISMATCH", 64: "HOSTNAME_MISMATCH",
    18: "SELF_SIGNED", 19: "SELF_SIGNED", 20: "UNTRUSTED_CHAIN", 21: "UNTRUSTED_CHAIN", 2: "UNTRUSTED_CHAIN",
}
_MESSAGES = {
    "VALID": "The certificate is valid and matches the host name.",
    "EXPIRED": "The certificate has expired.",
    "NOT_YET_VALID": "The certificate is not valid yet.",
    "HOSTNAME_MISMATCH": "The certificate was issued for a different host name.",
    "SELF_SIGNED": "The certificate is self-signed or its chain ends in an untrusted root.",
    "UNTRUSTED_CHAIN": "The certificate chain could not be verified against trusted authorities.",
    "ERROR": "The TLS handshake failed.",
    "NO_HTTPS": "The server did not accept a TLS connection on port 443.",
    "UNAVAILABLE": "TLS could not be checked.",
}


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def _parse_der(der: bytes, now: datetime) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb, na = cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = san.get_values_for_type(x509.DNSName)[:20]
    except x509.ExtensionNotFound:
        names = []
    return {
        "issuer_common_name": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_organization": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "subject_common_name": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "san_dns_names": names,
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_remaining": (na - now).days,
        "self_issued": cert.issuer == cert.subject,
    }


def _result(status: str, **extra) -> dict:
    base = {"status": status, "message": _MESSAGES.get(status, ""), "https_available": status not in
            ("NO_HTTPS", "UNAVAILABLE"), "certificate": None, "protocol": None, "cipher": None,
            "expiring_soon": False, "detail": ""}
    base.update(extra)
    return base


def inspect_tls(host: str, guard: NetGuard, *, now: datetime | None = None, port: int = 443) -> dict:
    now = now or datetime.now(timezone.utc)
    try:
        ips = guard.resolve_public(host)
    except BlockedDestination as exc:
        return _result("UNAVAILABLE", detail=exc.reason, blocked=True)
    except NoAddress:
        return _result("UNAVAILABLE", detail="The host name did not resolve.")

    def handshake(ctx):
        last = None
        for ip in ips:
            try:
                raw = guard.connector(ip, port, guard.connect_timeout)
            except (OSError, socket.timeout) as exc:
                last = exc
                continue
            try:
                return ctx.wrap_socket(raw, server_hostname=host)
            except Exception:
                raw.close()
                raise
        raise last or OSError("unreachable")

    ctx = guard.context_factory()
    try:
        tls = handshake(ctx)
    except ssl.SSLCertVerificationError as exc:
        status = _VERIFY_CODES.get(exc.verify_code, "UNTRUSTED_CHAIN")
        out = _result(status, detail=exc.verify_message or "")
        try:  # read the certificate anyway so we can report dates/issuer
            tls2 = handshake(unverified_context())
            out["certificate"] = _parse_der(tls2.getpeercert(binary_form=True), now)
            out["protocol"] = tls2.version()
            tls2.close()
        except Exception:
            pass
        return out
    except (socket.timeout, TimeoutError):
        return _result("NO_HTTPS", detail="Connection timed out.")
    except ConnectionRefusedError:
        return _result("NO_HTTPS", detail="Connection refused.")
    except ssl.SSLError as exc:
        return _result("ERROR", detail=exc.__class__.__name__ + ": " + (exc.reason or ""))
    except OSError as exc:
        return _result("NO_HTTPS", detail=exc.__class__.__name__)

    try:
        cert = _parse_der(tls.getpeercert(binary_form=True), now)
        out = _result("VALID", certificate=cert, protocol=tls.version(),
                      cipher=(tls.cipher() or (None,))[0])
        out["expiring_soon"] = cert["days_remaining"] < EXPIRING_SOON_DAYS
        if out["expiring_soon"]:
            out["message"] = f"The certificate is valid but expires in {cert['days_remaining']} day(s)."
        return out
    finally:
        tls.close()
