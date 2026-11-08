"""DNS client wrapper (dnspython) used for DNS-health checks AND for SSRF-safe address resolution."""
import ipaddress
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
from django.conf import settings

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "DS")
MAX_RECORDS = 20


@dataclass
class DnsAnswer:
    status: str                      # ok | nodata | nxdomain | timeout | servfail | error
    records: list[str] = field(default_factory=list)
    error: str = ""


class DnsClient:
    """Thin wrapper so tests can substitute a fake. Only performs DNS queries."""

    def __init__(self, nameservers=None, timeout: float | None = None):
        self._resolver = dns.resolver.Resolver(configure=not (nameservers or settings.DNS_NAMESERVERS))
        ns = nameservers or settings.DNS_NAMESERVERS
        if ns:
            self._resolver.nameservers = list(ns)
        self._resolver.lifetime = timeout or settings.DNS_TIMEOUT
        self._resolver.timeout = min(self._resolver.lifetime, 3.0)

    def resolve(self, name: str, rtype: str) -> DnsAnswer:
        try:
            ans = self._resolver.resolve(name, rtype, raise_on_no_answer=True)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer("nxdomain")
        except dns.resolver.NoAnswer:
            return DnsAnswer("nodata")
        except dns.resolver.NoNameservers:
            return DnsAnswer("servfail", error="No nameserver gave a usable answer.")
        except dns.exception.Timeout:
            return DnsAnswer("timeout", error="The DNS query timed out.")
        except Exception as exc:  # pragma: no cover - defensive
            return DnsAnswer("error", error=exc.__class__.__name__)
        records = []
        for rr in list(ans)[:MAX_RECORDS]:
            text = rr.to_text()
            records.append(text[:255])
        return DnsAnswer("ok", records)

    def addresses(self, host: str) -> list[str]:
        """A + AAAA addresses for a host (CNAME chains are followed by the resolver)."""
        try:
            ipaddress.ip_address(host.strip("[]"))
            return [host.strip("[]")]
        except ValueError:
            pass
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            ans = self.resolve(host, rtype)
            if ans.status == "ok":
                out.extend(ans.records)
        return out


def check_dns(host: str, client: DnsClient) -> dict:
    """DNS health observation for one host. Reports facts and issues; never invents data."""
    results: dict[str, dict] = {}
    for rtype in RECORD_TYPES:
        a = client.resolve(host, rtype)
        results[rtype] = {"status": a.status, "records": a.records, "error": a.error}

    nxdomain = any(r["status"] == "nxdomain" for r in results.values())
    all_failed = all(r["status"] in ("timeout", "servfail", "error") for r in results.values())
    has_addr = bool(results["A"]["records"] or results["AAAA"]["records"] or results["CNAME"]["records"])
    issues: list[dict] = []

    if nxdomain:
        status = "nxdomain"
        issues.append({"code": "nxdomain", "message": "The domain name does not exist in DNS."})
    elif all_failed:
        status = "lookup_failed"
        issues.append({"code": "dns_lookup_failed", "message": "DNS lookups failed or timed out."})
    else:
        status = "resolves" if has_addr else "no_address_records"
        if not has_addr:
            issues.append({"code": "no_address_records",
                           "message": "No A, AAAA or CNAME records were found for this name."})
        if results["NS"]["status"] == "ok" and len(results["NS"]["records"]) < 2:
            issues.append({"code": "single_nameserver",
                           "message": "Only one nameserver is published, which reduces resilience."})
        if results["NS"]["status"] in ("timeout", "servfail"):
            issues.append({"code": "nameserver_unresponsive",
                           "message": "The domain's nameservers did not answer reliably."})
        for rtype, r in results.items():
            if r["status"] in ("timeout", "servfail", "error") and rtype in ("A", "AAAA"):
                issues.append({"code": f"{rtype.lower()}_lookup_error",
                               "message": f"The {rtype} lookup did not complete ({r['status']})."})

    return {
        "status": status,
        "records": {k: v["records"] for k, v in results.items()},
        "record_status": {k: v["status"] for k, v in results.items()},
        "dnssec_ds_present": bool(results["DS"]["records"]),
        "mx_present": bool(results["MX"]["records"]),  # informational only, never a risk signal
        "issues": issues,
    }
