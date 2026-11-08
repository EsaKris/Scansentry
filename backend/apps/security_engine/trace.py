"""Redirect tracing for known URL shorteners only. Uses the SSRF guard: every hop is re-validated."""
from urllib.parse import urlsplit

from apps.domain_intel.normalize import InvalidDomainInput, normalize_domain_input


def redact(url: str) -> str:
    """Drop query and fragment (they may carry tokens)."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


def trace_redirects(url: str, guard) -> dict:
    res = guard.fetch(url, read_body=False, max_body=1024)
    hops = [{"url": redact(h["url"]), "status": h["status"]} for h in res.redirects]
    domains = []
    for h in res.redirects:
        try:
            domains.append(normalize_domain_input(urlsplit(h["url"]).hostname or "").registrable)
        except InvalidDomainInput:
            domains.append(urlsplit(h["url"]).hostname or "")
    final = res.final_url
    return {
        "completed": res.ok, "error": res.error, "error_detail": res.error_detail,
        "hop_count": len(hops), "hops": hops,
        "distinct_registrable_domains": len(set(domains)),
        "final_url": final, "final_url_redacted": redact(final) if final else None,
        "final_status": res.status,
    }
