"""Website availability check. Requests only the site root, never a user-supplied path."""
from . import status as st
from .netsafe import NetGuard


def _http_family(status: int) -> str:
    return {2: "success", 3: "redirect", 4: "client_error", 5: "server_error"}.get(status // 100, "other")


def check_website(host: str, guard: NetGuard) -> dict:
    """Try https first, then http. Reports what was observed with an honest confidence."""
    attempts = {}
    https = guard.fetch(f"https://{host}/")
    attempts["https"] = https
    http = None
    if not (https.ok and https.status is not None):
        http = guard.fetch(f"http://{host}/")
        attempts["http"] = http
    best = https if https.ok else (http if http is not None and http.ok else None)

    out = {
        "https_works": bool(https.ok),
        "https_certificate_verified": https.tls_verified if https.ok else None,
        "https_certificate_problem": https.tls_problem or None,
        "attempts": {k: {"ok": v.ok, "status": v.status, "error": v.error, "error_detail": v.error_detail}
                     for k, v in attempts.items()},
        "final_url": None, "http_status": None, "redirects": [], "redirect_count": 0,
        "hosting_status": st.HOSTING_UNKNOWN, "confidence": "low", "evidence": [], "heuristic": None,
        "parked_indicator": None, "server": None,
    }

    if best is None:
        errors = {v.error for v in attempts.values()}
        detail = "; ".join(f"{k}: {v.error} ({v.error_detail})" for k, v in attempts.items())
        out["redirects"] = https.redirects
        if errors == {"dns_failure"}:
            out.update(hosting_status=st.DNS_FAILURE, confidence="high",
                       evidence=["The host name does not resolve to an address."])
        elif errors == {"blocked_destination"}:
            out.update(hosting_status=st.HOSTING_UNKNOWN, confidence="high", blocked=True,
                       evidence=["The host resolves to a non-public network address, so it was not contacted."])
        elif "redirect_loop" in errors or "too_many_redirects" in errors:
            out.update(hosting_status=st.WEBSITE_UNAVAILABLE, confidence="medium", redirect_loop=True,
                       evidence=["The site redirects in a loop or through too many hops. " + detail])
        else:
            out.update(hosting_status=st.WEBSITE_UNAVAILABLE, confidence="medium",
                       evidence=[detail or "The web server could not be reached."])
        return out

    out.update(final_url=best.final_url, http_status=best.status, redirects=best.redirects,
               redirect_count=max(0, len(best.redirects) - 1), server=best.headers.get("server"))
    suspicion = st.detect_hosting_suspension(best.status, best.text)
    if suspicion:
        out.update(hosting_status=suspicion["classification"], confidence=suspicion["confidence"],
                   evidence=[suspicion["evidence"]], heuristic=True)
    else:
        family = _http_family(best.status)
        out.update(hosting_status=st.WEBSITE_RESPONDING, confidence="high",
                   evidence=[f"The web server answered with HTTP {best.status} ({family})."])
        if best.status in (403, 404) or best.status >= 500:
            out["evidence"].append("An error status alone does not show suspension, takedown or abuse.")
    parked = st.detect_parked(best.text)
    if parked:
        out["parked_indicator"] = f'Page text contains "{parked}".'
    return out
