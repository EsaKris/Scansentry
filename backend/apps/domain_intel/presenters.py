from .service import LIMITATIONS


def present(a, *, cached: bool = False) -> dict:
    """Public JSON shape of an assessment. Nothing here is computed beyond what was stored."""
    rdap = a.rdap_data or {}
    web = a.http_results or {}
    return {
        "id": str(a.id),
        "domain": a.domain,
        "display_domain": a.display_domain,
        "registrable_domain": a.registrable_domain,
        "checked_at": a.checked_at,
        "cache_expires_at": a.cache_expires_at,
        "cached": cached,
        "engine_version": a.engine_version,
        "completion_status": a.completion_status,
        "confidence": a.confidence,
        "registration": {
            "status": a.registration_status,
            "status_explanation": a.registration_status_explanation,
            "created_at": a.registration_created_at,
            "age_days": a.registration_age_days,
            "age_group": a.age_group,
            "age_note": rdap.get("age_note"),
            "reregistered_at": rdap.get("reregistered_at"),
            "expires_at": a.registration_expires_at,
            "updated_at": a.registration_updated_at,
            "registrar": a.registrar_name or None,
            "raw_status_flags": a.raw_status_flags,
            "nameservers": rdap.get("nameservers", []),
            "dnssec_signed": rdap.get("dnssec_signed"),
            "events": rdap.get("events", []),
            "not_disclosed": rdap.get("not_disclosed", []),
            "rdap_source": a.source_provider or None,
        },
        "dns": a.dns_results or None,
        "tls": a.tls_results or None,
        "website": {
            "hosting_status": a.hosting_status,
            "http_status": a.http_status,
            "final_url": web.get("final_url"),
            "https_works": web.get("https_works"),
            "https_certificate_verified": web.get("https_certificate_verified"),
            "redirect_count": web.get("redirect_count"),
            "redirects": web.get("redirects", []),
            "confidence": web.get("confidence"),
            "evidence": web.get("evidence", []),
            "heuristic": web.get("heuristic"),
            "parked_indicator": web.get("parked_indicator"),
        } if web else None,
        "scores": {
            "domain_health": {
                "score": a.domain_health_score,
                **{k: a.health_details.get(k) for k in ("label", "version", "note", "components",
                                                         "not_assessed", "coverage")},
            },
            "security_risk": None,   # produced by the security engine, not by domain intelligence
        },
        "missing_checks": a.missing_checks,
        "provider_errors": a.provider_errors,
        "limitations": LIMITATIONS,
    }
