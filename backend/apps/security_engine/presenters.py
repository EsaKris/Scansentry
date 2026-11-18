from .scoring import LABELS

LIMITATIONS = [
    "ScanSentry reports what it could verify. 'No known threat detected' is not a guarantee of safety.",
    "HTTPS shows an encrypted connection, not that a website is legitimate.",
    "Domain age is context, not proof of good or bad intent.",
    "The risk score is a transparent weighted sum of findings and has not been scientifically validated.",
]


def present_check(c, *, cached: bool = False) -> dict:
    triggered = [r for r in c.rule_results if r.get("status") == "triggered"]
    errors = [r for r in c.rule_results if r.get("status") == "error"]
    cls = c.risk_classification
    domain = c.domain_assessment
    return {
        "id": str(c.id),
        "classification": cls,
        "classification_label": LABELS.get(cls, cls),
        "risk_score": c.risk_score,
        "confidence": c.confidence,
        "completion_status": c.completion_status,
        "destination": {"submitted_url": c.submitted_url, "normalized_url": c.normalised_url or None,
                        "domain": c.normalised_domain or None},
        "findings": sorted(triggered, key=lambda r: -r["weight"]),
        "rule_errors": errors,
        "threat_intelligence": c.threat_findings,
        "domain": ({"assessment_id": str(domain.id), "health_score": domain.domain_health_score,
                    "registration_status": domain.registration_status, "age_group": domain.age_group,
                    "tls_status": domain.tls_status, "hosting_status": domain.hosting_status,
                    "completion_status": domain.completion_status} if domain else None),
        "redirect_trace": c.redirect_trace or None,
        "missing_checks": c.missing_checks,
        "provider_errors": c.provider_errors,
        "explanation": c.explanation,
        "policy": ("ScanSentry will not forward you to a destination with a confirmed malicious finding."
                   if cls == "known_malicious" else None),
        "scoring": {k: v for k, v in c.scoring.items() if k != "evidence"},
        "limitations": LIMITATIONS,
        "checked_at": c.checked_at, "cache_expires_at": c.cache_expires_at, "cached": cached,
        "engine_version": c.engine_version,
    }


def summary(c) -> dict:
    """Compact form embedded in scanner/verification responses."""
    top = sorted((r for r in c.rule_results if r.get("status") == "triggered"), key=lambda r: -r["weight"])[:4]
    return {"status": c.risk_classification, "label": LABELS.get(c.risk_classification),
            "risk_score": c.risk_score, "confidence": c.confidence, "check_id": str(c.id),
            "summary": (c.explanation or {}).get("summary"), "checked_at": c.checked_at,
            "top_findings": [{"rule": r["rule"], "name": r["name"], "severity": r["severity"], "message": r["message"]}
                             for r in top],
            "missing_checks": [m["check"] for m in c.missing_checks]}
