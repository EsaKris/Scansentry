"""Security Risk score and classification.

Principles (from the product spec):
  * a weak indicator alone never produces a severe conclusion
  * "known malicious" comes only from a threat-intelligence match, never from a score
  * "no known threat detected" is only said when at least one threat-intel source answered successfully
  * missing checks lower confidence and are listed; they are never treated as clean
  * the score is a transparent weighted sum, versioned, NOT scientifically validated
"""
from apps.core.config import get_config

ENGINE_VERSION = "security-engine-1.0"
RISK_VERSION = "risk-1"
DEFAULT_THRESHOLDS = {"suspicious": 35, "high_risk": 65, "weak_only_cap": 49}
SCORING_NOTE = ("The risk score is a weighted sum of rule findings. It has not been validated against a "
                "representative dataset and must be read together with the evidence listed.")

LABELS = {
    "known_malicious": "Known malicious", "high_risk": "High risk", "suspicious": "Suspicious",
    "needs_further_verification": "Needs further verification",
    "no_known_threat_detected": "No known threat detected", "assessment_unavailable": "Assessment unavailable",
}
CONFIRMED_RULES = {"intel.known_malware", "intel.known_phishing"}


def thresholds() -> dict:
    cfg = get_config("security.risk_thresholds", None)
    out = dict(DEFAULT_THRESHOLDS)
    if isinstance(cfg, dict):
        out.update({k: int(v) for k, v in cfg.items() if k in out})
    return out


def score_rules(results: list[dict]) -> dict:
    th = thresholds()
    triggered = [r for r in results if r.get("status") == "triggered"]
    strong = sum(r["strength"] == "strong" for r in triggered)
    moderate = sum(r["strength"] == "moderate" for r in triggered)
    weak = sum(r["strength"] == "weak" for r in triggered)
    raw = sum(r["weight"] for r in triggered)
    score, notes = min(100, raw), []
    confirmed = any(r["rule"] in CONFIRMED_RULES for r in triggered)

    if confirmed:
        score = 100
    else:
        if strong == 0 and moderate == 0 and score > th["weak_only_cap"]:
            score = th["weak_only_cap"]
            notes.append("Only weak indicators were found, so the score is capped below 'high risk'.")
        band = "high_risk" if score >= th["high_risk"] else "suspicious" if score >= th["suspicious"] else "low"
        if band == "high_risk" and not (strong >= 1 or moderate >= 2):
            score = min(score, th["high_risk"] - 1)
            notes.append("'High risk' needs at least one strong indicator or two moderate ones.")
    band = ("high_risk" if score >= th["high_risk"] else "suspicious" if score >= th["suspicious"] else "low")
    return {"score": score, "band": band, "raw_points": raw, "confirmed_threat": confirmed,
            "counts": {"strong": strong, "moderate": moderate, "weak": weak}, "notes": notes, "thresholds": th}


def classify(sc: dict, *, intel_ok: bool, domain_status: str, trace_failed: bool = False,
             rule_errors: int = 0) -> str:
    """domain_status: complete | partial | failed | not_applicable | not_run.

    A clean verdict additionally requires that the real destination was reached (redirect trace did not fail)
    and that no detection rule crashed, because either would hide a threat."""
    if sc["confirmed_threat"]:
        return "known_malicious"
    if sc["band"] == "high_risk":
        return "high_risk"
    if sc["band"] == "suspicious":
        return "suspicious"
    domain_unusable = domain_status in ("failed", "not_run")
    if not intel_ok and domain_unusable:
        return "assessment_unavailable"
    if not intel_ok or domain_status == "failed" or trace_failed or rule_errors:
        return "needs_further_verification"
    return "no_known_threat_detected"


def confidence(*, intel_ok: bool, domain_status: str, trace_ok: bool, rule_errors: int) -> str:
    pts = (0.5 if intel_ok else 0) + {"complete": 0.3, "not_applicable": 0.3, "partial": 0.15}.get(domain_status, 0) \
        + (0.1 if trace_ok else 0) + (0.1 if not rule_errors else 0)
    level = "high" if pts >= 0.85 else "medium" if pts >= 0.5 else "low"
    if (rule_errors or not trace_ok) and level == "high":
        level = "medium"          # a failed trace or crashed rule means part of the picture is missing
    return level
