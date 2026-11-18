"""Human-readable explanations of a security check.

The deterministic rule-based explanation always exists. An AI model may *rephrase and prioritise* it, but:
  * it only ever receives a small whitelisted evidence object (no paths, no query strings, no user data)
  * its output must pass strict validation (known finding keys only, same classification, no safety claims)
  * on any failure we fall back to the rule-based text; the classification is never changed by AI
"""
import json
import logging
import re

from django.conf import settings

from .scoring import LABELS

log = logging.getLogger(__name__)
SEVERITIES = {"info", "low", "medium", "high", "critical"}
FORBIDDEN = re.compile(
    r"100\s?%\s*safe|completely safe|totally safe|guaranteed safe|absolutely safe|is safe to|safe to (open|visit|proceed|use|click)|no risk|risk[- ]free",
    re.I)
SYSTEM_PROMPT = (
    "You explain the results of an automated URL security check to a non-technical person. "
    "You are given a JSON evidence object. Use ONLY facts in it. Never invent registration dates, "
    "threat-intelligence results, scan results, or any other facts. Never change the classification. "
    "Never call a destination safe or risk-free. Reply with ONE JSON object and nothing else, with keys: "
    '"summary" (string, max 500 chars), "classification" (copy the given classification exactly), '
    '"key_findings" (array of {"finding": <a finding key from the evidence>, "explanation": string, '
    '"severity": one of info|low|medium|high|critical}), "recommended_actions" (array of short strings), '
    '"limitations" (array of short strings).')


class ExplanationInvalid(Exception):
    pass


# ---- evidence (whitelist) ---------------------------------------------------------------------
def build_evidence(*, classification, risk_score, confidence, host, scheme, rules, threat, domain,
                   missing_checks, shortened) -> dict:
    """Only static, non-personal facts. Dynamic text, URL paths and query strings never leave the server."""
    from .rules import REGISTRY
    findings = []
    for r in sorted((x for x in rules if x.get("status") == "triggered"), key=lambda x: -x["weight"])[:10]:
        d = REGISTRY[r["rule"]]
        findings.append({"finding": r["rule"], "name": d.name, "meaning": d.description,
                         "reason_code": r["reason_code"], "severity": r["severity"], "strength": r["strength"]})
    reg = (domain or {}).get("registration") or {}
    return {
        "classification": classification, "classification_label": LABELS[classification],
        "risk_score": risk_score, "confidence": confidence,
        "destination": {"host": host, "scheme": scheme, "reached_through_url_shortener": bool(shortened)},
        "findings": findings,
        "threat_intelligence": {"sources_answered": (threat or {}).get("ok_count", 0),
                                "confirmed_categories": sorted({f["category"] for f in (threat or {}).get("confirmed", [])})},
        "domain": {"age_group": reg.get("age_group"), "registration_status": reg.get("status"),
                   "tls_status": ((domain or {}).get("tls") or {}).get("status"),
                   "website_status": ((domain or {}).get("website") or {}).get("hosting_status")},
        "missing_checks": sorted({m["check"] if isinstance(m, dict) else str(m) for m in missing_checks}),
    }


# ---- deterministic explanation -------------------------------------------------------------------
_SUMMARY = {
    "known_malicious": "A threat-intelligence source lists this destination as harmful. ScanSentry will not forward you to it.",
    "high_risk": "This destination shows several strong warning signs.",
    "suspicious": "This destination shows some warning signs. They are not proof of harm, but take care.",
    "needs_further_verification": "ScanSentry could not complete every check, so it cannot confirm anything about this destination.",
    "no_known_threat_detected": ("No known threat was found in the sources checked. This is not a guarantee: new or "
                                 "targeted threats may not be listed yet."),
    "assessment_unavailable": "ScanSentry could not assess this destination right now.",
}


def rule_based_explanation(evidence: dict, *, limitations_extra=()) -> dict:
    cls = evidence["classification"]
    findings = evidence["findings"]
    actions: list[str] = []
    from .rules import REGISTRY
    for f in findings:
        a = REGISTRY[f["finding"]].recommended_action
        if a and a not in actions:
            actions.append(a)
    if cls in ("known_malicious", "high_risk", "suspicious"):
        extra = "Do not enter passwords or payment details unless you have confirmed the site through another channel."
        if extra not in actions:
            actions.append(extra)
    if cls == "needs_further_verification" or cls == "assessment_unavailable":
        actions.append("Confirm the destination with the person or organisation that gave you this code.")
    limitations = [f"{c.replace('_', ' ').capitalize()} could not be completed." for c in evidence["missing_checks"]]
    limitations += list(limitations_extra)
    limitations.append("No automated check can prove that a destination is trustworthy.")
    return {
        "source": "rule_based", "summary": _SUMMARY[cls], "classification": cls,
        "key_findings": [{"finding": f["finding"], "explanation": f["meaning"], "severity": f["severity"]}
                         for f in findings[:6]],
        "recommended_actions": actions[:8], "limitations": limitations[:8],
    }


# ---- AI path ----------------------------------------------------------------------------------------
def validate_explanation(obj, evidence: dict) -> dict:
    """Strict schema + policy validation. Raises ExplanationInvalid on any problem."""
    if not isinstance(obj, dict):
        raise ExplanationInvalid("not an object")
    allowed_keys = {f["finding"] for f in evidence["findings"]}
    summary = obj.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 600:
        raise ExplanationInvalid("bad summary")
    if obj.get("classification") != evidence["classification"]:
        raise ExplanationInvalid("classification mismatch")   # AI must never change the verdict
    kf = obj.get("key_findings")
    if not isinstance(kf, list) or len(kf) > 10:
        raise ExplanationInvalid("bad key_findings")
    cleaned = []
    for item in kf:
        if not isinstance(item, dict) or item.get("finding") not in allowed_keys:
            raise ExplanationInvalid("unknown finding")        # no invented findings
        if item.get("severity") not in SEVERITIES or not isinstance(item.get("explanation"), str) \
                or not item["explanation"].strip() or len(item["explanation"]) > 400:
            raise ExplanationInvalid("bad finding fields")
        cleaned.append({"finding": item["finding"], "explanation": item["explanation"].strip(), "severity": item["severity"]})
    lists = {}
    for key, limit in (("recommended_actions", 8), ("limitations", 6)):
        v = obj.get(key)
        if not isinstance(v, list) or len(v) > limit or not all(isinstance(x, str) and 0 < len(x) <= 240 for x in v):
            raise ExplanationInvalid(f"bad {key}")
        lists[key] = [x.strip() for x in v]
    blob = " ".join([summary] + [c["explanation"] for c in cleaned] + lists["recommended_actions"] + lists["limitations"])
    if FORBIDDEN.search(blob):
        raise ExplanationInvalid("forbidden safety claim")
    return {"source": "ai", "summary": summary.strip(), "classification": evidence["classification"],
            "key_findings": cleaned, **lists}


def _extract_json(text: str):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    return json.loads(text)


def call_anthropic(evidence: dict, guard) -> str:
    """POST to the Anthropic Messages API through the SSRF guard. Returns the model's text."""
    body = json.dumps({"model": settings.AI_MODEL, "max_tokens": 900, "system": SYSTEM_PROMPT,
                       "messages": [{"role": "user", "content": json.dumps(evidence, ensure_ascii=False)}]})
    res = guard.fetch("https://api.anthropic.com/v1/messages", method="POST", body=body.encode(),
                      accept="application/json", require_https=True, max_body=128 * 1024,
                      headers={"x-api-key": settings.AI_API_KEY, "anthropic-version": "2023-06-01",
                               "content-type": "application/json"})
    if res.error or res.status != 200:
        raise ExplanationInvalid(f"ai_unavailable:{res.error or res.status}")
    data = json.loads(res.text)
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def ai_configured() -> bool:
    return settings.AI_PROVIDER == "anthropic" and bool(settings.AI_API_KEY)


def explain(evidence: dict, *, use_ai: bool, guard, limitations_extra=()) -> dict:
    base = rule_based_explanation(evidence, limitations_extra=limitations_extra)
    if not (use_ai and ai_configured()):
        return base
    try:
        text = call_anthropic(evidence, guard)
        return validate_explanation(_extract_json(text), evidence)
    except (ExplanationInvalid, ValueError, KeyError, TypeError) as exc:
        log.warning("AI explanation rejected: %s", exc)
        base["ai_error"] = "The AI explanation was unavailable or failed validation; showing the standard explanation."
        return base
