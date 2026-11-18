"""Domain Health Score: technical and registration health. It does NOT measure honesty or safety.

Each component yields 0..1 or None (not assessed). Weights are versioned and configurable
(AppConfiguration "domain.health_weights"); missing components are excluded and the remaining
weights renormalised, and the score's confidence reflects what was actually checked.
"""
from apps.core.config import get_config

from . import status as st

ENGINE_VERSION = "domain-intel-1.0"
HEALTH_SCORE_VERSION = "health-1"
DEFAULT_WEIGHTS = {"registration": 30, "dns": 25, "tls": 20, "website": 20, "configuration": 5}
DEFAULT_AGE_THRESHOLDS = {"newly_registered": 30, "recently_registered": 180, "established": 1825}
HEALTH_NOTE = ("Domain Health measures technical and registration health. It says nothing about whether "
               "the site or its owner is honest.")


def get_weights() -> dict:
    cfg = get_config("domain.health_weights", None)
    if isinstance(cfg, dict) and cfg:
        return {k: float(v) for k, v in cfg.items() if k in DEFAULT_WEIGHTS and float(v) >= 0}
    return dict(DEFAULT_WEIGHTS)


def age_group(age_days: int | None) -> str:
    if age_days is None:
        return "unknown"
    t = {**DEFAULT_AGE_THRESHOLDS, **(get_config("domain.age_thresholds_days", {}) or {})}
    if age_days < t["newly_registered"]:
        return "newly_registered"
    if age_days < t["recently_registered"]:
        return "recently_registered"
    if age_days < t["established"]:
        return "established"
    return "long_established"


_REG = {st.REGISTERED_ACTIVE: 1.0, st.REDEMPTION_PERIOD: 0.0, st.PENDING_DELETION: 0.0,
        st.REGISTRY_HOLD: 0.05, st.REGISTRAR_HOLD: 0.1, st.INACTIVE_OR_UNDELEGATED: 0.25,
        st.EXPIRED_OR_NOT_RENEWED: 0.1, st.NOT_FOUND: 0.0}


def _registration(reg_status: str | None):
    return _REG.get(reg_status)  # UNKNOWN / LOOKUP_UNAVAILABLE -> None (not assessed)


def _dns(dns: dict | None):
    if not dns or dns["status"] == "lookup_failed":
        return None
    if dns["status"] == "nxdomain":
        return 0.0
    if dns["status"] == "no_address_records":
        return 0.3
    penalty = 0.15 * len([i for i in dns["issues"] if i["code"] in ("single_nameserver", "nameserver_unresponsive")])
    return max(0.0, 1.0 - penalty)


def _tls(tls: dict | None):
    if not tls or tls["status"] in ("UNAVAILABLE", "ERROR"):
        return None
    return {"VALID": 0.7 if tls.get("expiring_soon") else 1.0, "NO_HTTPS": 0.4, "EXPIRED": 0.0,
            "NOT_YET_VALID": 0.0, "HOSTNAME_MISMATCH": 0.1, "SELF_SIGNED": 0.1,
            "UNTRUSTED_CHAIN": 0.1}.get(tls["status"])


def _website(web: dict | None):
    if not web or web.get("blocked"):
        return None
    hs, code = web["hosting_status"], web.get("http_status")
    if hs == st.DNS_FAILURE:
        return 0.0
    if hs == st.WEBSITE_UNAVAILABLE:
        return 0.2
    if hs in (st.HOSTING_SUSPENSION_INDICATOR_DETECTED, st.HOSTING_SUSPENSION_SUSPECTED):
        return 0.15
    if hs == st.WEBSITE_RESPONDING and code is not None:
        return 1.0 if code < 400 else (0.6 if code < 500 else 0.3)
    return None


def _configuration(reg_data: dict | None, dns: dict | None):
    if not dns or dns["status"] in ("lookup_failed", "nxdomain"):
        return None
    ns = len((reg_data or {}).get("nameservers") or dns["records"].get("NS") or [])
    has_addr = bool(dns["records"].get("A") or dns["records"].get("AAAA") or dns["records"].get("CNAME"))
    return (0.5 if ns < 2 and ns != 0 else 1.0 if ns >= 2 else 0.6) * (1.0 if has_addr else 0.5)


def compute_health(*, reg_status, reg_data, dns, tls, website) -> dict:
    weights = get_weights()
    parts = {
        "registration": _registration(reg_status), "dns": _dns(dns), "tls": _tls(tls),
        "website": _website(website), "configuration": _configuration(reg_data, dns),
    }
    assessed = {k: v for k, v in parts.items() if v is not None and weights.get(k, 0) > 0}
    total = sum(weights[k] for k in assessed)
    score = round(100 * sum(weights[k] * v for k, v in assessed.items()) / total) if total else None
    coverage = total / sum(weights.values()) if sum(weights.values()) else 0
    return {
        "score": score, "version": HEALTH_SCORE_VERSION, "note": HEALTH_NOTE,
        "components": {k: {"value": parts[k], "weight": weights.get(k, 0)} for k in parts},
        "not_assessed": sorted(k for k, v in parts.items() if v is None),
        "coverage": round(coverage, 2),
        "label": None if score is None else ("good" if score >= 80 else "fair" if score >= 55 else "poor"),
    }


def confidence_from(coverage: float) -> str:
    return "high" if coverage >= 0.85 else "medium" if coverage >= 0.55 else "low"
