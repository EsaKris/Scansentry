"""Security assessment pipeline.

  1. classify the content (no network)  ->  2. trace redirects (known shorteners only)
  3. domain intelligence                ->  4. threat-intelligence providers
  5. rule engine + scoring              ->  6. explanation  ->  7. store with evidence

Failures of any external step become entries in `missing_checks` / `provider_errors`; they are never
treated as clean results, and the local rules always run.
"""
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from apps.core.config import get_config
from apps.core.entitlements import feature_enabled
from apps.domain_intel import service as domain_service
from apps.domain_intel.normalize import InvalidDomainInput, normalize_domain_input
from apps.domain_intel.presenters import present as present_domain
from apps.scanner.analysis import analyze_content, analyze_url
from apps.threat_intel import service as threat_service
from apps.threat_intel.providers import ADAPTERS, ThreatQuery

from . import explain as explain_mod
from . import rules as rules_mod
from . import scoring
from .models import SecurityCheck
from .trace import redact, trace_redirects

log = logging.getLogger(__name__)
URL_KINDS = {"url", "blocked_scheme", "unsupported_scheme"}


class NotApplicable(Exception):
    """Security assessment applies to web links only."""


def _minutes(key: str, default: float) -> float:
    try:
        return float(get_config(key, default))
    except (TypeError, ValueError):
        return default


def _cache_key(normalized: str | None) -> str | None:
    return redact(normalized) if normalized else None


def latest_cached_check(url: str, now=None):
    """Most recent unexpired check for this destination (no network). Used by the redirect policy."""
    now = now or datetime.now(timezone.utc)
    try:
        key = _cache_key(analyze_url(url)["url"].get("normalized"))
    except Exception:
        return None
    if not key:
        return None
    return SecurityCheck.objects.filter(normalised_url=key, cache_expires_at__gt=now).order_by("-checked_at").first()


def _nd(host: str | None):
    try:
        return normalize_domain_input(host) if host else None
    except InvalidDomainInput:
        return None


def _threat_queries(urls: list[str]) -> list[tuple[str, ThreatQuery]]:
    out = []
    for label, url in urls:
        host = urlsplit(url).hostname or ""
        nd = _nd(host)
        out.append((label, ThreatQuery(url=redact(url), host=host, registrable=nd.registrable if nd else None)))
    return out


def analyze(content: str, *, user=None, source: str = "api", trace: bool = True, ai: bool = False,
            now: datetime | None = None, guard=None):
    """Returns (SecurityCheck, served_from_cache). Raises NotApplicable for non-web content."""
    now = now or datetime.now(timezone.utc)
    content = content.strip()
    analysis = analyze_content(content)
    kind = analysis["kind"]
    if kind not in URL_KINDS:
        raise NotApplicable()

    facts = analysis["url"]
    normalized = (facts or {}).get("normalized")
    allowed_ai = bool(ai and user is not None and feature_enabled(user, "ai.explanations"))
    rule_set = rules_mod.effective_rules()
    rhash = rules_mod.ruleset_hash(rule_set)

    key = _cache_key(normalized)
    if key:
        hit = SecurityCheck.objects.filter(normalised_url=key, engine_version=scoring.ENGINE_VERSION,
                                           scoring__ruleset_hash=rhash, cache_expires_at__gt=now
                                           ).order_by("-checked_at").first()
        if hit is not None:
            if allowed_ai and (hit.explanation or {}).get("source") != "ai" and hit.scoring.get("evidence"):
                hit.explanation = explain_mod.explain(hit.scoring["evidence"], use_ai=True,
                                                      guard=guard or domain_service.build_guard())
                hit.save(update_fields=["explanation"])
            return hit, True

    guard = guard or domain_service.build_guard()
    lists = rules_mod.load_lists()
    network_ok = kind == "url" and bool(normalized) and not analysis["actions"]["blocked"]

    # -- 2. redirect trace (known shorteners only) ----------------------------------------------------
    trace_data, effective_url, effective_facts = None, normalized, facts
    original_host = (facts or {}).get("host")
    is_short = bool(original_host) and (original_host in lists["shorteners"]
                                        or ".".join(original_host.split(".")[-2:]) in lists["shorteners"])
    trace_attempted = network_ok and trace and is_short and bool(get_config("security.trace_shorteners", True))
    if trace_attempted:
        trace_data = trace_redirects(normalized, guard)
        raw_final = trace_data.pop("final_url", None)       # may carry query secrets: used here, never stored
        if trace_data["completed"] and raw_final:
            fa = analyze_url(raw_final)
            if fa["url"].get("normalized"):
                effective_url, effective_facts = fa["url"]["normalized"], fa["url"]
                analysis["observations"] = analysis["observations"] + fa["observations"]
    trace_ok = (not trace_attempted) or bool(trace_data and trace_data["completed"])

    # -- 3. domain intelligence ----------------------------------------------------------------------------
    missing: list[dict] = []
    domain_assessment, domain_view, domain_status = None, None, "not_run"
    eff_host = (effective_facts or {}).get("host")
    nd = _nd(eff_host) if network_ok else None
    if network_ok and nd is None:
        domain_status = "not_applicable"       # IP / non-public host: no domain registration to assess
    elif nd is not None:
        try:
            domain_assessment, _ = domain_service.assess(nd.host, now=now)
            domain_view = present_domain(domain_assessment)
            domain_status = domain_assessment.completion_status
            missing += [{"check": f"domain:{m['check']}", "reason": m["reason"]} for m in domain_assessment.missing_checks]
        except Exception:
            log.exception("domain assessment failed")
            domain_status = "failed"
            missing.append({"check": "domain", "reason": "The domain assessment could not be completed."})

    # -- 4. threat intelligence -------------------------------------------------------------------------------
    outcome = threat_service.ThreatOutcome()
    if network_ok:
        targets = [("submitted", normalized)] + ([("destination", effective_url)] if effective_url != normalized else [])
        for label, q in _threat_queries(targets):
            o = threat_service.check_url(q, guard=guard)
            for r in o.results:
                r.target = label
            outcome.results += o.results
            outcome.providers_enabled = max(outcome.providers_enabled, o.providers_enabled)
    external_ok = [r for r in outcome.results if r.status == "ok" and ADAPTERS[r.provider].external]
    intel_ok = bool(external_ok)
    if network_ok:
        external_enabled = [r for r in outcome.results if ADAPTERS[r.provider].external]
        if not external_enabled:
            missing.append({"check": "threat_intelligence", "reason":
                            "No external threat-intelligence provider is enabled (only ScanSentry's own blocklist was checked)."})
        elif not intel_ok:
            missing.append({"check": "threat_intelligence", "reason": "No external threat-intelligence provider answered."})
        for e in outcome.errors:
            missing.append({"check": f"threat_intel:{e['provider']}", "reason": e["error"] or e["status"]})
    if trace_attempted and not trace_ok:
        missing.append({"check": "redirect_trace", "reason": (trace_data or {}).get("error_detail") or "trace failed"})

    # -- 5. rules + scoring --------------------------------------------------------------------------------------
    eff_nd = _nd(eff_host) if eff_host else None
    ctx = rules_mod.RuleContext(
        raw=content, kind=kind, url=effective_facts, observations=analysis["observations"],
        normalized=effective_url, host=eff_host, display_host=(effective_facts or {}).get("display_host"),
        registrable=eff_nd.registrable if eff_nd else None,
        display_registrable=eff_nd.registrable.encode("ascii").decode("idna") if eff_nd else None,
        scheme=(effective_facts or {}).get("scheme"), domain=domain_view,
        threat={"findings": outcome.findings}, trace=trace_data,
        original_host=original_host if is_short else None, **lists)
    results = rules_mod.evaluate(ctx, rule_set)
    sc = scoring.score_rules(results)
    rule_errors = sum(r.get("status") == "error" for r in results)
    classification = scoring.classify(sc, intel_ok=intel_ok, domain_status=domain_status,
                                      trace_failed=not trace_ok, rule_errors=rule_errors)
    conf = scoring.confidence(intel_ok=intel_ok, domain_status=domain_status, trace_ok=trace_ok, rule_errors=rule_errors)
    if rule_errors:
        missing.append({"check": "rules", "reason": f"{rule_errors} rule(s) failed to run"})

    # -- 6. explanation ---------------------------------------------------------------------------------------------
    threat_summary = outcome.summary()
    evidence = explain_mod.build_evidence(
        classification=classification, risk_score=sc["score"], confidence=conf, host=eff_host or "(none)",
        scheme=ctx.scheme, rules=results,
        threat={"ok_count": len(external_ok), "confirmed": outcome.confirmed}, domain=domain_view,
        missing_checks=missing, shortened=is_short and trace_ok and effective_url != normalized)
    explanation = explain_mod.explain(evidence, use_ai=allowed_ai, guard=guard)

    # -- 7. persist ----------------------------------------------------------------------------------------------------
    complete = not missing
    ttl = timedelta(minutes=_minutes("security.cache_minutes", 30) if complete else 5)
    if classification == "known_malicious":
        # keep the block in force: the redirect policy reads this record (see policy.py)
        ttl = max(ttl, timedelta(hours=_minutes("security.malicious_cache_hours", 24)))
    check = SecurityCheck.objects.create(
        submitted_url=(redact(normalized) if normalized else content.split("?")[0].split("#")[0][:200]),
        normalised_url=key or "",
        normalised_domain=(eff_nd.host if eff_nd else (eff_host or ""))[:255], source_type=source,
        requested_by=user if (user is not None and getattr(user, "is_authenticated", False)) else None,
        domain_assessment=domain_assessment, rule_results=results, threat_findings=threat_summary,
        redirect_trace=trace_data or {}, risk_score=sc["score"], risk_classification=classification,
        health_score=getattr(domain_assessment, "domain_health_score", None), confidence=conf,
        missing_checks=missing, provider_errors=outcome.errors, explanation=explanation,
        scoring={"risk_version": scoring.RISK_VERSION, "ruleset_hash": rhash, "thresholds": sc["thresholds"],
                 "counts": sc["counts"], "raw_points": sc["raw_points"], "notes": sc["notes"],
                 "note": scoring.SCORING_NOTE, "evidence": evidence},
        completion_status="complete" if complete else "partial", engine_version=scoring.ENGINE_VERSION,
        checked_at=now, cache_expires_at=now + ttl)
    return check, False
