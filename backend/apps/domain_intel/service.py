"""Orchestrates one domain assessment: runs the four independent checks concurrently,
scores domain health, stores the run and its observations, and caches results."""
import logging
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.core.cache import cache
from django.db import transaction

from apps.core.config import get_config

from . import status as st
from .dnscheck import DnsClient, check_dns
from .models import DomainAssessment, DomainLookup, DomainObservation
from .netsafe import NetGuard
from .normalize import NormalizedDomain, normalize_domain_input
from .rdap import lookup_rdap
from .scoring import ENGINE_VERSION, age_group, compute_health, confidence_from
from .tlscheck import inspect_tls
from .website import check_website

log = logging.getLogger(__name__)

LIMITATIONS = [
    "Registration data comes from RDAP. Some registries hide or redact fields, and those are reported "
    "as not disclosed rather than guessed.",
    "A registration date does not show who owns the domain now or whether it can be trusted.",
    "HTTPS means the connection is encrypted and the certificate matches the host name. It does not mean "
    "the website is legitimate.",
    "Domain Health describes technical condition, not honesty. Security risk is assessed separately.",
]


def build_dns_client() -> DnsClient:
    return DnsClient()


def build_guard(dns_client=None) -> NetGuard:
    return NetGuard(dns_client or build_dns_client())


def _cfg_hours(key: str, default: float) -> float:
    try:
        return float(get_config(key, default))
    except (TypeError, ValueError):
        return default


def _rdap_cached(nd: NormalizedDomain, guard: NetGuard, now: datetime, force: bool, ttl_ok: int) -> dict:
    """Runs in a worker thread: must not touch the database (ttl is resolved by the caller)."""
    key = f"rdap:result:{nd.registrable}"
    hit = None if force else cache.get(key)
    if hit is not None:
        return hit
    result = lookup_rdap(nd.registrable, nd.tld, guard, now=now)
    ttl = ttl_ok if result["ok"] else 60
    cache.set(key, result, ttl)
    return result


def run_checks(nd: NormalizedDomain, *, guard: NetGuard, dns: DnsClient, now: datetime,
               force_rdap: bool = False) -> dict:
    rdap_ttl = int(_cfg_hours("domain.rdap_cache_hours", 24) * 3600)   # DB read happens here, in the caller's thread
    jobs = {
        "rdap": lambda: _rdap_cached(nd, guard, now, force_rdap, rdap_ttl),
        "dns": lambda: check_dns(nd.host, dns),
        "tls": lambda: inspect_tls(nd.host, guard, now=now),
        "website": lambda: check_website(nd.host, guard),
    }
    results: dict = {}
    errors: list[dict] = []
    pool = ThreadPoolExecutor(max_workers=4)
    futures = {pool.submit(fn): name for name, fn in jobs.items()}
    done, pending = wait(futures, timeout=settings.DOMAIN_CHECK_TIMEOUT)
    for fut in done:
        name = futures[fut]
        try:
            results[name] = fut.result()
        except Exception as exc:  # a failing check must never become a clean result
            log.exception("domain check %s failed", name)
            errors.append({"check": name, "error": exc.__class__.__name__})
    for fut in pending:
        errors.append({"check": futures[fut], "error": "timeout"})
    pool.shutdown(wait=False, cancel_futures=True)
    return {"results": results, "errors": errors}


def _missing_checks(res: dict, errors: list[dict]) -> list[dict]:
    missing = [{"check": e["check"], "reason": e["error"]} for e in errors]
    rdap = res.get("rdap")
    if rdap and rdap["status"] in (st.LOOKUP_UNAVAILABLE, st.UNKNOWN) and not rdap["ok"]:
        missing.append({"check": "rdap", "reason": rdap.get("error") or "unavailable"})
    dns = res.get("dns")
    if dns and dns["status"] == "lookup_failed":
        missing.append({"check": "dns", "reason": "DNS lookups failed or timed out"})
    tls = res.get("tls")
    if tls and tls["status"] in ("UNAVAILABLE", "ERROR"):
        missing.append({"check": "tls", "reason": tls.get("detail") or tls["status"]})
    web = res.get("website")
    if web and (web.get("blocked") or web["hosting_status"] == st.HOSTING_UNKNOWN):
        missing.append({"check": "website", "reason": "; ".join(web.get("evidence", [])) or "not assessed"})
    return missing


def _dt(value):
    return datetime.fromisoformat(value) if value else None


@transaction.atomic
def _store(nd: NormalizedDomain, res: dict, errors: list, now: datetime) -> DomainAssessment:
    rdap = res.get("rdap")
    rdata = (rdap or {}).get("data") or {}
    reg_status = (rdap or {}).get("status") or st.LOOKUP_UNAVAILABLE
    dns, tls, web = res.get("dns"), res.get("tls"), res.get("website")

    health = compute_health(reg_status=reg_status, reg_data=rdata or None, dns=dns, tls=tls, website=web)
    missing = _missing_checks(res, errors)
    expected = 4
    completion = "complete" if not missing else ("failed" if len(missing) >= expected else "partial")
    ttl = (timedelta(hours=_cfg_hours("domain.cache_hours", 24)) if completion == "complete"
           else timedelta(minutes=_cfg_hours("domain.error_cache_minutes", 15)))
    age_days = rdata.get("age_days")
    explanation = rdata.get("status_explanation") or (rdap or {}).get("error") or ""

    a = DomainAssessment.objects.create(
        domain=nd.host, registrable_domain=nd.registrable, display_domain=nd.display_host,
        registration_created_at=_dt(rdata.get("created_at")), registration_age_days=age_days,
        age_group=age_group(age_days), registrar_name=rdata.get("registrar") or "",
        registration_expires_at=_dt(rdata.get("expires_at")), registration_updated_at=_dt(rdata.get("updated_at")),
        raw_status_flags=rdata.get("raw_status_flags", []), registration_status=reg_status,
        registration_status_explanation=explanation, rdap_data=rdata,
        hosting_status=(web or {}).get("hosting_status", st.HOSTING_UNKNOWN),
        dns_status=(dns or {}).get("status", ""), tls_status=(tls or {}).get("status", ""),
        http_status=(web or {}).get("http_status"), dns_results=dns or {}, tls_results=tls or {},
        http_results=web or {}, domain_health_score=health["score"], health_details=health,
        confidence=confidence_from(health["coverage"]), missing_checks=missing, provider_errors=errors,
        completion_status=completion, source_provider=(rdap or {}).get("source") or "",
        error_state="" if not missing else "; ".join(f"{m['check']}: {m['reason']}" for m in missing)[:255],
        engine_version=ENGINE_VERSION, checked_at=now, cache_expires_at=now + ttl,
    )
    obs = [("rdap", rdap, reg_status), ("dns", dns, (dns or {}).get("status", "missing")),
           ("tls", tls, (tls or {}).get("status", "missing")),
           ("http", web, (web or {}).get("hosting_status", "missing"))]
    DomainObservation.objects.bulk_create([
        DomainObservation(assessment=a, observation_type=t, observation_value=v or {},
                          result_status=s, evidence={"missing": any(m["check"] == ("website" if t == "http" else t)
                                                                      for m in missing)}, observed_at=now)
        for t, v, s in obs])
    return a


def assess(value: str, *, user=None, refresh: bool = False, now: datetime | None = None):
    """Returns (assessment, served_from_cache). Raises InvalidDomainInput for bad input."""
    now = now or datetime.now(timezone.utc)
    nd = normalize_domain_input(value)
    cached = None
    if not (refresh and user is not None):
        cached = (DomainAssessment.objects.filter(domain=nd.host, engine_version=ENGINE_VERSION,
                                                  cache_expires_at__gt=now).order_by("-checked_at").first())
    if cached is not None:
        assessment, from_cache = cached, True
    else:
        dns = build_dns_client()
        guard = build_guard(dns)
        out = run_checks(nd, guard=guard, dns=dns, now=now, force_rdap=refresh and user is not None)
        assessment, from_cache = _store(nd, out["results"], out["errors"], now), False
    if user is not None:
        DomainLookup.objects.create(user=user, assessment=assessment, submitted_value=value[:300],
                                    served_from_cache=from_cache)
    return assessment, from_cache
