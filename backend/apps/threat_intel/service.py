"""Runs enabled providers for one query: rate limits, retries, caching, health metrics, persistence.

Never converts a failure into a clean result: the outcome lists every provider with its own status.
"""
import hashlib
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import timedelta

from django.core.cache import cache
from django.db.models import F
from django.utils import timezone

from .models import ThreatIndicator, ThreatProvider
from .providers import (ADAPTERS, CONFIRMED_CATEGORIES, DEFAULTS, STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_OK,
                        STATUS_RATE_LIMITED, STATUS_TIMEOUT, ProviderResult, ProviderSettings, ThreatQuery,
                        read_secret)

log = logging.getLogger(__name__)
TRANSIENT = {STATUS_TIMEOUT, STATUS_ERROR}
SAVE_TTL_HOURS = 24 * 7


def sync_providers() -> None:
    """Create any missing provider rows (idempotent; never overwrites admin settings)."""
    for key, defaults in DEFAULTS.items():
        ThreatProvider.objects.get_or_create(key=key, defaults=defaults)


@dataclass
class ThreatOutcome:
    results: list[ProviderResult] = field(default_factory=list)
    providers_enabled: int = 0

    @property
    def findings(self) -> list[dict]:
        out = []
        for r in self.results:
            if r.status == STATUS_OK:
                for f in r.findings:
                    out.append({"provider": r.provider, "category": f.category, "severity": f.severity,
                                "reference": f.reference, "detail": f.detail})
        return out

    @property
    def confirmed(self) -> list[dict]:
        return [f for f in self.findings if f["category"] in CONFIRMED_CATEGORIES]

    @property
    def ok_providers(self) -> list[str]:
        return [r.provider for r in self.results if r.status == STATUS_OK]

    @property
    def errors(self) -> list[dict]:
        return [{"provider": r.provider, "status": r.status, "error": r.error}
                for r in self.results if r.status != STATUS_OK]

    def summary(self) -> dict:
        return {
            "providers": [{"provider": r.provider, "status": r.status, "error": r.error or None,
                           "checked_at": r.checked_at.isoformat(), "cached": r.cached,
                           "target": getattr(r, "target", None),
                           "finding_count": len(r.findings) if r.status == STATUS_OK else None}
                          for r in self.results],
            "findings": self.findings,
            "providers_enabled": self.providers_enabled,
        }


def _rate_ok(provider: ThreatProvider) -> bool:
    if not provider.rate_limit_per_minute:
        return True
    key = f"ti:rate:{provider.key}:{int(time.time() // 60)}"
    cache.add(key, 0, 70)
    try:
        return cache.incr(key) <= provider.rate_limit_per_minute
    except ValueError:  # pragma: no cover - key expired between add and incr
        return True


def _record(provider: ThreatProvider, result: ProviderResult) -> None:
    """Usage metrics. Called once per provider API attempt (retries count: providers bill per call).
    A 'not configured' outcome made no call, so it counts as an error but not as a request."""
    now = timezone.now()
    updates = {} if result.status == STATUS_NOT_CONFIGURED else {"request_count": F("request_count") + 1}
    if result.status == STATUS_OK:
        updates["last_success_at"] = now
    else:   # every non-ok outcome (including "not configured") counts as an error in the health metrics
        updates.update(error_count=F("error_count") + 1, last_error_at=now, last_error=(result.error or result.status)[:255])
    ThreatProvider.objects.filter(pk=provider.pk).update(**updates)


def _persist(result: ProviderResult, q: ThreatQuery) -> None:
    if result.status != STATUS_OK or result.provider == "local_blocklist":
        return
    now = timezone.now()
    for f in result.findings:
        obj, created = ThreatIndicator.objects.get_or_create(
            indicator=q.url[:2048], provider=result.provider, threat_category=f.category,
            defaults=dict(indicator_type="url", severity=f.severity, source_reference=f.reference[:255],
                          first_seen_at=now, last_seen_at=now, checked_at=now,
                          expires_at=now + timedelta(hours=SAVE_TTL_HOURS)))
        if not created:
            ThreatIndicator.objects.filter(pk=obj.pk).update(
                last_seen_at=now, checked_at=now, severity=f.severity, expires_at=now + timedelta(hours=SAVE_TTL_HOURS))


def check_url(q: ThreatQuery, *, guard) -> ThreatOutcome:
    """Query every enabled provider. Sequential, each bounded by its own timeout and retry budget."""
    providers = list(ThreatProvider.objects.filter(enabled=True))
    outcome = ThreatOutcome(providers_enabled=len(providers))
    for p in providers:
        adapter_cls = ADAPTERS.get(p.key)
        if adapter_cls is None:
            outcome.results.append(ProviderResult(p.key, STATUS_ERROR, error="No adapter is installed for this provider."))
            continue
        cache_ttl = int((p.config or {}).get("cache_ttl_seconds", 0) or 0)
        ck = "ti:res:%s:%s" % (p.key, hashlib.sha256(q.url.encode()).hexdigest()[:32])
        if cache_ttl:
            hit = cache.get(ck)
            if hit is not None:
                hit.cached = True
                outcome.results.append(hit)
                continue
        if not _rate_ok(p):
            res = ProviderResult(p.key, STATUS_RATE_LIMITED, error="ScanSentry's own rate limit for this provider was reached.")
            outcome.results.append(res)
            continue
        settings_ = ProviderSettings(timeout=p.timeout_seconds, attempts=max(1, p.retry_attempts),
                                     config=p.config or {}, secret=read_secret(p.credential_ref))
        adapter = adapter_cls(guard)
        result = None
        for attempt in range(settings_.attempts):
            started = time.monotonic()
            try:
                result = adapter.check(q, settings_)
            except Exception as exc:   # an adapter bug must not become a clean result or a 500
                log.exception("threat provider %s crashed", p.key)
                result = ProviderResult(p.key, STATUS_ERROR, error=f"adapter error: {exc.__class__.__name__}")
            result.latency_ms = int((time.monotonic() - started) * 1000)
            _record(p, result)
            if result.status not in TRANSIENT:
                break
            if attempt + 1 < settings_.attempts:
                time.sleep(0.05 * (attempt + 1))
        _persist(result, q)
        if cache_ttl and result.status == STATUS_OK:
            cache.set(ck, result, cache_ttl)
        outcome.results.append(result)
    return outcome
