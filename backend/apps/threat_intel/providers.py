"""Threat-intelligence provider adapters.

An adapter turns "is this URL/host known to be bad?" into a ProviderResult. Rules every adapter follows:
  * a finding is only ever reported when the provider answered successfully
  * any failure (timeout, bad credentials, rate limit, outage, unparsable answer) returns a non-"ok"
    status - it is NEVER converted into a clean result
  * secrets come from the environment at call time; they are never logged or returned
Licensing: do not enable a provider for commercial production use without checking its terms.
Google Web Risk is the commercially licensed Google service; VirusTotal's public API and the free Safe
Browsing API are non-commercial and are intentionally NOT included.
"""
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from django.db.models import Q
from django.utils import timezone as djtz

# ---- result types ---------------------------------------------------------------------------
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_NOT_CONFIGURED = "not_configured"

CATEGORIES = {"malware", "phishing", "unwanted_software", "suspicious", "other"}
CONFIRMED_CATEGORIES = {"malware", "phishing"}          # these make a destination "known malicious"


@dataclass
class ProviderFinding:
    category: str
    severity: str = "high"
    reference: str = ""
    detail: str = ""


@dataclass
class ProviderResult:
    provider: str
    status: str
    findings: list[ProviderFinding] = field(default_factory=list)
    error: str = ""
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: int = 0
    cached: bool = False


@dataclass
class ThreatQuery:
    url: str            # query string and fragment already removed
    host: str
    registrable: str | None


@dataclass
class ProviderSettings:
    timeout: float
    attempts: int
    config: dict
    secret: str | None


class BaseProvider:
    key = ""
    display_name = ""
    commercial_note = ""
    needs_credential = False
    external = True        # a real reputation source (vs. staff-managed local data)

    def __init__(self, guard=None):
        self.guard = guard

    def check(self, q: ThreatQuery, s: ProviderSettings) -> ProviderResult:  # pragma: no cover - interface
        raise NotImplementedError


# ---- local blocklist (staff-managed indicators + saved findings) --------------------------------------
class LocalBlocklistProvider(BaseProvider):
    key = "local_blocklist"
    external = False
    display_name = "ScanSentry blocklist"
    commercial_note = "Internal data; no third-party terms."

    def check(self, q, s):
        """Only staff-managed entries (provider="local_blocklist"). Findings saved from external providers
        are kept as evidence/history and are deliberately NOT re-served here (they go stale and may not be
        reusable under the provider's terms)."""
        from .models import ThreatIndicator
        now = djtz.now()
        hosts = {q.host} | ({q.registrable} if q.registrable else set())
        rows = ThreatIndicator.objects.filter(provider=self.key, active=True).filter(
            Q(expires_at__isnull=True) | Q(expires_at__gt=now)).filter(
            Q(indicator_type="domain", indicator__in=hosts) | Q(indicator_type="url", indicator=q.url))
        findings = [ProviderFinding(r.threat_category, r.severity, r.source_reference or "local",
                                    r.note or "Listed on the ScanSentry blocklist.") for r in rows]
        return ProviderResult(self.key, STATUS_OK, findings)


# ---- controlled test fixture (disabled by default) -----------------------------------------------------
FIXTURE_PATH = Path(__file__).parent / "data" / "test_indicators.json"


class TestFixtureProvider(BaseProvider):
    __test__ = False   # not a pytest class
    key = "test_fixture"
    display_name = "Test fixture (development only)"
    commercial_note = "Local controlled test data. Keep disabled in production."

    def check(self, q, s):
        data = json.loads(FIXTURE_PATH.read_text())
        for row in data["indicators"]:
            if row["host"] in (q.host, q.registrable):
                if row["verdict"] == "harmless":
                    return ProviderResult(self.key, STATUS_OK, [])
                return ProviderResult(self.key, STATUS_OK, [ProviderFinding(
                    row["category"], row["severity"], row.get("reference", ""), "Matched controlled test indicator.")])
        return ProviderResult(self.key, STATUS_OK, [])


# ---- Google Web Risk (commercial Lookup API) -------------------------------------------------------------------
_WEB_RISK_MAP = {"MALWARE": ("malware", "critical"), "SOCIAL_ENGINEERING": ("phishing", "critical"),
                 "UNWANTED_SOFTWARE": ("unwanted_software", "medium")}


class GoogleWebRiskProvider(BaseProvider):
    """https://cloud.google.com/web-risk - requires a Google Cloud project with billing and the Web Risk API
    enabled. Credential: set the env var named in credential_ref (default THREAT_INTEL_API_KEY)."""

    key = "google_web_risk"
    display_name = "Google Web Risk"
    commercial_note = "Commercially licensed Google Cloud service (paid). Review pricing and terms before enabling."
    needs_credential = True
    ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"

    def check(self, q, s):
        if not s.secret:
            return ProviderResult(self.key, STATUS_NOT_CONFIGURED, error="No API key is configured.")
        url = (self.ENDPOINT + "?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE"
               f"&uri={quote(q.url, safe='')}")
        res = self.guard.fetch(url, accept="application/json", require_https=True, max_body=64 * 1024,
                               headers={"x-goog-api-key": s.secret})   # key travels in a header, not the URL
        if res.error == "timeout":
            return ProviderResult(self.key, STATUS_TIMEOUT, error="The provider did not answer in time.")
        if res.error:
            return ProviderResult(self.key, STATUS_ERROR, error=f"{res.error}: {res.error_detail}")
        if res.status == 429:
            return ProviderResult(self.key, STATUS_RATE_LIMITED, error="The provider rate-limited the request.")
        if res.status in (401, 403):
            return ProviderResult(self.key, STATUS_ERROR, error="The provider rejected the credentials.")
        if res.status != 200:
            return ProviderResult(self.key, STATUS_ERROR, error=f"The provider returned HTTP {res.status}.")
        try:
            threat = (json.loads(res.text) or {}).get("threat") or {}
            types = threat.get("threatTypes") or []
        except (ValueError, AttributeError, TypeError):
            return ProviderResult(self.key, STATUS_ERROR, error="The provider response could not be parsed.")
        findings = []
        for t in types:
            category, severity = _WEB_RISK_MAP.get(t, ("other", "medium"))
            findings.append(ProviderFinding(category, severity, f"webrisk:{t}", f"Listed by Google Web Risk as {t}."))
        return ProviderResult(self.key, STATUS_OK, findings)


ADAPTERS: dict[str, type[BaseProvider]] = {
    LocalBlocklistProvider.key: LocalBlocklistProvider,
    TestFixtureProvider.key: TestFixtureProvider,
    GoogleWebRiskProvider.key: GoogleWebRiskProvider,
}

# Providers created on migrate (disabled unless noted). Local blocklist is internal and on by default.
DEFAULTS = {
    "local_blocklist": dict(name=LocalBlocklistProvider.display_name, enabled=True, credential_ref="",
                            rate_limit_per_minute=0),
    "google_web_risk": dict(name=GoogleWebRiskProvider.display_name, enabled=False,
                            credential_ref="THREAT_INTEL_API_KEY", rate_limit_per_minute=60),
    "test_fixture": dict(name=TestFixtureProvider.display_name, enabled=False, credential_ref="",
                         rate_limit_per_minute=0),
}


def read_secret(credential_ref: str) -> str | None:
    return os.environ.get(credential_ref) if credential_ref else None
