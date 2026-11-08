"""Maintainable rule engine.

Each rule has: key, name, description, category, severity, strength (weak/moderate/strong), default weight,
recommended action, version and detection logic. Detection lives here; administrators tune enabled, weight,
severity and thresholds in the database (SecurityRule) without a deploy.

STRENGTH matters: weak indicators (domain age, URL shortening, missing TLS, unusual TLD, IDN) can add up to
"suspicious" but can never reach "high risk" on their own (see scoring.py).
"""
import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

from apps.core.config import get_config

from .lookalike import DEFAULT_BRANDS, find_brand_keyword, find_lookalikes

DEFAULT_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
                      "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bit.do", "s.id", "t.ly", "lnkd.in"]
# Abuse-heavy TLDs are a *contextual* signal only (many legitimate sites use them).
DEFAULT_UNUSUAL_TLDS = ["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
                        "support", "rest", "surf"]


@dataclass
class RuleContext:
    raw: str
    kind: str                                  # url | blocked_scheme | unsupported_scheme
    url: dict | None = None                    # facts from scanner.analysis.analyze_url
    observations: list = field(default_factory=list)
    normalized: str | None = None
    host: str | None = None
    display_host: str | None = None
    registrable: str | None = None
    display_registrable: str | None = None
    scheme: str | None = None
    domain: dict | None = None                 # presented DomainAssessment of the effective host
    threat: dict | None = None                 # {"findings": [...]}
    trace: dict | None = None                  # redirect trace of a shortened link
    original_host: str | None = None           # host of the submitted link when it was shortened
    brands: list = field(default_factory=lambda: list(DEFAULT_BRANDS))
    shorteners: list = field(default_factory=lambda: list(DEFAULT_SHORTENERS))
    unusual_tlds: list = field(default_factory=lambda: list(DEFAULT_UNUSUAL_TLDS))

    def has_obs(self, code: str) -> bool:
        return any(o.get("code") == code for o in self.observations)


@dataclass
class Detection:
    reason_code: str
    message: str
    evidence: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RuleDef:
    key: str
    name: str
    description: str
    category: str
    severity: str
    strength: str
    weight: int
    recommended_action: str
    detect: Callable[[RuleContext, dict], Detection | None]
    version: int = 1
    params: dict = field(default_factory=dict)


REGISTRY: dict[str, RuleDef] = {}


def rule(**kw):
    def deco(fn):
        REGISTRY[kw["key"]] = RuleDef(detect=fn, **kw)
        return fn
    return deco


# ---- URL structure --------------------------------------------------------------------------------
@rule(key="url.malformed", name="Malformed URL", category="url", severity="medium", strength="moderate", weight=30,
      description="The link could not be parsed as a valid web address.",
      recommended_action="Do not open this link; ask the sender for the correct address.")
def _malformed(c, p):
    if c.kind == "url" and not c.normalized and not (c.has_obs("embedded_credentials") or c.has_obs("encoded_host")):
        return Detection("malformed_url", "The link is not a valid web address.", {"length": len(c.raw)})


@rule(key="url.dangerous_scheme", name="Dangerous URL scheme", category="url", severity="critical", strength="strong",
      weight=70, description="javascript:, data:, file: and similar schemes can run code or read local data.",
      recommended_action="Never open this. It is not a normal web link.")
def _dangerous(c, p):
    if c.kind == "blocked_scheme":
        return Detection("dangerous_scheme", "The code uses a scheme that can execute code or access local data.",
                         {"scheme": (c.url or {}).get("scheme")})


@rule(key="url.unsupported_scheme", name="Unsupported URL scheme", category="url", severity="medium", strength="moderate",
      weight=20, description="A custom or uncommon scheme that ScanSentry does not open.",
      recommended_action="Only open it if you trust where the code came from and know which app it targets.")
def _unsupported(c, p):
    if c.kind == "unsupported_scheme":
        return Detection("unsupported_scheme", "The code uses an uncommon application link.", {})


@rule(key="url.credentials_in_url", name="Credentials in URL", category="url", severity="high", strength="strong", weight=45,
      description="A user@host section can make a link appear to point to a trusted site.",
      recommended_action="Do not open. Look at the text after the @ sign: that is the real destination.")
def _creds(c, p):
    if c.has_obs("embedded_credentials"):
        return Detection("embedded_credentials", "The address contains a username before the host name.", {})


@rule(key="url.encoded_host", name="Encoded host name", category="url", severity="high", strength="strong", weight=45,
      description="Percent-encoding inside the host name hides the real destination.",
      recommended_action="Do not open this link.")
def _enc_host(c, p):
    if c.has_obs("encoded_host"):
        return Detection("encoded_host", "The host name contains percent-encoded characters.", {})


@rule(key="url.ip_host", name="IP-address URL", category="url", severity="medium", strength="moderate", weight=25,
      description="Legitimate services rarely ask people to visit a bare IP address.",
      recommended_action="Be cautious; ask the publisher for the web address of the service.")
def _ip(c, p):
    if c.host:
        try:
            ipaddress.ip_address(c.host.strip("[]"))
            return Detection("ip_address_host", "The link goes to a numeric address rather than a named website.", {"host": c.host})
        except ValueError:
            pass


@rule(key="url.obfuscated_ip", name="Obfuscated IP address", category="url", severity="high", strength="strong", weight=40,
      description="Decimal or hexadecimal numbers used as a host name disguise an IP address.",
      recommended_action="Do not open this link.")
def _obf_ip(c, p):
    if c.host and re.fullmatch(r"\d+|0x[0-9a-f]+", c.host, re.I):
        return Detection("obfuscated_ip", "The host name is a disguised numeric address.", {"host": c.host})


@rule(key="url.punycode_idn", name="International host name", category="url", severity="low", strength="weak", weight=10,
      description="Host names with non-English characters are legitimate, but can imitate other sites.",
      recommended_action="Check the displayed host name carefully before entering any details.")
def _idn(c, p):
    if (c.url or {}).get("is_idn"):
        return Detection("idn_host", "The host name uses international characters.",
                         {"punycode": c.host, "display": c.display_host})


@rule(key="url.mixed_scripts", name="Mixed-alphabet host name", category="url", severity="high", strength="strong", weight=45,
      description="Mixing alphabets (e.g. Latin and Cyrillic) is a classic way to imitate another website.",
      recommended_action="Do not enter any details. Type the real website address yourself.")
def _mixed(c, p):
    if (c.url or {}).get("mixed_scripts"):
        return Detection("mixed_scripts", "The host name mixes alphabets, which can imitate another site.",
                         {"punycode": c.host, "display": c.display_host})


@rule(key="url.lookalike_brand", name="Look-alike of a known brand", category="impersonation", severity="high",
      strength="strong", weight=50, description="The domain imitates a well-known brand (look-alike characters, "
      "a one-letter difference, or the brand used as a sub-domain of another domain).",
      recommended_action="Do not sign in or pay. Go to the brand's real website by typing its address.")
def _lookalike(c, p):
    if c.display_host and c.display_registrable:
        hits = find_lookalikes(c.display_host, c.display_registrable, c.brands)
        if hits:
            return Detection("brand_lookalike", hits[0]["detail"], {"matches": hits[:3]})


@rule(key="url.brand_keyword_combo", name="Brand name with sensitive keyword", category="impersonation", severity="medium",
      strength="moderate", weight=30, description="A brand name plus words like login, secure or verify in an unrelated domain.",
      recommended_action="Be cautious: real brands use their own domain for sign-in pages.")
def _combo(c, p):
    if c.display_host and c.display_registrable:
        hits = find_brand_keyword(c.display_host, c.display_registrable, c.brands)
        if hits:
            return Detection("brand_keyword_combo",
                             f"The address pairs '{hits[0]['brand'].split('.')[0]}' with {', '.join(hits[0]['keywords'])}.",
                             {"matches": hits[:3]})


@rule(key="url.excessive_subdomains", name="Excessive sub-domains", category="url", severity="low", strength="weak", weight=10,
      params={"min_labels": 4}, description="Very long chains of sub-domains are used to bury the real domain.",
      recommended_action="Read the host name from right to left: the real domain is the last two parts.")
def _subs(c, p):
    if c.host and c.registrable and c.host != c.registrable:
        extra = len(c.host.split(".")) - len(c.registrable.split("."))
        if extra >= int(p.get("min_labels", 4)):
            return Detection("many_subdomains", f"The host has {extra} sub-domain levels in front of {c.registrable}.",
                             {"extra_levels": extra})


@rule(key="url.encoding_unusual", name="Unusual URL encoding", category="url", severity="medium", strength="moderate", weight=20,
      description="Double-encoding, encoded control characters, or hidden direction-control characters.",
      recommended_action="Do not open the link; ask the sender for a plain address.")
def _encoding(c, p):
    raw = c.normalized or c.raw
    found = []
    if re.search(r"%25[0-9a-f]{2}", raw, re.I):
        found.append("double_encoding")
    if re.search(r"%(00|0a|0d|1b)", raw, re.I):
        found.append("encoded_control_characters")
    if re.search(r"%2e%2e|%252e", raw, re.I):
        found.append("encoded_path_traversal")
    if any(unicodedata.category(ch) == "Cf" for ch in c.raw):
        found.append("hidden_direction_or_format_characters")
    if found:
        return Detection("unusual_encoding", "The address uses unusual encoding: " + ", ".join(found) + ".", {"found": found})


@rule(key="url.redirect_parameter", name="Redirect parameter", category="redirect", severity="low", strength="weak", weight=10,
      description="The link carries another web address in a parameter, so it may forward you elsewhere.",
      recommended_action="Check where you end up before entering any details.")
def _redir_param(c, p):
    if c.has_obs("redirect_parameter"):
        return Detection("redirect_parameter", "The link carries another address in one of its parameters.", {})


@rule(key="url.shortener", name="URL shortener", category="redirect", severity="low", strength="weak", weight=10,
      description="Shortened links hide their destination. Legitimate and malicious links both use them.",
      recommended_action="Check where the link actually leads before continuing.")
def _shortener(c, p):
    host = c.original_host or c.host
    if host and (host in c.shorteners or ".".join(host.split(".")[-2:]) in c.shorteners):
        return Detection("url_shortener", "The link uses a URL-shortening service, which hides its destination.", {"host": host})


@rule(key="url.unusual_tld", name="Uncommon top-level domain", category="url", severity="low", strength="weak", weight=6,
      description="Some TLDs are heavily abused, though many legitimate sites use them too.",
      recommended_action="Treat as a minor signal only; judge the site on other evidence.")
def _tld(c, p):
    if c.host and c.host.rsplit(".", 1)[-1] in c.unusual_tlds:
        return Detection("unusual_tld", f"The domain ends in .{c.host.rsplit('.', 1)[-1]}, which is abused more often than average.", {})


@rule(key="redirect.suspicious_chain", name="Suspicious redirect chain", category="redirect", severity="medium",
      strength="moderate", weight=25, params={"max_domains": 3},
      description="The link passes through several unrelated domains, loops, or hits a forbidden destination.",
      recommended_action="Do not continue; the final destination is being deliberately obscured.")
def _chain(c, p):
    t = c.trace
    if not t:
        return None
    reasons = []
    if t.get("error") in ("redirect_loop", "too_many_redirects"):
        reasons.append(t["error"])
    if t.get("error") == "blocked_destination":
        reasons.append("redirect_to_forbidden_destination")
    if t.get("distinct_registrable_domains", 0) >= int(p.get("max_domains", 3)):
        reasons.append("many_unrelated_domains")
    if reasons:
        return Detection("redirect_chain", "The redirect chain is suspicious: " + ", ".join(reasons) + ".",
                         {"reasons": reasons, "hops": t.get("hop_count")})


# ---- domain facts (from Domain Intelligence) ---------------------------------------------------------------------
@rule(key="tls.no_https", name="No HTTPS", category="tls", severity="low", strength="weak", weight=8,
      description="The site does not offer an encrypted connection. This alone says nothing about intent.",
      recommended_action="Do not enter passwords or payment details on unencrypted pages.")
def _no_https(c, p):
    tls = (c.domain or {}).get("tls") or {}
    if c.scheme == "http" or tls.get("status") == "NO_HTTPS":
        return Detection("no_https", "The destination does not use an encrypted (HTTPS) connection.", {"scheme": c.scheme})


@rule(key="tls.invalid_certificate", name="Invalid certificate", category="tls", severity="medium", strength="moderate",
      weight=20, description="The site's certificate is expired, not yet valid, for another name, or untrusted.",
      recommended_action="Do not proceed past a browser certificate warning.")
def _bad_cert(c, p):
    tls = (c.domain or {}).get("tls") or {}
    if tls.get("status") in ("EXPIRED", "NOT_YET_VALID", "HOSTNAME_MISMATCH", "SELF_SIGNED", "UNTRUSTED_CHAIN"):
        return Detection("invalid_certificate", tls.get("message") or "The certificate is not valid.", {"status": tls["status"]})


@rule(key="domain.registry_hold", name="Domain on hold", category="domain", severity="medium", strength="moderate", weight=20,
      description="The registry or registrar has put this domain on hold (often after abuse or non-payment).",
      recommended_action="The destination may be taken down; do not rely on it.")
def _hold(c, p):
    reg = ((c.domain or {}).get("registration") or {}).get("status")
    if reg in ("REGISTRY_HOLD", "REGISTRAR_HOLD"):
        return Detection("registry_hold", "The domain is on hold at the registry or registrar.", {"status": reg})


@rule(key="domain.recently_registered", name="Recently registered domain", category="domain", severity="low", strength="weak",
      weight=12, params={"threshold_days": 90},
      description="New domains are used by both new businesses and attackers. Age alone proves nothing.",
      recommended_action="Look for independent signs the organisation is real before sharing details.")
def _young(c, p):
    reg = (c.domain or {}).get("registration") or {}
    age = reg.get("age_days")
    if age is not None and age < int(p.get("threshold_days", 90)):
        return Detection("recently_registered", f"The domain was registered about {age} day(s) ago.", {"age_days": age})


@rule(key="domain.non_public_resolution", name="Resolves to a private address", category="domain", severity="medium",
      strength="moderate", weight=25, description="The public domain points at an internal/private network address.",
      recommended_action="Do not open; this can be used to attack devices on your network.")
def _private_res(c, p):
    web = (c.domain or {}).get("website") or {}
    miss = [m for m in (c.domain or {}).get("missing_checks", []) if m.get("check") == "website"]
    if miss and "non-public" in " ".join(web.get("evidence", []) + [m.get("reason", "") for m in miss]).lower():
        return Detection("non_public_resolution", "The domain resolves to a private or non-public network address.", {})


# ---- threat intelligence ---------------------------------------------------------------------------------------------
def _intel(c, category):
    return [f for f in ((c.threat or {}).get("findings") or []) if f["category"] == category]


@rule(key="intel.known_malware", name="Known malware indicator", category="threat_intel", severity="critical", strength="strong",
      weight=100, description="A threat-intelligence provider lists this destination as distributing malware.",
      recommended_action="Do not open. ScanSentry will not forward you to this destination.")
def _malware(c, p):
    hits = _intel(c, "malware")
    if hits:
        return Detection("known_malware", "A threat-intelligence source lists this destination for malware.",
                         {"sources": [{"provider": h["provider"], "reference": h["reference"]} for h in hits]})


@rule(key="intel.known_phishing", name="Known phishing indicator", category="threat_intel", severity="critical", strength="strong",
      weight=100, description="A threat-intelligence provider lists this destination as a phishing/social-engineering site.",
      recommended_action="Do not open or enter any details. ScanSentry will not forward you to this destination.")
def _phish(c, p):
    hits = _intel(c, "phishing")
    if hits:
        return Detection("known_phishing", "A threat-intelligence source lists this destination for phishing.",
                         {"sources": [{"provider": h["provider"], "reference": h["reference"]} for h in hits]})


@rule(key="intel.unwanted_software", name="Unwanted software indicator", category="threat_intel", severity="high",
      strength="strong", weight=55, description="A provider lists this destination for unwanted or deceptive software.",
      recommended_action="Do not download or install anything from this destination.")
def _unwanted(c, p):
    hits = _intel(c, "unwanted_software")
    if hits:
        return Detection("unwanted_software", "A threat-intelligence source lists this destination for unwanted software.",
                         {"sources": [{"provider": h["provider"], "reference": h["reference"]} for h in hits]})


@rule(key="intel.suspicious_listing", name="Suspicious listing", category="threat_intel", severity="medium", strength="moderate",
      weight=30, description="A provider flags this destination as suspicious without confirming a specific threat.",
      recommended_action="Be cautious and verify through an independent channel.")
def _suspicious_listing(c, p):
    hits = _intel(c, "suspicious") + _intel(c, "other")
    if hits:
        return Detection("suspicious_listing", "A threat-intelligence source flags this destination as suspicious.",
                         {"sources": [{"provider": h["provider"], "reference": h["reference"]} for h in hits]})


# ---- configuration / effective rules ------------------------------------------------------------------------------------
@dataclass
class EffectiveRule:
    defn: RuleDef
    enabled: bool
    weight: int
    severity: str
    params: dict


def sync_rules() -> None:
    """Create missing SecurityRule rows and refresh code-owned fields (never admin-tunable ones)."""
    from .models import SecurityRule
    for d in REGISTRY.values():
        row, created = SecurityRule.objects.get_or_create(key=d.key, defaults=dict(
            name=d.name, description=d.description, category=d.category, strength=d.strength, severity=d.severity,
            weight=d.weight, params=d.params, recommended_action=d.recommended_action, version=d.version))
        if not created and row.version < d.version:
            SecurityRule.objects.filter(pk=row.pk).update(
                name=d.name, description=d.description, category=d.category, strength=d.strength,
                recommended_action=d.recommended_action, version=d.version)


def effective_rules() -> list[EffectiveRule]:
    from .models import SecurityRule
    rows = {r.key: r for r in SecurityRule.objects.all()}
    out = []
    for key, d in REGISTRY.items():
        r = rows.get(key)
        out.append(EffectiveRule(
            defn=d, enabled=r.enabled if r else True, weight=r.weight if r else d.weight,
            severity=r.severity if r else d.severity, params={**d.params, **((r.params if r else {}) or {})}))
    return out


def ruleset_hash(rules: list[EffectiveRule]) -> str:
    blob = json.dumps([[r.defn.key, r.defn.version, r.enabled, r.weight, r.severity, r.params]
                       for r in sorted(rules, key=lambda x: x.defn.key)], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def load_lists() -> dict:
    """Admin-editable lists (AppConfiguration) with safe defaults."""
    def lst(key, default):
        v = get_config(key, None)
        return [str(x).lower() for x in v] if isinstance(v, list) and v else list(default)
    return {"brands": lst("security.brand_domains", DEFAULT_BRANDS),
            "shorteners": lst("security.url_shorteners", DEFAULT_SHORTENERS),
            "unusual_tlds": lst("security.unusual_tlds", DEFAULT_UNUSUAL_TLDS)}


def evaluate(ctx: RuleContext, rules: list[EffectiveRule]) -> list[dict]:
    """Run every enabled rule. A rule that crashes is reported as an error, never as 'not triggered'."""
    results = []
    for er in rules:
        if not er.enabled:
            continue
        d = er.defn
        try:
            det = d.detect(ctx, er.params)
        except Exception as exc:
            results.append({"rule": d.key, "name": d.name, "status": "error", "error": exc.__class__.__name__,
                            "version": d.version})
            continue
        if det is not None:
            results.append({"rule": d.key, "name": d.name, "category": d.category, "severity": er.severity,
                            "strength": d.strength, "weight": er.weight, "reason_code": det.reason_code,
                            "message": det.message, "evidence": det.evidence, "recommended_action": d.recommended_action,
                            "version": d.version, "status": "triggered"})
    return results
