"""RDAP client (bootstrap -> registry), parsing and result shaping. No data is ever invented."""
import json
from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache

from . import status as st
from .netsafe import NetGuard

BOOTSTRAP_CACHE_KEY = "rdap:bootstrap:v1"
BOOTSTRAP_TTL = 24 * 3600
RDAP_MAX_BODY = 512 * 1024
AGE_NOTE = ("The registration date shows when this domain name was first registered (or last "
            "re-registered). It does not prove who owns the domain now, how long the current owner has "
            "held it, or whether the site is trustworthy.")


def _parse_dt(value) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_bootstrap(guard: NetGuard) -> tuple[dict | None, str | None]:
    cached = cache.get(BOOTSTRAP_CACHE_KEY)
    if cached:
        return cached, None
    res = guard.fetch(settings.RDAP_BOOTSTRAP_URL, accept="application/json", max_body=RDAP_MAX_BODY,
                      require_https=True)
    if not res.ok or res.status != 200:
        return None, res.error or f"http_{res.status}"
    try:
        data = json.loads(res.text)
        mapping: dict[str, str] = {}
        for tlds, urls in data.get("services", []):
            https = [u for u in urls if u.startswith("https://")]
            if https:
                for tld in tlds:
                    mapping[tld.lower()] = https[0].rstrip("/")
    except (ValueError, TypeError):
        return None, "bootstrap_parse_error"
    cache.set(BOOTSTRAP_CACHE_KEY, mapping, BOOTSTRAP_TTL)
    return mapping, None


def _registrar_name(entities) -> str | None:
    for ent in entities or []:
        if "registrar" in [r.lower() for r in ent.get("roles", [])]:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop and prop[0] == "fn" and len(prop) > 3 and prop[3]:
                        return str(prop[3])[:200]
            for pid in ent.get("publicIds", []) or []:
                if pid.get("identifier"):
                    return f"IANA ID {pid['identifier']}"
    return None


def parse_rdap_domain(data: dict, *, now: datetime) -> dict:
    events = []
    created = expires = updated = reregistered = None
    for ev in data.get("events", []) or []:
        action, when = str(ev.get("eventAction", "")).lower(), _parse_dt(ev.get("eventDate"))
        if not when:
            continue
        events.append({"action": action, "date": when.isoformat()})
        if action == "registration":
            created = created or when
        elif action == "expiration":
            expires = expires or when
        elif action == "last changed":
            updated = updated or when
        elif action == "reregistration":
            reregistered = reregistered or when
    nameservers = sorted({str(ns.get("ldhName", "")).lower().rstrip(".")
                          for ns in data.get("nameservers", []) or [] if ns.get("ldhName")})
    flags = [str(s) for s in data.get("status", []) or []]
    not_disclosed = [name for name, val in (("registration_date", created), ("expiration_date", expires),
                                            ("registrar", _registrar_name(data.get("entities")))) if not val]
    classification, explanation = st.classify_registration(flags, expires_at=expires, now=now)
    effective_start = reregistered or created
    return {
        "created_at": created.isoformat() if created else None,
        "reregistered_at": reregistered.isoformat() if reregistered else None,
        "expires_at": expires.isoformat() if expires else None,
        "updated_at": updated.isoformat() if updated else None,
        "age_days": max(0, (now - effective_start).days) if effective_start else None,
        "registrar": _registrar_name(data.get("entities")),
        "raw_status_flags": flags,
        "status": classification,
        "status_explanation": explanation,
        "nameservers": nameservers,
        "dnssec_signed": (data.get("secureDNS") or {}).get("delegationSigned"),
        "events": events[:20],
        "not_disclosed": not_disclosed,
        "age_note": AGE_NOTE,
    }


def lookup_rdap(registrable: str, tld: str, guard: NetGuard, *, now: datetime | None = None) -> dict:
    """Returns {"ok": bool, "status": classification, "data": parsed|None, "source": url, "error": str|None}."""
    now = now or datetime.now(timezone.utc)
    observed = now.isoformat()
    mapping, err = load_bootstrap(guard)
    base = (mapping or {}).get(tld)
    if mapping is None:
        base = (settings.RDAP_PROVIDER_CONFIG or {}).get("fallback_base")
        if not base:
            return {"ok": False, "status": st.LOOKUP_UNAVAILABLE, "data": None, "source": None,
                    "error": f"RDAP bootstrap unavailable ({err}).", "observed_at": observed}
    elif base is None:
        base = (settings.RDAP_PROVIDER_CONFIG or {}).get("fallback_base")
        if not base:
            return {"ok": False, "status": st.UNKNOWN, "data": None, "source": None,
                    "error": f".{tld} does not publish RDAP service in the IANA registry, so registration "
                             "data is not available.", "rdap_supported": False, "observed_at": observed}
    url = f"{base.rstrip('/')}/domain/{registrable}"
    res = guard.fetch(url, accept="application/rdap+json, application/json", max_body=RDAP_MAX_BODY,
                      require_https=True)
    out = {"source": url, "observed_at": observed, "data": None, "error": None, "ok": False}
    if res.error:
        out.update(status=st.LOOKUP_UNAVAILABLE, error=f"{res.error}: {res.error_detail}")
        return out
    if res.status == 404:
        out.update(ok=True, status=st.NOT_FOUND,
                   error=None, data={"status": st.NOT_FOUND, "raw_status_flags": [], "created_at": None,
                                     "expires_at": None, "updated_at": None, "age_days": None,
                                     "registrar": None, "nameservers": [], "events": [], "not_disclosed": [],
                                     "status_explanation": "The registry reports that this domain is not "
                                                           "registered.", "age_note": AGE_NOTE,
                                     "reregistered_at": None, "dnssec_signed": None})
        return out
    if res.status in (429, 500, 502, 503, 504):
        out.update(status=st.LOOKUP_UNAVAILABLE, error=f"The RDAP server returned HTTP {res.status}.")
        return out
    if res.status != 200:
        out.update(status=st.UNKNOWN, error=f"The RDAP server returned HTTP {res.status}.")
        return out
    try:
        parsed = parse_rdap_domain(json.loads(res.text), now=now)
    except (ValueError, TypeError, AttributeError):
        out.update(status=st.UNKNOWN, error="The RDAP response could not be parsed.")
        return out
    out.update(ok=True, status=parsed["status"], data=parsed)
    return out
