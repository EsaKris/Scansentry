"""Map RDAP/EPP status flags and website observations to ScanSentry classifications."""
import re
from datetime import datetime, timedelta, timezone

# ---- registration (registry / registrar) ---------------------------------------------------------
REGISTERED_ACTIVE = "REGISTERED_ACTIVE"
REGISTRY_HOLD = "REGISTRY_HOLD"
REGISTRAR_HOLD = "REGISTRAR_HOLD"
REDEMPTION_PERIOD = "REDEMPTION_PERIOD"
PENDING_DELETION = "PENDING_DELETION"
INACTIVE_OR_UNDELEGATED = "INACTIVE_OR_UNDELEGATED"
EXPIRED_OR_NOT_RENEWED = "EXPIRED_OR_NOT_RENEWED"
NOT_FOUND = "NOT_FOUND"
UNKNOWN = "UNKNOWN"
LOOKUP_UNAVAILABLE = "LOOKUP_UNAVAILABLE"

REGISTRATION_STATES = [REGISTERED_ACTIVE, REGISTRY_HOLD, REGISTRAR_HOLD, REDEMPTION_PERIOD,
                       PENDING_DELETION, INACTIVE_OR_UNDELEGATED, EXPIRED_OR_NOT_RENEWED,
                       NOT_FOUND, UNKNOWN, LOOKUP_UNAVAILABLE]

# Protective locks: normal, NOT a suspension.
LOCK_FLAGS = {"clienttransferprohibited", "servertransferprohibited", "clientdeleteprohibited",
              "serverdeleteprohibited", "clientupdateprohibited", "serverupdateprohibited",
              "clientrenewprohibited", "serverrenewprohibited"}
BENIGN_FLAGS = LOCK_FLAGS | {"ok", "active", "autorenewperiod", "addperiod", "renewperiod",
                             "transferperiod", "associated", "validated", "pendingcreate",
                             "pendingupdate", "pendingtransfer", "pendingrenew"}


def _key(flag: str) -> str:
    return re.sub(r"[^a-z]", "", flag.lower())


def classify_registration(flags: list[str], *, expires_at: datetime | None = None,
                          now: datetime | None = None) -> tuple[str, str]:
    """Return (classification, explanation). Only evidence-backed states are returned."""
    now = now or datetime.now(timezone.utc)
    keys = {_key(f) for f in flags}
    if "pendingdelete" in keys:
        return PENDING_DELETION, "The registry lists the domain as pending deletion; it is scheduled to be removed."
    if "redemptionperiod" in keys or "pendingrestore" in keys:
        return REDEMPTION_PERIOD, ("The domain is in the redemption/restore period after non-renewal or "
                                   "deletion; the registrant can still recover it for a fee.")
    if "serverhold" in keys:
        return REGISTRY_HOLD, ("The registry has placed the domain on hold (serverHold), so it is not "
                               "published in DNS.")
    if "clienthold" in keys:
        return REGISTRAR_HOLD, ("The registrar has placed the domain on hold (clientHold), so it is not "
                                "published in DNS. Registrars do this for non-payment, abuse or legal reasons.")
    if "inactive" in keys:
        return INACTIVE_OR_UNDELEGATED, ("The domain is registered but has no delegated nameservers "
                                         "(inactive), so it does not resolve.")
    if expires_at is not None and expires_at < now - timedelta(days=1):
        return EXPIRED_OR_NOT_RENEWED, ("The recorded expiration date has passed. The registry may still "
                                        "list the domain during a grace period.")
    locks = sorted(k for k in keys if k in LOCK_FLAGS)
    note = ""
    if locks:
        note = " Lock flags such as transfer-prohibited are normal protections and do not mean suspension."
    return REGISTERED_ACTIVE, "The domain is registered and no restrictive status was reported." + note


# ---- hosting / website ---------------------------------------------------------------------------------
WEBSITE_RESPONDING = "WEBSITE_RESPONDING"
WEBSITE_UNAVAILABLE = "WEBSITE_UNAVAILABLE"
DNS_FAILURE = "DNS_FAILURE"
HOSTING_SUSPENSION_SUSPECTED = "HOSTING_SUSPENSION_SUSPECTED"
HOSTING_SUSPENSION_INDICATOR_DETECTED = "HOSTING_SUSPENSION_INDICATOR_DETECTED"
HOSTING_UNKNOWN = "UNKNOWN"

# Heuristic phrases found on hosting-provider suspension pages. Never proof; always labelled so.
STRONG_SUSPENSION_PHRASES = (
    "this account has been suspended", "account suspended", "website suspended",
    "this site has been suspended", "this website has been suspended", "site has been disabled",
    "account has been deactivated", "bandwidth limit exceeded", "resource limit is reached",
    "suspended page", "domain has been suspended by",
)
WEAK_SUSPENSION_PHRASES = ("suspended", "contact your hosting provider", "contact the hosting provider")
PARKED_PHRASES = ("this domain is for sale", "domain is parked", "buy this domain", "parked free",
                  "this domain may be for sale", "domain parking")


def detect_hosting_suspension(status: int | None, body_text: str) -> dict | None:
    """Heuristic detection from page text. Returns None when nothing was found."""
    text = " ".join(body_text.lower().split())[:30000]
    for phrase in STRONG_SUSPENSION_PHRASES:
        if phrase in text:
            return {"classification": HOSTING_SUSPENSION_INDICATOR_DETECTED, "confidence": "medium",
                    "evidence": f'Page text contains "{phrase}".', "http_status": status}
    for phrase in WEAK_SUSPENSION_PHRASES:
        if phrase in text and status in (402, 403, 404, 409, 410, 451, 503, 509):
            return {"classification": HOSTING_SUSPENSION_SUSPECTED, "confidence": "low",
                    "evidence": f'Page text contains "{phrase}" alongside HTTP {status}.',
                    "http_status": status}
    return None


def detect_parked(body_text: str) -> str | None:
    text = " ".join(body_text.lower().split())[:30000]
    for phrase in PARKED_PHRASES:
        if phrase in text:
            return phrase
    return None
