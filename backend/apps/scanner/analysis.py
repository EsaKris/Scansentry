"""Classify and describe decoded QR content WITHOUT fetching anything or judging safety.

Output is facts + "observations" (neutral findings). Threat verdicts, domain registration and
reputation belong to the security engine (Milestone 4). Nothing here ever opens a URL.
"""
import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlsplit

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError

from apps.core.urlsafety import validate_http_url

CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
HTTP_RE = re.compile(r"^https?://", re.I)
BARE_DOMAIN_RE = re.compile(
    r"^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$", re.I)

DANGEROUS_SCHEMES = {
    "javascript", "data", "file", "vbscript", "blob", "about", "chrome", "intent", "jar",
    "ms-msdt", "search-ms", "ms-officecmd", "content", "android-app",
}
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirecturl", "next", "continue", "return",
                   "returnurl", "return_to", "dest", "destination", "target", "goto", "link"}
SECURITY_NOT_ASSESSED = {
    "status": "assessment_not_available",
    "message": "No reputation or domain assessment has been run for this content yet.",
}


def _obs(code: str, message: str) -> dict:
    return {"code": code, "message": message, "severity": "info"}


def _clean(text: str, limit: int = 1000) -> str:
    return CONTROL.sub("", text)[:limit]


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def _actions(kind: str, *, can_open: bool, action: str | None, blocked: bool = False,
             reason: str | None = None) -> dict:
    return {"kind": kind, "can_open": can_open and not blocked, "action": action if not blocked else None,
            "requires_user_confirmation": True, "blocked": blocked, "block_reason": reason}


# --------------------------------------------------------------------------------------
def analyze_url(raw: str, *, assumed_scheme: bool = False) -> dict:
    """Facts about an http(s) URL. Returns {url: {...}, observations: [...], blocked, reason}."""
    candidate = f"https://{raw}" if assumed_scheme else raw
    parts = urlsplit(candidate)
    obs: list[dict] = []
    blocked, reason = False, None

    if assumed_scheme:
        obs.append(_obs("assumed_scheme", "The code contained no http(s):// prefix; https:// was assumed."))
    if "@" in parts.netloc:
        blocked, reason = True, ("This link contains embedded credentials before the host name, a common "
                                 "trick to disguise the real destination.")
        obs.append(_obs("embedded_credentials", "The URL has a username/password section (user@host)."))
    elif "%" in parts.netloc:
        blocked, reason = True, "The host name contains percent-encoding, which is used to hide the real host."
        obs.append(_obs("encoded_host", "The host name contains percent-encoded characters."))

    normalised = None
    if not blocked:
        try:
            normalised = validate_http_url(candidate)
        except DjangoValidationError as exc:
            blocked, reason = True, f"The link is malformed: {exc.messages[0]}"

    if normalised is None:
        return {"url": {"original": _clean(raw, 300), "scheme": parts.scheme.lower() or None},
                "observations": obs, "blocked": blocked, "reason": reason}

    n = urlsplit(normalised)
    host = n.hostname or ""
    try:
        display_host = host.encode("ascii").decode("idna")
    except UnicodeError:
        display_host = host
    labels = [l for l in host.split(".") if l]
    is_idn = any(l.startswith("xn--") for l in labels) or any(ord(c) > 127 for c in parts.netloc)
    scripts = _scripts(display_host)
    mixed = len(scripts) > 1

    is_ip, obfuscated_ip = False, False
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"\d+|0x[0-9a-f]+", bare, re.I):
            obfuscated_ip = True

    if is_idn:
        obs.append(_obs("internationalised_domain", "The host name uses international characters "
                        f"(punycode: {host}; displayed as: {display_host})."))
    if mixed:
        obs.append(_obs("mixed_scripts", "The host name mixes alphabets (" + ", ".join(sorted(scripts)).lower()
                        + "), which can be used to imitate another site."))
    if is_ip or obfuscated_ip:
        obs.append(_obs("ip_address_host", "The link goes to a numeric address rather than a named website."))

    redirect_param = None
    for key, value in parse_qsl(n.query, keep_blank_values=True):
        v = unquote(value).lower()
        if key.lower() in REDIRECT_PARAMS and (v.startswith(("http://", "https://", "//")) or "://" in v):
            redirect_param = key
            break
    if redirect_param:
        obs.append(_obs("redirect_parameter", f"The link carries another address in its '{redirect_param}' "
                        "parameter, so it may forward you elsewhere."))

    return {
        "url": {
            "original": _clean(raw, 300), "normalized": normalised, "scheme": n.scheme,
            "host": host, "display_host": display_host, "is_idn": is_idn, "mixed_scripts": mixed,
            "is_ip_address": is_ip or obfuscated_ip, "port": n.port, "uses_https": n.scheme == "https",
            "path_length": len(n.path), "has_query": bool(n.query), "assumed_scheme": assumed_scheme,
        },
        "observations": obs, "blocked": False, "reason": None,
    }


# ---- non-URL payloads ------------------------------------------------------------------
def _unescape_wifi(v: str) -> str:
    return re.sub(r"\\(.)", r"\1", v)


def parse_wifi(content: str) -> dict | None:
    body = content[5:]
    fields, buf, key, esc = {}, "", None, False
    # tokenise on unescaped ';' ; each token is KEY:VALUE (value may contain escaped ':' ';')
    tokens, cur = [], ""
    for ch in body:
        if esc:
            cur += "\\" + ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ";":
            tokens.append(cur)
            cur = ""
        else:
            cur += ch
    if cur:
        tokens.append(cur)
    for t in tokens:
        m = re.match(r"^([A-Za-z]):(.*)$", t, re.S)
        if m:
            fields[m.group(1).upper()] = _unescape_wifi(m.group(2))
    if "S" not in fields:
        return None
    return {"ssid": _clean(fields["S"], 64), "security": fields.get("T", "nopass") or "nopass",
            "hidden": fields.get("H", "").lower() == "true",
            "password_present": bool(fields.get("P"))}


def parse_vcard(content: str) -> dict:
    text = re.sub(r"\r?\n[ \t]", "", content)  # unfold
    card: dict = {"name": None, "organization": None, "title": None, "phones": [], "emails": [], "urls": []}
    for line in re.split(r"\r?\n", text):
        if ":" not in line:
            continue
        prop, _, value = line.partition(":")
        name = prop.split(";")[0].upper()
        value = _clean(value.replace("\\n", " ").replace("\\,", ",").replace("\\;", ";"), 200).strip()
        if name == "FN" and value:
            card["name"] = value
        elif name == "N" and not card["name"]:
            fam, _, given = value.partition(";")
            card["name"] = f"{given.split(';')[0]} {fam}".strip() or None
        elif name == "ORG":
            card["organization"] = value.replace(";", " ").strip() or None
        elif name == "TITLE":
            card["title"] = value or None
        elif name == "TEL" and len(card["phones"]) < 5:
            card["phones"].append(value)
        elif name == "EMAIL" and len(card["emails"]) < 5:
            card["emails"].append(value)
        elif name == "URL" and len(card["urls"]) < 5:
            card["urls"].append(value)
    return card


def parse_mailto(content: str) -> dict:
    body = content[7:]
    addr, _, query = body.partition("?")
    params = dict(parse_qsl(query, keep_blank_values=True))
    lower = {k.lower(): v for k, v in params.items()}
    extra = sorted(k for k in lower if k not in {"subject", "body"})
    return {"to": _clean(unquote(addr), 254), "subject": _clean(lower.get("subject", ""), 200),
            "body": _clean(lower.get("body", ""), 500), "ignored_parameters": extra}


# --------------------------------------------------------------------------------------
def analyze_content(content: str) -> dict:
    """Describe decoded QR content. Never performs network access."""
    text = content.strip()
    base = {"raw": _clean(text, 500), "security": SECURITY_NOT_ASSESSED, "observations": [],
            "url": None, "preview": None}

    if HTTP_RE.match(text) or BARE_DOMAIN_RE.match(text):
        assumed = not HTTP_RE.match(text)
        if "\n" in text or "\r" in text:
            return {**base, "kind": "text", "preview": {"text": _clean(text)},
                    "actions": _actions("text", can_open=False, action=None)}
        res = analyze_url(text, assumed_scheme=assumed)
        return {**base, "kind": "url", "url": res["url"], "observations": res["observations"],
                "actions": _actions("url", can_open=True, action="open_url", blocked=res["blocked"],
                                    reason=res["reason"])}

    m = SCHEME_RE.match(text)
    scheme = m.group(1).lower() if m else None

    if scheme == "wifi":
        wifi = parse_wifi(text)
        if wifi is None:
            return {**base, "kind": "text", "preview": {"text": _clean(text)},
                    "actions": _actions("text", can_open=False, action=None)}
        obs = []
        if wifi["security"].lower() in ("nopass", "") or not wifi["password_present"]:
            obs.append(_obs("open_network", "This Wi-Fi network has no password."))
        return {**base, "kind": "wifi", "preview": wifi, "observations": obs,
                "actions": _actions("wifi", can_open=True, action="join_wifi")}

    if text.upper().startswith("BEGIN:VCARD"):
        card = parse_vcard(text)
        return {**base, "kind": "vcard", "preview": card,
                "actions": _actions("vcard", can_open=True, action="save_contact")}

    if scheme == "tel":
        number = re.sub(r"[\s().-]", "", text[4:])
        if re.fullmatch(r"\+?[\d*#]{3,20}", number):
            return {**base, "kind": "phone", "preview": {"number": number},
                    "actions": _actions("phone", can_open=True, action="call")}
        return {**base, "kind": "text", "preview": {"text": _clean(text)},
                "actions": _actions("text", can_open=False, action=None)}

    if scheme == "mailto":
        mail = parse_mailto(text)
        obs = []
        if mail["ignored_parameters"]:
            obs.append(_obs("extra_mail_parameters", "Extra mail fields ("
                            + ", ".join(mail["ignored_parameters"]) + ") are ignored by ScanSentry."))
        return {**base, "kind": "email", "preview": mail, "observations": obs,
                "actions": _actions("email", can_open=True, action="compose_email")}

    if scheme:
        dangerous = scheme in DANGEROUS_SCHEMES
        reason = (f"'{scheme}:' links can run code or access local data and are always blocked."
                  if dangerous else
                  f"'{scheme}:' links are not supported. ScanSentry only opens web links, phone numbers, "
                  "email, Wi-Fi and contact cards.")
        return {**base, "kind": "blocked_scheme" if dangerous else "unsupported_scheme",
                "preview": {"scheme": scheme, "text": _clean(text, 300)},
                "observations": [_obs("blocked_scheme" if dangerous else "unsupported_scheme", reason)],
                "actions": _actions("blocked", can_open=False, action=None, blocked=True, reason=reason)}

    return {**base, "kind": "text", "preview": {"text": _clean(text)},
            "actions": _actions("text", can_open=False, action=None)}


def managed_token_from_url(url: str) -> str | None:
    """If `url` is a ScanSentry dynamic link (REDIRECT_BASE_URL/r/<token>) return the token."""
    base = urlsplit(settings.REDIRECT_BASE_URL)
    u = urlsplit(url)
    if (u.scheme, (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80)) != (
            base.scheme, (base.hostname or "").lower(), base.port or (443 if base.scheme == "https" else 80)):
        return None
    m = re.fullmatch(r"/r/([A-Za-z0-9_-]{16,64})/?", u.path)
    return m.group(1) if m else None
