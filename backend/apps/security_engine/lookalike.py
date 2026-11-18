"""Brand look-alike detection: homoglyphs, typo-squats and brand names used inside other domains."""
import re
import unicodedata

# Starter list of frequently impersonated brands. Administrators can replace it from the admin
# (AppConfiguration key "security.brand_domains"). Extend it for your market.
DEFAULT_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "instagram.com", "whatsapp.com", "netflix.com", "linkedin.com", "dhl.com", "fedex.com", "ups.com",
    "binance.com", "coinbase.com", "stripe.com", "paystack.com", "flutterwave.com", "gtbank.com",
    "zenithbank.com", "ubagroup.com",
]
SENSITIVE_KEYWORDS = {
    "login", "signin", "secure", "security", "verify", "verification", "account", "update", "support",
    "wallet", "billing", "payment", "confirm", "recovery", "unlock", "helpdesk", "auth", "password",
}

_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v", "α": "a", "ο": "o", "ρ": "p", "ι": "i", "κ": "k",
    "τ": "t", "υ": "u", "ℓ": "l", "ǀ": "l", "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a",
}


def skeleton(text: str) -> str:
    """Reduce visually confusable characters to a canonical form."""
    s = unicodedata.normalize("NFKD", text.lower())
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s if not unicodedata.combining(ch))
    s = s.replace("-", "").replace("rn", "m").replace("vv", "w")
    return s


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _tokens(*parts: str) -> set[str]:
    return {t for p in parts for t in re.split(r"[-.]", p.lower()) if t}


def find_lookalikes(display_host: str, display_registrable: str, brands: list[str]) -> list[dict]:
    """Return matches describing how the host imitates a brand. A brand's own domains never match."""
    labels = display_host.lower().split(".")
    reg_parts = display_registrable.lower().split(".")
    sub_labels = labels[:-len(reg_parts)] if len(reg_parts) < len(labels) else []
    label = reg_parts[0]
    out: list[dict] = []
    for brand in brands:
        brand = brand.lower()
        if display_registrable.lower() == brand:
            continue
        b_label = brand.split(".")[0]
        if label != b_label and skeleton(label) == skeleton(b_label):
            out.append({"brand": brand, "kind": "homoglyph",
                        "detail": f"'{label}' looks like '{b_label}' when similar-looking characters are normalised."})
        elif (len(b_label) >= 5 and label != b_label and abs(len(label) - len(b_label)) <= 2
              and 0 < levenshtein(label, b_label) <= (2 if len(b_label) >= 8 else 1)):
            out.append({"brand": brand, "kind": "typosquat",
                        "detail": f"'{label}' is one or two characters away from '{b_label}'."})
        elif b_label in sub_labels:
            out.append({"brand": brand, "kind": "brand_in_subdomain",
                        "detail": f"'{b_label}' appears as a sub-domain of the unrelated domain {display_registrable}."})
    return out


def find_brand_keyword(display_host: str, display_registrable: str, brands: list[str]) -> list[dict]:
    """Brand name combined with a sensitive keyword (e.g. paypal-secure-login.com)."""
    if not display_host:
        return []
    labels = display_host.lower().split(".")
    reg_parts = display_registrable.lower().split(".")
    sub = labels[:-len(reg_parts)] if len(reg_parts) < len(labels) else []
    tokens = _tokens(reg_parts[0], *sub)
    out = []
    for brand in brands:
        brand = brand.lower()
        if display_registrable.lower() == brand:
            continue
        b_label = brand.split(".")[0]
        brand_hit = b_label in tokens or (len(b_label) >= 6 and any(
            t != b_label and (t.startswith(b_label) or t.endswith(b_label)) for t in tokens))
        keyword_hit = tokens & SENSITIVE_KEYWORDS or {
            kw for t in tokens for kw in SENSITIVE_KEYWORDS if len(kw) >= 5 and kw in t and t != kw and b_label in t}
        if brand_hit and keyword_hit:
            out.append({"brand": brand, "keywords": sorted(keyword_hit)})
    return out
