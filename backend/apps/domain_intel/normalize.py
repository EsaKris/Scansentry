"""Turn a user-supplied URL or domain into a validated, IDNA-encoded host."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList

_PSL = PublicSuffixList(only_icann=True)
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")  # underscore allowed in DNS labels
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f]")

# Names that never exist on the public internet (RFC 6761 / 6762 / common private suffixes).
NON_PUBLIC_TLDS = {
    "localhost", "local", "localdomain", "internal", "intranet", "lan", "home", "corp", "private",
    "test", "example", "invalid", "onion", "arpa", "home.arpa", "alt", "kubernetes", "svc",
}


class InvalidDomainInput(ValueError):
    """Raised with a user-presentable message."""


@dataclass(frozen=True)
class NormalizedDomain:
    host: str               # ASCII (punycode) host, lower-case, no trailing dot
    display_host: str       # Unicode form for humans
    registrable: str        # ASCII registrable domain (eTLD+1, ICANN suffixes only)
    tld: str                # ASCII top-level label
    is_idn: bool


def _to_ascii(host: str) -> str:
    try:
        return idna.encode(host, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        raise InvalidDomainInput("The domain name contains invalid characters.")


def normalize_domain_input(value: str) -> NormalizedDomain:
    value = (value or "").strip()
    if not value:
        raise InvalidDomainInput("Enter a domain name or URL.")
    if len(value) > 2048 or _BAD_CHARS.search(value):
        raise InvalidDomainInput("The value contains spaces or control characters, or is too long.")

    candidate = value if "://" in value else f"//{value}"
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        _ = parts.port  # validates the port
    except ValueError:
        raise InvalidDomainInput("The value is not a valid URL or domain name.")
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        raise InvalidDomainInput("Only http(s) URLs or plain domain names can be assessed.")
    if not host:
        raise InvalidDomainInput("No domain name was found in the value.")

    host = host.rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        raise InvalidDomainInput("IP addresses are not supported here. Enter a domain name.")
    except ValueError:
        pass
    if re.fullmatch(r"\d+|0x[0-9a-f]+", host, re.I):
        raise InvalidDomainInput("Numeric host names are not supported. Enter a domain name.")

    ascii_host = _to_ascii(host)
    if len(ascii_host) > 253:
        raise InvalidDomainInput("The domain name is too long.")
    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise InvalidDomainInput("Enter a full domain name such as example.com.")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise InvalidDomainInput("The domain name contains invalid characters.")
    tld = labels[-1]
    if tld in NON_PUBLIC_TLDS or ".".join(labels[-2:]) in NON_PUBLIC_TLDS or tld.isdigit():
        raise InvalidDomainInput("This is not a public internet domain, so it cannot be assessed.")

    unicode_host = ascii_host.encode("ascii").decode("idna")
    registrable_unicode = _PSL.privatesuffix(unicode_host)
    if registrable_unicode is None:
        raise InvalidDomainInput("This looks like a public suffix, not a registrable domain.")
    registrable = _to_ascii(registrable_unicode)
    return NormalizedDomain(
        host=ascii_host, display_host=unicode_host, registrable=registrable, tld=tld,
        is_idn=any(l.startswith("xn--") for l in labels))
