"""Destination URL validation shared by QR creation, the scanner and (later) the rule engine."""
import re
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


def validate_http_url(value: str) -> str:
    """Return a normalised http(s) URL or raise ValidationError.

    - explicit http/https scheme only (javascript:, data:, file:, custom schemes rejected)
    - no embedded credentials, no whitespace/control characters
    - hostname is IDNA-encoded (punycode) so lookalike Unicode hosts are explicit
    """
    value = (value or "").strip()
    if not value:
        raise ValidationError("URL is required.")
    if len(value) > MAX_URL_LENGTH:
        raise ValidationError("URL is too long.")
    if _CONTROL_OR_SPACE.search(value):
        raise ValidationError("URL must not contain spaces or control characters.")

    parts = urlsplit(value)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError("Only http:// and https:// URLs are allowed.")
    if "@" in parts.netloc:
        raise ValidationError("URLs with embedded credentials are not allowed.")
    host = parts.hostname
    if not host:
        raise ValidationError("URL must include a hostname.")
    try:
        port = parts.port
    except ValueError:
        raise ValidationError("URL has an invalid port.")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValidationError("URL has an invalid hostname.")
    if ":" in ascii_host:  # IPv6 literal
        ascii_host = f"[{ascii_host}]"
    netloc = ascii_host if port is None else f"{ascii_host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))
