"""Provider reward-callback verification.

AdMob server-side verification (SSV): Google calls our URL with the reward details as query parameters. The signature is an
ECDSA/SHA-256 signature over the query string that precedes `&signature=`; `signature` and `key_id` are always the last two
parameters. The public keys come from Google's key server (https://developers.google.com/admob/android/ssv) and rotate, so they
are cached for a few hours only (Google: never longer than 24 h).

Strictness that protects against forged or tampered callbacks:
  * the signed text is verified exactly as received (raw query string), never a re-serialised version
  * nothing may follow `signature` except `key_id` (parameters after the signature are not covered by it)
  * every parameter we rely on must appear exactly once (no parameter pollution)
Google Ad Manager WEB rewarded ads have no server-side verification (it is an app-only feature), so there is deliberately no
verifier for them here: see rewarded.attest_web_completion().
"""
import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import parse_qs

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django.core.cache import cache

KEYS_URL = "https://www.gstatic.com/admob/reward/verifier-keys.json"
KEYS_CACHE_KEY = "rewarded:admob:verifier-keys"
KEYS_TTL_SECONDS = 6 * 3600                       # Google's documented ceiling is 24 hours
REFETCH_COOLDOWN_KEY = "rewarded:admob:keys-refetched"
REFETCH_COOLDOWN_SECONDS = 300                    # an unknown key id triggers at most one refresh per 5 minutes
MAX_QUERY = 4096
MAX_TRANSACTION_ID = 120                    # stored in 200-character columns together with a prefix
REQUIRED = ("transaction_id", "custom_data", "user_id", "ad_unit", "timestamp", "key_id", "signature")


class VerificationFailure(Exception):
    def __init__(self, code: str, message: str = "", *, transient: bool = False):
        super().__init__(message or code)
        self.code = code
        self.transient = transient


@dataclass
class Claim:
    transaction_id: str
    session_token: str
    user_id: str
    ad_unit: str
    reward_at: datetime


def reward_timestamp(raw: str) -> datetime:
    """AdMob sends epoch time in milliseconds (its own docs sample is longer, i.e. microseconds): normalise by magnitude."""
    try:
        n = int(raw)
    except (TypeError, ValueError):
        raise VerificationFailure("malformed", "timestamp is not a number")
    if n <= 0:
        raise VerificationFailure("malformed", "timestamp is not valid")
    seconds = n / 1_000_000 if n >= 10**14 else n / 1000 if n >= 10**11 else n
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise VerificationFailure("malformed", "timestamp is out of range")


def fetch_keys() -> dict:
    """{key_id: PEM}. Goes through the SSRF-guarded client. Raises VerificationFailure(transient) if Google cannot be reached."""
    from apps.domain_intel.service import build_guard
    res = build_guard().fetch(KEYS_URL, accept="application/json", require_https=True, max_body=128 * 1024)
    if res.error or res.status != 200:
        raise VerificationFailure("key_unavailable", "could not fetch the provider's verification keys", transient=True)
    try:
        keys = {str(k["keyId"]): k["pem"] for k in json.loads(res.text)["keys"]}
    except (ValueError, KeyError, TypeError):
        raise VerificationFailure("key_unavailable", "the provider's key list could not be read", transient=True)
    if not keys:
        raise VerificationFailure("key_unavailable", "the provider's key list was empty", transient=True)
    return keys


def _key_for(key_id: str) -> str:
    keys = cache.get(KEYS_CACHE_KEY)
    if keys is None:
        keys = fetch_keys()
        cache.set(KEYS_CACHE_KEY, keys, KEYS_TTL_SECONDS)
    if key_id not in keys and cache.add(REFETCH_COOLDOWN_KEY, 1, REFETCH_COOLDOWN_SECONDS):
        keys = fetch_keys()                              # keys rotate: one bounded refresh for an id we have not seen
        cache.set(KEYS_CACHE_KEY, keys, KEYS_TTL_SECONDS)
    pem = keys.get(key_id)
    if pem is None:
        raise VerificationFailure("invalid_signature", "unknown verification key")
    return pem


def _b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_admob(query_string: str) -> Claim:
    """Verify an AdMob SSV callback from its raw query string. Raises VerificationFailure; returns the claim on success."""
    if not query_string or len(query_string) > MAX_QUERY:
        raise VerificationFailure("malformed", "missing or oversized query string")
    content, sep, tail = query_string.partition("&signature=")
    if not sep:
        raise VerificationFailure("malformed", "no signature")
    sig_part, _, rest = tail.partition("&")
    if not rest.startswith("key_id=") or "&" in rest:
        raise VerificationFailure("malformed", "key_id must directly follow the signature and nothing may come after it")
    params = parse_qs(query_string, keep_blank_values=True)
    if any(len(v) != 1 for v in params.values()) or any(not params.get(k, [""])[0] for k in REQUIRED):
        raise VerificationFailure("malformed", "a required parameter is missing or repeated")
    if len(params["transaction_id"][0]) > MAX_TRANSACTION_ID:
        raise VerificationFailure("malformed", "transaction_id is too long")
    signature, key_id = params["signature"][0], params["key_id"][0]
    if sig_part != signature:
        raise VerificationFailure("malformed", "inconsistent signature parameter")
    try:
        public_key = load_pem_public_key(_key_for(key_id).encode())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise VerificationFailure("invalid_signature", "unexpected key type")
        public_key.verify(_b64(signature), content.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise VerificationFailure("invalid_signature", "the signature does not match")
    except (ValueError, TypeError):
        raise VerificationFailure("invalid_signature", "the signature could not be decoded")
    return Claim(transaction_id=params["transaction_id"][0], session_token=params["custom_data"][0],
                 user_id=params["user_id"][0], ad_unit=params["ad_unit"][0], reward_at=reward_timestamp(params["timestamp"][0]))


VERIFIERS = {"admob": verify_admob}
