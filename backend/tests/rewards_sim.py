"""A stand-in for Google's AdMob SSV: signs callbacks with a real ECDSA key, and serves its public key as the 'key server'."""
import base64
import time
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from apps.credits import verifiers

KEY_ID = "3335741209"
TEST_UNIT = "5224354917"                      # the numeric part of Google's rewarded test unit


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class AdMobSim:
    def __init__(self, monkeypatch):
        from django.core.cache import cache
        cache.clear()
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.key_fetches = 0
        self.available = True
        self.keys = {KEY_ID: self.pem(self.private)}
        monkeypatch.setattr(verifiers, "fetch_keys", self._fetch)

    @staticmethod
    def pem(private) -> str:
        return private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def _fetch(self):
        self.key_fetches += 1
        if not self.available:
            raise verifiers.VerificationFailure("key_unavailable", "down", transient=True)
        return dict(self.keys)

    def query(self, session, *, tx="tx-0001", ts=None, ad_unit=TEST_UNIT, user_id=None, custom_data=None, key_id=KEY_ID,
              signer=None, extra_after="", params_override=None, tamper=None) -> str:
        ts = int((ts if ts is not None else time.time()) * 1000)
        params = {"ad_network": "5450213213286189855", "ad_unit": ad_unit,
                  "custom_data": custom_data if custom_data is not None else session.unique_session_token,
                  "reward_amount": "1", "reward_item": "coins", "timestamp": str(ts), "transaction_id": tx,
                  "user_id": user_id if user_id is not None else str(session.user_id)}
        params.update(params_override or {})
        content = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
        sig = (signer or self.private).sign(content.encode(), ec.ECDSA(hashes.SHA256()))
        query = f"{content}&signature={b64url(sig)}&key_id={key_id}{extra_after}"
        if tamper:
            query = query.replace(*tamper)
        return query

    def call(self, client, session, **kw):
        return client.get("/api/v1/advertising/reward-callbacks/admob/?" + self.query(session, **kw))
