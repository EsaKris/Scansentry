"""Payment-provider adapter interface.

Rules every adapter follows:
  * credentials come from the environment (settings), never the database or a client
  * amounts we charge are calculated by the backend from the database price; the provider's report is only
    ever compared against it, never trusted on its own
  * a webhook is never believed by itself: payments are re-verified with the provider's API
  * network problems are ProviderError(transient=True) so callers can retry; they never become "success"
"""
import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal


class ProviderError(Exception):
    def __init__(self, message: str, *, transient: bool = False):
        super().__init__(message)
        self.transient = transient


@dataclass
class InitResult:
    authorization_url: str
    provider_reference: str = ""


@dataclass
class VerifyResult:
    status: str                      # success | failed | abandoned | pending | not_found
    amount: Decimal | None = None    # major units
    currency: str = ""
    reference: str = ""
    customer_reference: str = ""
    channel: str = ""
    paid_at: datetime | None = None
    plan_code: str = ""


@dataclass
class WebhookEvent:
    event_id: str                    # unique per provider event (idempotency key)
    event_type: str
    reference: str = ""
    data: dict = field(default_factory=dict)       # whitelisted fields only (no card data)
    private: dict = field(default_factory=dict)    # used for processing, never stored (e.g. e-mail)


class PaymentProvider:
    key = ""
    display_name = ""
    supported_currencies: set[str] = set()
    supports_recurring = False
    implemented = True
    note = ""

    def __init__(self, guard=None):
        self.guard = guard

    def secret(self) -> str:                                   # pragma: no cover - interface
        raise NotImplementedError

    def configured(self) -> bool:
        return bool(self.secret())

    # -- HTTP through the SSRF guard ------------------------------------------------------------------
    def _call(self, method: str, url: str, *, body: dict | None = None, headers: dict | None = None):
        res = self.guard.fetch(url, method=method, accept="application/json", require_https=True, max_body=256 * 1024,
                               body=json.dumps(body).encode() if body is not None else None,
                               headers={"content-type": "application/json", **(headers or {})})
        if res.error:
            raise ProviderError(f"{res.error}: {res.error_detail}", transient=True)
        if res.status in (429, 500, 502, 503, 504):
            raise ProviderError(f"The provider returned HTTP {res.status}.", transient=True)
        if res.status in (401, 403):
            raise ProviderError("The provider rejected our credentials.", transient=False)
        try:
            data = json.loads(res.text) if res.text else {}
        except ValueError:
            raise ProviderError("The provider response could not be parsed.", transient=False)
        return res.status, data

    # -- interface -----------------------------------------------------------------------------------------
    def initialize(self, *, reference, email, amount: Decimal, currency, callback_url, metadata, plan_code="") -> InitResult:
        raise NotImplementedError

    def verify(self, reference: str) -> VerifyResult:
        raise NotImplementedError

    def verify_signature(self, raw_body: bytes, headers: dict) -> bool:
        raise NotImplementedError

    def parse_webhook(self, payload: dict) -> WebhookEvent:
        raise NotImplementedError

    def cancel_recurring(self, subscription_reference: str) -> bool:
        return False
