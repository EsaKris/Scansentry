import hmac
import json
import hashlib
from datetime import datetime
from decimal import Decimal

from django.conf import settings

from .base import InitResult, PaymentProvider, ProviderError, VerifyResult, WebhookEvent

API = "https://api.flutterwave.com/v3"
STATUS_MAP = {"successful": "success", "failed": "failed", "cancelled": "abandoned"}


class FlutterwaveProvider(PaymentProvider):
    """Flutterwave v3 hosted payments. Implemented from the public documentation: verify in the Flutterwave
    sandbox before going live. One payment per billing period (no provider-managed renewals)."""

    key = "flutterwave"
    display_name = "Flutterwave"
    supported_currencies = {"NGN", "GHS", "KES", "ZAR", "USD", "EUR", "GBP", "UGX", "TZS", "RWF"}
    supports_recurring = False
    note = ("Set FLUTTERWAVE_SECRET_KEY and FLUTTERWAVE_WEBHOOK_HASH (the 'secret hash' you configure in the "
            "dashboard). Webhook URL: /api/v1/billing/webhooks/flutterwave/.")

    def secret(self) -> str:
        return settings.FLUTTERWAVE_SECRET_KEY

    def _auth(self) -> dict:
        return {"authorization": f"Bearer {self.secret()}"}

    def initialize(self, *, reference, email, amount, currency, callback_url, metadata, plan_code=""):
        body = {"tx_ref": reference, "amount": str(Decimal(amount)), "currency": currency, "redirect_url": callback_url,
                "customer": {"email": email}, "meta": metadata, "customizations": {"title": "ScanSentry"}}
        status, data = self._call("POST", f"{API}/payments", body=body, headers=self._auth())
        link = (data.get("data") or {}).get("link")
        if status != 200 or data.get("status") != "success" or not link:
            raise ProviderError(f"Flutterwave could not start the payment (HTTP {status}).", transient=False)
        return InitResult(link, reference)

    def verify(self, reference):
        status, data = self._call("GET", f"{API}/transactions/verify_by_reference?tx_ref={reference}", headers=self._auth())
        if status == 404 or (data.get("status") == "error" and "No transaction" in str(data.get("message", ""))):
            return VerifyResult("not_found", reference=reference)
        if status != 200 or data.get("status") != "success":
            raise ProviderError(f"Flutterwave verification failed (HTTP {status}).", transient=status >= 500)
        d = data.get("data") or {}
        return VerifyResult(
            status=STATUS_MAP.get(d.get("status"), "pending"),
            amount=Decimal(str(d["amount"])) if d.get("amount") is not None else None,
            currency=(d.get("currency") or "").upper(), reference=d.get("tx_ref", reference),
            customer_reference=str((d.get("customer") or {}).get("id", "")), channel=d.get("payment_type", ""),
            paid_at=None)

    def verify_signature(self, raw_body, headers):
        secret = settings.FLUTTERWAVE_WEBHOOK_HASH
        sig = headers.get("verif-hash", "")
        return bool(secret and sig) and hmac.compare_digest(secret, sig)

    def parse_webhook(self, payload):
        event = str(payload.get("event", ""))[:60]
        d = payload.get("data")
        if not event or not isinstance(d, dict):
            raise ProviderError("Malformed webhook payload.")
        ident = d.get("id") or d.get("tx_ref") or hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]
        safe = {"reference": d.get("tx_ref", ""), "status": d.get("status", ""), "amount": d.get("amount"),
                "currency": d.get("currency", ""), "channel": d.get("payment_type", "")}
        return WebhookEvent(event_id=f"{event}:{ident}", event_type=event, reference=safe["reference"], data=safe)
