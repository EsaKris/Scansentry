import hashlib
import hmac
import json
from datetime import datetime
from decimal import Decimal

from django.conf import settings

from .base import InitResult, PaymentProvider, ProviderError, VerifyResult, WebhookEvent

API = "https://api.paystack.co"
STATUS_MAP = {"success": "success", "failed": "failed", "abandoned": "abandoned", "reversed": "failed"}


def _dt(v):
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")) if isinstance(v, str) else None
    except ValueError:
        return None


class PaystackProvider(PaymentProvider):
    """Paystack (https://paystack.com/docs). Implemented from the public API documentation:
    verify end to end in Paystack's TEST mode before going live."""

    key = "paystack"
    display_name = "Paystack"
    supported_currencies = {"NGN", "GHS", "ZAR", "KES", "USD"}      # which ones your account may use depends on its setup
    supports_recurring = True
    note = ("Set PAYSTACK_SECRET_KEY. Point the Paystack webhook URL at /api/v1/billing/webhooks/paystack/. "
            "For automatic renewals, create a Paystack plan and store its code on the plan as provider_refs.paystack_plan_code.")

    def secret(self) -> str:
        return settings.PAYSTACK_SECRET_KEY

    def _auth(self) -> dict:
        return {"authorization": f"Bearer {self.secret()}"}

    def initialize(self, *, reference, email, amount, currency, callback_url, metadata, plan_code=""):
        body = {"email": email, "amount": int((Decimal(amount) * 100).to_integral_value()), "currency": currency,
                "reference": reference, "callback_url": callback_url, "metadata": metadata}
        if plan_code:
            body["plan"] = plan_code          # Paystack then manages renewals for this customer
        status, data = self._call("POST", f"{API}/transaction/initialize", body=body, headers=self._auth())
        url = (data.get("data") or {}).get("authorization_url")
        if status != 200 or not data.get("status") or not url:
            raise ProviderError(f"Paystack could not start the payment (HTTP {status}).", transient=False)
        return InitResult(url, (data.get("data") or {}).get("reference", reference))

    def verify(self, reference):
        status, data = self._call("GET", f"{API}/transaction/verify/{reference}", headers=self._auth())
        if status == 404:
            return VerifyResult("not_found", reference=reference)
        if status != 200 or not data.get("status"):
            raise ProviderError(f"Paystack verification failed (HTTP {status}).", transient=status >= 500)
        d = data.get("data") or {}
        plan_obj = d.get("plan_object") if isinstance(d.get("plan_object"), dict) else (
            d.get("plan") if isinstance(d.get("plan"), dict) else {})
        return VerifyResult(
            status=STATUS_MAP.get(d.get("status"), "pending"),
            amount=(Decimal(d["amount"]) / 100) if d.get("amount") is not None else None,
            currency=(d.get("currency") or "").upper(), reference=d.get("reference", reference),
            customer_reference=(d.get("customer") or {}).get("customer_code", ""), channel=d.get("channel", ""),
            paid_at=_dt(d.get("paid_at")), plan_code=plan_obj.get("plan_code", ""))

    def verify_signature(self, raw_body, headers):
        secret = self.secret()
        sig = headers.get("x-paystack-signature", "")
        if not secret or not sig:
            return False
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
        return hmac.compare_digest(expected, sig)

    def parse_webhook(self, payload):
        event = str(payload.get("event", ""))[:60]
        d = payload.get("data")
        if not event or not isinstance(d, dict):
            raise ProviderError("Malformed webhook payload.")
        ident = d.get("id") or d.get("invoice_code") or d.get("subscription_code") or d.get("reference") or ""
        if not ident:
            ident = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:32]
        cust = d.get("customer") if isinstance(d.get("customer"), dict) else {}
        sub = d.get("subscription") if isinstance(d.get("subscription"), dict) else {}
        plan = d.get("plan") if isinstance(d.get("plan"), dict) else {}
        safe = {"reference": d.get("reference") or d.get("transaction_reference") or "",
                "transaction_reference": d.get("transaction_reference", ""), "status": d.get("status", ""),
                "amount": d.get("amount"), "currency": d.get("currency", ""), "channel": d.get("channel", ""),
                "customer_code": cust.get("customer_code", ""),
                "subscription_code": d.get("subscription_code") or sub.get("subscription_code", ""),
                "plan_code": plan.get("plan_code", "")}
        return WebhookEvent(event_id=f"{event}:{ident}", event_type=event, reference=safe["reference"], data=safe,
                            private={"email": (cust.get("email") or "").lower()})

    def cancel_recurring(self, subscription_reference):
        status, data = self._call("GET", f"{API}/subscription/{subscription_reference}", headers=self._auth())
        token = (data.get("data") or {}).get("email_token") if status == 200 else None
        if not token:
            return False
        status, data = self._call("POST", f"{API}/subscription/disable", headers=self._auth(),
                                  body={"code": subscription_reference, "token": token})
        return status == 200 and bool(data.get("status"))
