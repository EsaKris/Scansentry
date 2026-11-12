"""Simulated payment-provider APIs for tests (served through the fake-internet harness)."""
import hashlib
import hmac
import json
from datetime import datetime, timezone

from tests.netfakes import http_response


def _json(status, obj):
    return http_response(status, json.dumps(obj), {"Content-Type": "application/json"})


def _split(req):
    head, _, body = req.partition("\r\n\r\n")
    line = head.split("\r\n")[0]
    method, path, _v = line.split(" ", 2)
    headers = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in head.split("\r\n")[1:] if ":" in h}
    return method, path, headers, body


class PaystackSim:
    def __init__(self, senv, ip="104.16.0.10"):
        self.initialized, self.requests = [], []
        self.results = {}                   # reference -> verify "data" object
        self.mode = {}                      # e.g. {"initialize": 503, "verify": 500}
        self.disabled, self.subscriptions = [], {"SUB_1": {"email_token": "tok-1"}}
        self.server = senv.world.site("api.paystack.co", ip, https=self.handler)

    def handler(self, req):
        method, path, headers, body = _split(req)
        self.requests.append((method, path, headers))
        if path == "/transaction/initialize" and method == "POST":
            if "initialize" in self.mode:
                return _json(self.mode["initialize"], {"status": False})
            payload = json.loads(body)
            self.initialized.append(payload)
            return _json(200, {"status": True, "data": {"authorization_url": f"https://checkout.paystack.com/{payload['reference']}",
                                                         "access_code": "ac", "reference": payload["reference"]}})
        if path.startswith("/transaction/verify/") and method == "GET":
            if "verify" in self.mode:
                return _json(self.mode["verify"], {"status": False})
            ref = path.rsplit("/", 1)[1]
            data = self.results.get(ref)
            return _json(200, {"status": True, "data": data}) if data else _json(404, {"status": False, "message": "not found"})
        if path.startswith("/subscription/disable") and method == "POST":
            if "disable" in self.mode:
                return _json(self.mode["disable"], {"status": False})
            self.disabled.append(json.loads(body))
            return _json(200, {"status": True})
        if path.startswith("/subscription/") and method == "GET":
            code = path.rsplit("/", 1)[1]
            sub = self.subscriptions.get(code)
            return _json(200, {"status": True, "data": sub}) if sub else _json(404, {"status": False})
        return _json(404, {"status": False})

    def result(self, ref, amount, currency="NGN", status="success", customer="CUS_abc", plan_code=None, email="ada@example.com"):
        data = {"status": status, "reference": ref, "amount": int(round(float(amount) * 100)), "currency": currency, "channel": "card",
                "paid_at": datetime.now(timezone.utc).isoformat(), "customer": {"customer_code": customer, "email": email}}
        if plan_code:
            data["plan_object"] = {"plan_code": plan_code}
        self.results[ref] = data
        return data


class FlutterwaveSim:
    def __init__(self, senv, ip="104.16.0.20"):
        self.initialized, self.results, self.mode, self.requests = [], {}, {}, []
        self.server = senv.world.site("api.flutterwave.com", ip, https=self.handler)

    def handler(self, req):
        method, path, headers, body = _split(req)
        self.requests.append((method, path, headers))
        if path == "/v3/payments" and method == "POST":
            if "initialize" in self.mode:
                return _json(self.mode["initialize"], {"status": "error"})
            payload = json.loads(body)
            self.initialized.append(payload)
            return _json(200, {"status": "success", "data": {"link": f"https://checkout.flutterwave.com/{payload['tx_ref']}"}})
        if path.startswith("/v3/transactions/verify_by_reference") and method == "GET":
            ref = path.split("tx_ref=")[1]
            d = self.results.get(ref)
            return _json(200, {"status": "success", "data": d}) if d else _json(200, {"status": "error", "message": "No transaction was found for this id"})
        return _json(404, {})

    def result(self, ref, amount, currency="NGN", status="successful"):
        self.results[ref] = {"status": status, "tx_ref": ref, "amount": float(amount), "currency": currency,
                             "payment_type": "card", "customer": {"id": 77}}


def sign_paystack(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()


def ps_event(event, **data):
    return {"event": event, "data": data}


def post_webhook(client, provider, payload, *, secret="sk_test_secret", signature=None, headers=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    extra = dict(headers or {})
    if provider == "paystack":
        extra["HTTP_X_PAYSTACK_SIGNATURE"] = signature if signature is not None else sign_paystack(body, secret)
    elif provider == "flutterwave":
        extra["HTTP_VERIF_HASH"] = signature if signature is not None else "fw-hash-123"
    return client.post(f"/api/v1/billing/webhooks/{provider}/", data=body, content_type="application/json", **extra)
