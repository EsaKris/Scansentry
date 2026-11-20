"""Optional error monitoring. Does nothing unless SENTRY_DSN is set.

Privacy first: no default PII, no request bodies, and every event is scrubbed of query strings, cookies and
authorization headers before it leaves the server (scanned content, session tokens and reward-callback data live there).
"""
import re

_QUERY = re.compile(r"\?[^\s\"']*")
SENSITIVE_HEADERS = {"authorization", "cookie", "x-csrftoken", "set-cookie", "x-forwarded-for", "x-real-ip"}


def scrub_event(event: dict, hint=None) -> dict | None:
    req = event.get("request") or {}
    req.pop("query_string", None)
    req.pop("cookies", None)
    req.pop("data", None)
    if isinstance(req.get("url"), str):
        req["url"] = req["url"].split("?", 1)[0]
    if isinstance(req.get("headers"), dict):
        req["headers"] = {k: ("[redacted]" if k.lower() in SENSITIVE_HEADERS else v) for k, v in req["headers"].items()}
    event.pop("user", None)
    for crumb in (event.get("breadcrumbs") or {}).get("values", []) or []:
        scrub_breadcrumb(crumb)
    return event


def scrub_breadcrumb(crumb: dict, hint=None) -> dict:
    if isinstance(crumb.get("message"), str):
        crumb["message"] = _QUERY.sub("?[query removed]", crumb["message"])
    crumb.pop("data", None)                      # http breadcrumbs carry the full URL with its query string here
    return crumb


def init_sentry(dsn: str, environment: str, release: str = "", traces_sample_rate: float = 0.0) -> bool:
    if not dsn:
        return False
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    sentry_sdk.init(dsn=dsn, environment=environment, release=release or None, integrations=[DjangoIntegration()],
                    send_default_pii=False, max_request_body_size="never", traces_sample_rate=traces_sample_rate,
                    before_send=scrub_event, before_breadcrumb=scrub_breadcrumb)
    return True
