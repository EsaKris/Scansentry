import logging
import re
import uuid

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse

from config.logging_utils import request_id_var

log = logging.getLogger("scansentry.request")
_VALID_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class RequestIdMiddleware:
    """Gives every request an id (a valid incoming X-Request-ID is kept), logs it with the response and returns it in X-Request-ID."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        incoming = request.META.get("HTTP_X_REQUEST_ID", "")
        rid = incoming if _VALID_ID.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        try:
            response = self.get_response(request)
            response["X-Request-ID"] = rid
            if response.status_code >= 500 or getattr(settings, "LOG_REQUESTS", False):
                log.info("%s %s -> %s", request.method, request.path, response.status_code)    # the path only: never the query string
            return response
        finally:
            request_id_var.reset(token)


class AdminLoginThrottleMiddleware:
    """Django's admin login form has no brute-force protection. Allow a few POSTs per client per window; needs the shared cache in production."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        login_path = "/" + settings.ADMIN_URL.strip("/") + "/login/"
        if request.method == "POST" and request.path == login_path:
            limit, window = settings.ADMIN_LOGIN_ATTEMPTS, settings.ADMIN_LOGIN_WINDOW_SECONDS
            ident = _client_ip(request)
            key = f"admin-login:{ident}"
            if cache.add(key, 1, window):
                attempts = 1
            else:
                try:
                    attempts = cache.incr(key)
                except ValueError:
                    cache.set(key, 1, window)
                    attempts = 1
            if attempts > limit:
                return HttpResponse("Too many sign-in attempts. Try again later.", status=429, headers={"Retry-After": str(window)})
        return self.get_response(request)


def _client_ip(request) -> str:
    proxies = settings.REST_FRAMEWORK.get("NUM_PROXIES", 0)
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if proxies and xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= proxies:
            return parts[-proxies]
    return request.META.get("REMOTE_ADDR", "unknown")


class NoIndexMiddleware:
    """This Django app serves the API, the admin and redirects: none of it should ever appear in a search engine.
    (The public WEBSITE is a separate app and is what should rank: see docs/SEO_AND_ANALYTICS.md.)"""

    VALUE = "noindex, nofollow, noarchive, nosnippet"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["X-Robots-Tag"] = self.VALUE
        return response
