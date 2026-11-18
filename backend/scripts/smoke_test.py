#!/usr/bin/env python3
"""Post-deployment smoke test. Standard library only. Read-only and safe to run against production: it creates nothing.

    python scripts/smoke_test.py https://api.yourdomain.com [--web-origin https://app.yourdomain.com]

Exit code 0 = every check passed, 1 = at least one failed. WARN lines are advice, not failures.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

results = []


def call(base, path, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    try:
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=20)
    except urllib.error.HTTPError as e:
        r = e
    raw = r.read().decode("utf-8", "replace")
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    return r.status, {k.lower(): v for k, v in r.headers.items()}, parsed, raw


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail and not ok else ""))


def warn(msg):
    print("WARN  " + msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--web-origin", default="", help="the real web app origin, to confirm CORS allows it")
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    https = base.startswith("https://")

    s, h, j, _ = call(base, "/api/v1/health/")
    check("health endpoint reports ok with the database reachable", s == 200 and j == {"status": "ok", "database": "ok"}, f"{s} {j}")
    check("every response carries an X-Request-ID", bool(h.get("x-request-id")))

    s, _, j, raw = call(base, "/api/v1/schema/")
    check("OpenAPI schema is served", s == 200 and "openapi" in raw[:200].lower(), str(s))

    if https:
        check("HSTS header present", "max-age" in h.get("strict-transport-security", ""))
    check("X-Content-Type-Options: nosniff", h.get("x-content-type-options") == "nosniff")
    check("framing is denied", h.get("x-frame-options", "").upper() == "DENY")

    s, _, j, _ = call(base, "/api/v1/scanner/analyze/", "POST", {"content": "https://example.com/menu"})
    check("public scanner works without an account", s == 200 and isinstance(j, dict) and j.get("kind") == "url", str(s))
    check("a scanned link requires explicit confirmation to open", bool(j and j["actions"]["requires_user_confirmation"]))
    check("no 'safe' label is ever returned", '"safe"' not in json.dumps(j or {}).lower())

    s, _, j, _ = call(base, "/api/v1/scanner/analyze/", "POST", {"content": "javascript:alert(1)"})
    check("dangerous schemes are blocked", s == 200 and j["actions"]["blocked"] is True and j["actions"]["open_target"] is None, str(s))

    s, _, j, _ = call(base, "/api/v1/scanner/verify/definitely-not-a-real-token/")
    check("an unknown QR token is a clean 404 (no redirect)", s == 404 and j and j["error"]["code"] == "not_found", str(s))

    s, _, j, _ = call(base, "/api/v1/auth/me/")
    check("private endpoints refuse anonymous access", s == 401, str(s))

    s, _, j, _ = call(base, "/api/v1/admin/credits/overview/")
    check("admin endpoints refuse anonymous access", s in (401, 403), str(s))

    s, _, j, _ = call(base, "/api/v1/advertising/reward-callbacks/admob/?transaction_id=1&signature=x&key_id=1")
    check("a forged reward callback is refused", s in (400, 403, 503), str(s))
    s, _, j, _ = call(base, "/api/v1/advertising/reward-callbacks/google_ad_manager/")
    check("web rewarded ads have no (unverifiable) callback", s == 404, str(s))

    s, h, _, _ = call(base, "/api/v1/health/", headers={"Origin": "https://evil.example"})
    check("CORS does not allow an arbitrary origin", h.get("access-control-allow-origin") not in ("*", "https://evil.example"))
    if a.web_origin:
        s, h, _, _ = call(base, "/api/v1/health/", headers={"Origin": a.web_origin})
        check("CORS allows your web app origin", h.get("access-control-allow-origin") == a.web_origin, str(h.get("access-control-allow-origin")))

    s, _, j, _ = call(base, "/api/v1/plans/")
    check("plans endpoint answers", s == 200, str(s))
    s, _, j, _ = call(base, "/api/v1/advertising/config/")
    check("ad configuration is public-safe (no secrets)", s in (200, 401) and not any(w in json.dumps(j or {}).lower() for w in ("secret", "api_key", "password")), str(s))

    s, _, _, _ = call(base, "/admin/login/")
    if s == 200:
        warn("the admin sign-in is reachable at the default /admin/ address: set DJANGO_ADMIN_URL to move it and restrict it by IP/VPN if you can")
    if not https:
        warn("not an https:// URL: transport security was not checked")

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
