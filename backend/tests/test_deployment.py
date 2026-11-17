"""Production configuration, structured logging, error-monitoring privacy and admin sign-in protection."""
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from django.core.cache import cache
from django.test import Client, override_settings

from config import logging_utils, sentry_setup

BACKEND = Path(__file__).resolve().parent.parent
GOOD = {"DJANGO_SECRET_KEY": "k" * 64, "DJANGO_ALLOWED_HOSTS": "api.example.com", "CORS_ALLOWED_ORIGINS": "https://app.example.com",
        "DATABASE_URL": "sqlite:////tmp/deploy-test.sqlite3", "REDIS_URL": "redis://localhost:6399/0"}


def production(**env):
    """Import config.settings.production in a clean process and report what happened (the module raises on a bad setup)."""
    base = {k: v for k, v in os.environ.items() if not k.startswith(("DJANGO_", "REDIS", "ALLOW_", "FILE_", "S3_", "SENTRY", "CORS_", "DATABASE_"))}
    base.update(GOOD)
    base.update(env)
    base = {k: v for k, v in base.items() if v is not None}
    code = ("import json, importlib; m = importlib.import_module('config.settings.production');"
            "print(json.dumps({'storage': m.STORAGES['default'], 'cache': m.CACHES['default']['BACKEND'], 'sentry': m.SENTRY_ENABLED,"
            "'log': m.LOGGING['handlers']['console']['formatter'], 'admin': m.ADMIN_URL}))")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=BACKEND, env={**base, "PYTHONPATH": str(BACKEND)})
    return r


def ok(**env):
    r = production(**env)
    assert r.returncode == 0, r.stderr[-600:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def fails(message, **env):
    r = production(**env)
    assert r.returncode != 0 and message in r.stderr, (r.returncode, r.stderr[-400:])


# ---- production settings fail closed ---------------------------------------------------------------------------------------------
def test_a_correct_production_configuration_starts():
    cfg = ok()
    assert cfg["cache"].endswith("RedisCache") and cfg["log"] == "json" and cfg["sentry"] is False


def test_production_refuses_a_missing_or_weak_secret_key():
    fails("DJANGO_SECRET_KEY", DJANGO_SECRET_KEY="insecure-dev-key-change-me")
    fails("DJANGO_SECRET_KEY", DJANGO_SECRET_KEY="short")


def test_production_refuses_default_allowed_hosts():
    fails("DJANGO_ALLOWED_HOSTS", DJANGO_ALLOWED_HOSTS="localhost,127.0.0.1")


def test_production_refuses_plain_http_cors_origins():
    fails("https://", CORS_ALLOWED_ORIGINS="http://app.example.com")


def test_production_needs_a_shared_cache_so_rate_limits_are_not_multiplied_per_worker():
    fails("REDIS_URL is required", REDIS_URL=None)
    assert ok(REDIS_URL=None, ALLOW_LOCAL_CACHE_SINGLE_WORKER="true")["cache"].endswith("LocMemCache")     # explicit single-worker opt-out


def test_object_storage_must_be_private_and_signed():
    cfg = ok(FILE_STORAGE_PROVIDER="s3", S3_BUCKET_NAME="scansentry-private", S3_ENDPOINT_URL="https://x.supabase.co/storage/v1/s3",
             S3_ACCESS_KEY_ID="a", S3_SECRET_ACCESS_KEY="b", S3_REGION="eu-west-1")["storage"]
    assert cfg["BACKEND"] == "storages.backends.s3.S3Storage"
    o = cfg["OPTIONS"]
    assert o["default_acl"] == "private" and o["querystring_auth"] is True and o["file_overwrite"] is False and o["querystring_expire"] <= 600


def test_object_storage_needs_a_bucket_and_an_known_provider():
    fails("S3_BUCKET_NAME", FILE_STORAGE_PROVIDER="s3")
    fails("FILE_STORAGE_PROVIDER", FILE_STORAGE_PROVIDER="dropbox")


def test_filesystem_storage_is_the_default():
    assert ok()["storage"]["BACKEND"].endswith("FileSystemStorage")


def test_the_admin_path_is_configurable():
    assert ok(DJANGO_ADMIN_URL="ops-7f3a/")["admin"] == "ops-7f3a/"


def test_sentry_is_enabled_only_with_a_dsn():
    assert ok(SENTRY_DSN="https://public@o0.ingest.sentry.io/1")["sentry"] is True


# ---- a shared cache really is shared (needs a Redis; skipped when none is reachable) ------------------------------------------------
def test_two_processes_share_one_rate_limit_counter_through_redis():
    import redis
    url = os.environ.get("REDIS_TEST_URL", GOOD["REDIS_URL"])
    try:
        redis.Redis.from_url(url).ping()
    except Exception:
        pytest.skip("no Redis reachable")
    code = ("import django; django.setup(); from django.core.cache import cache; cache.add('shared-counter-test', 0, 30); print(cache.incr('shared-counter-test'))")
    env = {**os.environ, **GOOD, "REDIS_URL": url, "DJANGO_SETTINGS_MODULE": "config.settings.production", "PYTHONPATH": str(BACKEND)}
    counts = [int(subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=BACKEND, env=env).stdout.strip()) for _ in range(3)]
    redis.Redis.from_url(url).delete("scansentry:1:shared-counter-test")
    assert counts == [1, 2, 3]


# ---- structured logging ------------------------------------------------------------------------------------------------------------------
def record(msg, *args, level=logging.ERROR, exc=None):
    r = logging.LogRecord("scansentry.test", level, __file__, 1, msg, args, exc)
    logging_utils.RequestIdFilter().filter(r)
    return r


def test_json_log_lines_are_parseable_and_carry_the_request_id():
    token = logging_utils.request_id_var.set("req-12345678")
    try:
        line = logging_utils.JsonFormatter().format(record("hello %s", "world"))
    finally:
        logging_utils.request_id_var.reset(token)
    data = json.loads(line)
    assert data["message"] == "hello world" and data["level"] == "ERROR" and data["request_id"] == "req-12345678" and data["time"].endswith("+00:00")


def test_logs_never_contain_query_strings_or_bearer_tokens():
    line = logging_utils.JsonFormatter().format(record("GET /api/v1/advertising/reward-callbacks/admob/?custom_data=SECRET&signature=ABC Bearer eyJhbGciOi.abc.def"))
    assert "SECRET" not in line and "signature=ABC" not in line and "eyJhbGciOi" not in line and "[query removed]" in line
    try:
        raise ValueError("failed for https://shop.com/?token=abc123")
    except ValueError:
        line = logging_utils.JsonFormatter().format(record("boom", exc=sys.exc_info()))
    assert "abc123" not in line and "exception" in json.loads(line)


def test_text_logging_is_the_development_default():
    assert logging_utils.build_logging("INFO", "text")["handlers"]["console"]["formatter"] == "text"
    assert logging_utils.build_logging("INFO", "json")["handlers"]["console"]["formatter"] == "json"


@pytest.mark.django_db
def test_every_response_has_a_request_id_and_a_valid_incoming_one_is_kept(api):
    r = api.get("/api/v1/health/")
    assert len(r["X-Request-ID"]) == 32
    assert api.get("/api/v1/health/", HTTP_X_REQUEST_ID="trace-abcdef123")["X-Request-ID"] == "trace-abcdef123"
    assert api.get("/api/v1/health/", HTTP_X_REQUEST_ID="bad id with spaces/<script>")["X-Request-ID"] != "bad id with spaces/<script>"
    assert len(api.get("/api/v1/health/", HTTP_X_REQUEST_ID="x" * 500)["X-Request-ID"]) == 32


@pytest.mark.django_db
def test_server_errors_are_logged_with_the_path_but_never_the_query(api, caplog, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("apps.core.views.HealthView.get", boom)
    api.raise_request_exception = False
    with caplog.at_level(logging.INFO, logger="scansentry.request"):
        assert api.get("/api/v1/health/?secret=topsecret").status_code == 500
    text = " ".join(r.getMessage() for r in caplog.records if r.name == "scansentry.request")
    assert "/api/v1/health/" in text and "topsecret" not in text


# ---- Sentry privacy -----------------------------------------------------------------------------------------------------------------------
def test_sentry_events_are_scrubbed_of_query_strings_bodies_cookies_and_identity():
    event = {"request": {"url": "https://api.example.com/api/v1/scanner/verify/TOKEN?x=secret", "query_string": "x=secret", "cookies": {"s": "1"},
                         "data": {"content": "https://private.example"}, "headers": {"Authorization": "Bearer abc", "Accept": "json", "X-Forwarded-For": "1.2.3.4"}},
             "user": {"email": "a@b.c", "ip_address": "1.2.3.4"},
             "breadcrumbs": {"values": [{"message": "GET /x?token=zzz", "data": {"url": "https://a/b?token=zzz"}}]}}
    out = sentry_setup.scrub_event(event)
    flat = json.dumps(out)
    for secret in ("secret", "abc", "1.2.3.4", "a@b.c", "zzz", "private.example"):
        assert secret not in flat, secret
    assert out["request"]["headers"]["Accept"] == "json" and "user" not in out


def test_sentry_does_nothing_without_a_dsn():
    assert sentry_setup.init_sentry("", "production") is False


# ---- admin sign-in protection ---------------------------------------------------------------------------------------------------------------
@pytest.mark.django_db
def test_admin_sign_in_is_rate_limited_per_client():
    cache.clear()
    c = Client()
    codes = [c.post("/admin/login/", {"username": "x@example.com", "password": "wrong"}).status_code for _ in range(12)]
    assert 429 not in codes[:10] and codes[-1] == 429
    assert c.get("/admin/login/").status_code == 200                       # viewing the form is never blocked


@pytest.mark.django_db
def test_admin_throttle_is_per_client_address():
    cache.clear()
    a, b = Client(REMOTE_ADDR="10.0.0.1"), Client(REMOTE_ADDR="10.0.0.2")
    for _ in range(11):
        a.post("/admin/login/", {"username": "x", "password": "y"})
    assert a.post("/admin/login/", {"username": "x", "password": "y"}).status_code == 429
    assert b.post("/admin/login/", {"username": "x", "password": "y"}).status_code != 429


@pytest.mark.django_db
def test_admin_throttle_follows_the_configured_admin_path():
    cache.clear()
    with override_settings(ADMIN_URL="ops-7f3a/", ADMIN_LOGIN_ATTEMPTS=2):
        c = Client()
        for _ in range(3):
            c.post("/ops-7f3a/login/", {"username": "x", "password": "y"})
        assert c.post("/ops-7f3a/login/", {}).status_code == 429


@pytest.mark.django_db
def test_forged_forwarded_for_cannot_dodge_the_admin_throttle():
    cache.clear()
    c = Client(REMOTE_ADDR="10.0.0.9")
    for i in range(11):
        c.post("/admin/login/", {"username": "x", "password": "y"}, HTTP_X_FORWARDED_FOR=f"9.9.9.{i}")
    assert c.post("/admin/login/", {}, HTTP_X_FORWARDED_FOR="1.1.1.1").status_code == 429     # NUM_PROXIES=0: the header is ignored


@pytest.mark.django_db
def test_health_endpoint_reports_the_database(api):
    r = api.get("/api/v1/health/")
    assert r.status_code == 200 and r.data == {"status": "ok", "database": "ok"}


# ---- the post-deployment smoke script --------------------------------------------------------------------------------------------------------
def test_the_smoke_test_script_passes_against_a_running_server(live_server, transactional_db):
    r = subprocess.run([sys.executable, str(BACKEND / "scripts" / "smoke_test.py"), live_server.url], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-1500:]
    assert "checks passed" in r.stdout and "FAIL" not in r.stdout


def test_the_smoke_test_script_fails_when_the_server_misbehaves(live_server, transactional_db, monkeypatch):
    """A smoke test that cannot fail is worthless: point it at a server whose health endpoint is broken."""
    from rest_framework.response import Response
    monkeypatch.setattr("apps.core.views.HealthView.get",
                        lambda self, request: Response({"status": "degraded", "database": "unavailable"}, status=503))
    r = subprocess.run([sys.executable, str(BACKEND / "scripts" / "smoke_test.py"), live_server.url], capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and "FAIL  health endpoint" in r.stdout
