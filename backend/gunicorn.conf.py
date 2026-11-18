"""Gunicorn settings (all overridable by environment variables)."""
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = int(os.environ.get("WEB_CONCURRENCY", "3"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))        # a domain assessment can take ~20 s
graceful_timeout = 30
keepalive = 5
max_requests = 1000                                             # recycle workers to contain slow leaks
max_requests_jitter = 100
worker_tmp_dir = "/dev/shm"

# Access logging is OFF by default. When enabled it records the PATH only: never the query string (reward callbacks, scan content and
# tokens travel there) and never the client address, which keeps the "no raw IPs" promise. A reverse proxy in front may still log them:
# see docs/DEPLOYMENT.md.
accesslog = "-" if os.environ.get("GUNICORN_ACCESS_LOG", "false").lower() in ("1", "true", "yes") else None
access_log_format = '"%(m)s %(U)s" %(s)s %(b)s %(L)s'          # %(U)s = URL path without the query string
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
forwarded_allow_ips = os.environ.get("GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1")
