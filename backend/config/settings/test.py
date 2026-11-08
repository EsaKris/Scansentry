from .base import *  # noqa: F401,F403

SECRET_KEY = "test-secret-key-that-is-long-enough-for-hmac-sha256"
DEBUG = False
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
REST_FRAMEWORK = {
    **REST_FRAMEWORK,  # noqa: F405
    "DEFAULT_THROTTLE_RATES": {
        "anon": "10000/min", "user": "10000/min", "auth_login": "10000/min",
        "auth_register": "10000/min", "auth_password_reset": "10000/min",
        "auth_verify": "10000/min", "qr_resolve": "10000/min", "scanner_decode": "10000/min", "scanner_analyze": "10000/min", "abuse_report": "10000/hour", "domain_anon": "10000/hour", "domain_user": "10000/hour", "security_anon": "10000/hour", "security_user": "10000/hour",
    },
}

MIDDLEWARE = [m for m in MIDDLEWARE if "whitenoise" not in m]
