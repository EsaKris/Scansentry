from datetime import timedelta
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv

from config.env import env, env_bool, env_int, env_list

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", "insecure-dev-key-change-me")
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third party
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "django_filters",
    "drf_spectacular",
    # local
    "apps.core",
    "apps.accounts",
    "apps.organizations",
    "apps.audit",
    "apps.qr_codes",
    "apps.scanner",
    "apps.abuse_reports",
    "apps.domain_intel",
    "apps.threat_intel",
    "apps.security_engine",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

# --- Database (Supabase Postgres works through DATABASE_URL) -----------------
# Use the direct or session-pooler connection string for migrations.
# If you use Supabase's transaction pooler (port 6543), set
# DB_DISABLE_SERVER_SIDE_CURSORS=true.

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# DATABASES = {
#     "default": dj_database_url.config(
#         env="DATABASE_URL",
#         default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
#         conn_max_age=env_int("DB_CONN_MAX_AGE", 60),
#         ssl_require=env_bool("DB_SSL_REQUIRE", False),
#     )
# }
# DATABASES["default"]["DISABLE_SERVER_SIDE_CURSORS"] = env_bool(
#     "DB_DISABLE_SERVER_SIDE_CURSORS", False
# )
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Auth ---------------------------------------------------------------------
AUTH_USER_MODEL = "accounts.User"
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
PASSWORD_RESET_TIMEOUT = env_int("PASSWORD_RESET_TIMEOUT_SECONDS", 60 * 60)  # 1 hour
EMAIL_VERIFICATION_MAX_AGE = env_int("EMAIL_VERIFICATION_MAX_AGE_SECONDS", 60 * 60 * 72)

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=env_int("JWT_ACCESS_LIFETIME_MINUTES", 15)),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env_int("JWT_REFRESH_LIFETIME_DAYS", 7)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# --- DRF ----------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "EXCEPTION_HANDLER": "apps.core.exceptions.api_exception_handler",
    # Number of trusted reverse proxies in front of the API. 0 = use the socket address only
    # (X-Forwarded-For is ignored, so clients cannot spoof it to dodge rate limits).
    "NUM_PROXIES": env_int("NUM_PROXIES", 0),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {
        "anon": "60/min",
        "user": "300/min",
        "auth_login": "10/min",
        "auth_register": "5/min",
        "auth_password_reset": "5/min",
        "auth_verify": "10/min",
        "qr_resolve": "120/min",
        "scanner_decode": "30/min",
        "scanner_analyze": "60/min",
        "abuse_report": "5/hour",
        "domain_anon": "20/hour",
        "domain_user": "100/hour",
        "security_anon": "30/hour",
        "security_user": "200/hour",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "ScanSentry API",
    "DESCRIPTION": "Create. Verify. Monitor. Protect.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}

# --- CORS ---------------------------------------------------------------------
CORS_ALLOWED_ORIGINS = env_list("CORS_ALLOWED_ORIGINS", "http://localhost:5173")

# --- Email --------------------------------------------------------------------
EMAIL_BACKEND = env("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "ScanSentry <no-reply@scansentry.local>")
FRONTEND_URL = env("FRONTEND_URL", "http://localhost:5173")

# --- i18n / static / media ------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
}

# --- QR codes -------------------------------------------------------------------
# Base URL of the public redirect/verification domain used inside dynamic QR codes.
REDIRECT_BASE_URL = env("REDIRECT_BASE_URL", "http://localhost:8000").rstrip("/")
QR_MIN_CONTRAST_RATIO = float(env("QR_MIN_CONTRAST_RATIO", "4.0"))
QR_MAX_LOGO_RATIO = float(env("QR_MAX_LOGO_RATIO", "0.2"))
QR_MAX_LOGO_BYTES = env_int("QR_MAX_LOGO_BYTES", 1_000_000)
QR_MAX_PAYLOAD_CHARS = env_int("QR_MAX_PAYLOAD_CHARS", 2000)

# --- Scanner ----------------------------------------------------------------------
SCANNER_MAX_IMAGE_BYTES = env_int("SCANNER_MAX_IMAGE_BYTES", 5_000_000)
SCANNER_MAX_IMAGE_PIXELS = env_int("SCANNER_MAX_IMAGE_PIXELS", 20_000_000)
SCANNER_MAX_CONTENT_CHARS = env_int("SCANNER_MAX_CONTENT_CHARS", 4096)
ABUSE_EVIDENCE_MAX_BYTES = env_int("ABUSE_EVIDENCE_MAX_BYTES", 2_000_000)
ABUSE_DEDUPE_HOURS = env_int("ABUSE_DEDUPE_HOURS", 24)

# --- Domain intelligence / outbound network safety -----------------------------------
import json as _json

DOMAIN_CHECK_TIMEOUT = env_int("DOMAIN_CHECK_TIMEOUT", 20)              # whole assessment, seconds
NETGUARD_CONNECT_TIMEOUT = float(env("NETGUARD_CONNECT_TIMEOUT", "5"))
NETGUARD_TOTAL_TIMEOUT = float(env("NETGUARD_TOTAL_TIMEOUT", "10"))     # one fetch incl. redirects
NETGUARD_MAX_REDIRECTS = env_int("NETGUARD_MAX_REDIRECTS", 5)
NETGUARD_MAX_BODY_BYTES = env_int("NETGUARD_MAX_BODY_BYTES", 65536)
DNS_NAMESERVERS = env_list("DNS_NAMESERVERS", "")                       # empty = system resolver
DNS_TIMEOUT = float(env("DNS_TIMEOUT", "4"))
RDAP_BOOTSTRAP_URL = env("RDAP_BOOTSTRAP_URL", "https://data.iana.org/rdap/dns.json")
RDAP_TIMEOUT = float(env("RDAP_TIMEOUT", "8"))
# JSON, e.g. {"fallback_base": "https://rdap.example.net"}. No fallback by default: verify a
# provider's terms of service before using it commercially.
RDAP_PROVIDER_CONFIG = _json.loads(env("RDAP_PROVIDER_CONFIG", "") or "{}")

# --- AI explanations (optional) -------------------------------------------------------------
# AI only EXPLAINS deterministic findings. Leave AI_PROVIDER empty to use rule-based explanations only.
AI_PROVIDER = env("AI_PROVIDER", "")                         # "anthropic" or ""
AI_API_KEY = env("AI_API_KEY", "")
AI_MODEL = env("AI_MODEL", "claude-sonnet-5-5")              # verify the current model name in Anthropic's docs
AI_TIMEOUT = float(env("AI_TIMEOUT", "10"))
