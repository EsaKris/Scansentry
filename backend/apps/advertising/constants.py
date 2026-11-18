"""Advertising rules that are NOT configurable, because they protect users.

Ads may only ever appear on the ALLOWED surfaces (calm, non-critical screens). Everything in FORBIDDEN is refused by the
backend for every client, regardless of any administrator setting.
"""
ALLOWED_SURFACES = {
    "dashboard": "Dashboard",
    "qr_library": "QR library",
    "analytics": "Non-critical analytics",
    "resources": "Educational resources and help",
    "account": "Account and settings (non-critical)",
}

# Never show ads here (spec section 9.E). The backend answers "no placements" for these on both platforms.
FORBIDDEN_SURFACES = {
    "scanner": "During QR camera scanning",
    "scan_result": "Before / while a scan result is displayed",
    "verification": "On public QR verification pages",
    "security_warning": "On a security warning or malicious-destination page",
    "threat_result": "Between a detected threat and its explanation",
    "security_confirmation": "During a security-critical confirmation",
    "qr_generation": "While generating a QR code",
    "qr_download": "While downloading a QR code",
    "redirect": "On dynamic QR redirect or verification flows",
    "emergency_alert": "On emergency security alerts",
    "domain_report": "On security / domain assessment results",
}

PLATFORMS = ("web", "android")
SPONSORED_LABEL = "Advertisement"

# provider -> (platforms, formats)
PROVIDER_CAPABILITIES = {
    "google_adsense": ({"web"}, {"display"}),
    "google_ad_manager": ({"web"}, {"display", "banner", "native", "rewarded"}),
    "admob": ({"android"}, {"banner", "native", "rewarded"}),
}

# Official Google sample/test units (documented by Google for development). They must never be used in production.
ADMOB_TEST_APP_ID = "ca-app-pub-3940256099942544~3347511713"
ADMOB_TEST_UNITS = {"banner": "ca-app-pub-3940256099942544/6300978111", "native": "ca-app-pub-3940256099942544/2247696110",
                    "rewarded": "ca-app-pub-3940256099942544/5224354917"}
AD_MANAGER_TEST_UNIT = "/6499/example/banner"
TEST_ID_MARKERS = ("ca-app-pub-3940256099942544", "/6499/example")


def is_test_identifier(value: str) -> bool:
    v = (value or "").strip()
    return any(m in v for m in TEST_ID_MARKERS)
