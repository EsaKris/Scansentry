"""Idempotent defaults on migrate. Placements are created DISABLED with no ad unit ids: an administrator fills in the
real identifiers from their AdMob / Ad Manager / AdSense accounts and then enables them."""
from apps.core.models import AppConfiguration

from .settings_store import DEFAULTS

PROVIDERS = [
    ("google_adsense", "Google AdSense", "web", "Standard web display ads. Needs an approved AdSense account and site. NOT used for rewarded ads."),
    ("google_ad_manager", "Google Ad Manager", "web", "Web display/native and rewarded web inventory. Needs an Ad Manager network."),
    ("admob", "Google AdMob", "android", "Android banner/native/rewarded via the Google Mobile Ads SDK (needs an Expo development build, not Expo Go)."),
]
PLACEMENTS = [  # key, name, platform, surface, format, provider
    ("web.dashboard.banner", "Web dashboard banner", "web", "dashboard", "display", "google_adsense"),
    ("web.qr_library.banner", "Web QR library banner", "web", "qr_library", "display", "google_adsense"),
    ("web.analytics.banner", "Web analytics banner", "web", "analytics", "display", "google_adsense"),
    ("web.resources.native", "Web help/resources native", "web", "resources", "native", "google_ad_manager"),
    ("android.dashboard.banner", "Android dashboard banner", "android", "dashboard", "banner", "admob"),
    ("android.qr_library.banner", "Android QR library banner", "android", "qr_library", "banner", "admob"),
    ("android.analytics.banner", "Android analytics banner", "android", "analytics", "banner", "admob"),
    ("android.resources.native", "Android resources native", "android", "resources", "native", "admob"),
]


def seed_defaults() -> None:
    from .models import AdPlacement, AdProvider
    for key, value in DEFAULTS.items():
        AppConfiguration.objects.get_or_create(key=key, defaults=dict(
            value=value, is_public=False, description="Advertising setting (see docs). Edit in the admin."))
    providers = {}
    for key, name, platforms, notes in PROVIDERS:
        providers[key], _ = AdProvider.objects.get_or_create(key=key, defaults=dict(name=name, platforms=platforms, notes=notes))
    for key, name, platform, surface, fmt, prov in PLACEMENTS:
        AdPlacement.objects.get_or_create(key=key, defaults=dict(
            display_name=name, platform=platform, surface=surface, format=fmt, provider=providers[prov], enabled=False))
