"""Advertising switches, stored in AppConfiguration so they can be changed without a deployment."""
from apps.core.config import get_config

DEFAULTS = {
    "ads_enabled": False,                    # master switch: stays OFF until ad accounts/providers are ready
    "ads_web_enabled": True,
    "ads_android_enabled": True,
    "ads_enabled_for_free_users": True,
    "ads_enabled_for_trial_users": True,
    "ads_enabled_for_paid_users": False,
    "ads_enabled_for_enterprise_users": False,
    "ads_non_personalized_default": True,    # privacy-first
    "ads_test_mode": True,                   # official test units until an administrator switches to production
    "ads_frequency_limits": {"max_per_session": 3, "min_seconds_between": 60},
    "ads_remove_with_premium": True,
    "ads_enterprise_plan_slugs": ["enterprise"],
}


def get(key: str):
    return get_config(key, DEFAULTS[key])


def flag(key: str) -> bool:
    return bool(get(key))
