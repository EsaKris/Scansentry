"""Rewarded-ad and credit settings, stored in AppConfiguration so they change without a deployment.

Keys starting with `rewarded` or `credits` need the `advertising.manage_ads` permission in the admin (see core/admin.py).
Everything that earns or spends credits is OFF / empty by default: a fresh install behaves exactly as before.
"""
from apps.core.config import get_config

DEFAULTS = {
    "rewarded_ads_enabled": False,                    # master switch for the whole rewarded-ad system
    "rewarded_ads_web_enabled": False,
    "rewarded_ads_android_enabled": False,
    "rewarded_ads_test_mode": True,                   # Google's test units; production refuses test-unit callbacks
    # Google Ad Manager's web rewarded ads have NO server-side verification (it is app-only). Web rewards can therefore only be
    # "client attested" and are OFF until an administrator accepts that risk explicitly.
    "rewarded_web_client_attested_enabled": False,
    "rewarded_session_ttl_seconds": 900,              # how long an ad session may take from creation to completion
    "rewarded_ssv_max_delay_seconds": 86400,          # a provider callback may arrive this long after the reward moment
    "rewarded_attested_min_watch_seconds": 5,         # client-attested completions faster than this are refused
    "rewarded_abuse_daily_threshold": 10,             # more rewards than this in 24 h flags the user in the admin overview
    "credits.feature_costs": {},                      # {"domain.lookups": 2}: credits per extra use; empty = no credit-funded use
}


def get(key: str):
    return get_config(key, DEFAULTS[key])


def flag(key: str) -> bool:
    return bool(get(key))


def number(key: str) -> int:
    try:
        return max(0, int(get(key)))
    except (TypeError, ValueError):
        return int(DEFAULTS[key])
