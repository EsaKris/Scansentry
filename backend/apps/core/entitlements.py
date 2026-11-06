"""Entitlement checks used by feature code.

Milestone 2 placeholder: values come from the `default_entitlements` AppConfiguration row
(a JSON object such as {"qr.dynamic.active_limit": 5, "qr.svg_export": true}).
Milestone 6 replaces the lookup with plan/subscription-based entitlements while keeping
these function signatures, so feature code does not change. Missing keys mean
"allowed / unlimited" until an administrator configures them.
"""
from rest_framework import status
from rest_framework.exceptions import APIException

from .config import get_config


class FeatureNotAvailable(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "feature_not_available"
    default_detail = "This feature is not available on your current plan."


class FeatureLimitReached(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "limit_reached"
    default_detail = "You have reached the limit for this feature."


def _defaults() -> dict:
    value = get_config("default_entitlements", {})
    return value if isinstance(value, dict) else {}


def feature_enabled(user, key: str) -> bool:
    return bool(_defaults().get(key, True))


def require_feature(user, key: str) -> None:
    if not feature_enabled(user, key):
        raise FeatureNotAvailable()


def get_limit(user, key: str):
    """Return an int limit, or None when unlimited/unconfigured."""
    value = _defaults().get(key)
    return None if value is None else int(value)
