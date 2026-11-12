"""Entitlement checks used by feature code.

Entitlements are resolved by apps.billing.entitlements from the user's effective plan, the feature
catalogue, the global baseline (`default_entitlements`) and administrative overrides. These functions
keep the signatures feature code has always used. Keys nobody configured mean "allowed / unlimited".
"""
from rest_framework import status
from rest_framework.exceptions import APIException



class FeatureNotAvailable(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "feature_not_available"
    default_detail = "This feature is not available on your current plan."


class FeatureLimitReached(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "limit_reached"
    default_detail = "You have reached the limit for this feature."


def _entitlement(user, key: str):
    from apps.billing.entitlements import resolve   # local import: billing depends on core
    return resolve(user, key)


def feature_enabled(user, key: str) -> bool:
    return _entitlement(user, key).enabled


def require_feature(user, key: str) -> None:
    if not feature_enabled(user, key):
        raise FeatureNotAvailable()


def get_limit(user, key: str):
    """Return an int limit (0 when the feature is off for this user), or None when unlimited."""
    e = _entitlement(user, key)
    return 0 if not e.enabled else e.limit
