"""Billing switches, all stored in AppConfiguration so the product owner can change them without a deploy."""
from apps.core.config import get_config


def pricing_enabled() -> bool:
    return bool(get_config("pricing_enabled", False))


def free_plan_slug() -> str:
    return str(get_config("billing.free_plan_slug", "free"))


def pricing_disabled_plan_slug() -> str:
    """Plan whose entitlements apply to users WITHOUT paid access while pricing is switched off
    (the 'fallback access policy'). Defaults to the free plan."""
    return str(get_config("billing.pricing_disabled_plan_slug", free_plan_slug()))


def enabled_providers() -> list[str]:
    v = get_config("billing.enabled_providers", ["paystack"])
    return [str(x) for x in v] if isinstance(v, list) else ["paystack"]


def trials_enabled() -> bool:
    return bool(get_config("billing.trials_enabled", True))


def refund_revokes_access() -> bool:
    return bool(get_config("billing.refund_revokes_access", True))
