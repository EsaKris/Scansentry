"""The single source of truth for 'what may this user do?'. Web and Android both rely on it.

Layers, lowest to highest priority:
  1. FeatureDefinition default
  2. legacy global baseline: AppConfiguration "default_entitlements" (kept for backward compatibility)
  3. the user's effective plan (paid plan with access, else the free / pricing-disabled plan)
  4. administrative overrides (temporary premium plan access, then feature grants/revokes)
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from apps.core.config import get_config

from . import config
from .models import EntitlementOverride, FeatureDefinition, Plan, PlanFeature, Subscription

S = Subscription.Status


@dataclass
class Entitlement:
    enabled: bool = True
    limit: int | None = None        # None = unlimited (only meaningful when enabled)
    config: dict = field(default_factory=dict)
    source: str = "default"


def access_until(sub: Subscription) -> datetime | None:
    """Until when does this subscription grant its plan's entitlements? (None = never / not at all)"""
    grace = timedelta(days=sub.plan.grace_period_days)
    if sub.status == S.TRIALING:
        return sub.trial_ends_at
    if sub.status in (S.ACTIVE, S.PAST_DUE, S.GRACE_PERIOD):
        return sub.current_period_end + grace if sub.current_period_end else None
    if sub.status == S.CANCELLED:                       # paid access is never cut short by cancelling
        return sub.current_period_end
    return None                                         # pending_payment, expired, suspended


def has_access(sub: Subscription | None, now: datetime) -> bool:
    if sub is None:
        return False
    until = access_until(sub)
    return until is not None and now < until


def current_subscription(user) -> Subscription | None:
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    return Subscription.objects.filter(user=user, is_current=True).select_related("plan").first()


def effective_plan(user, now: datetime | None = None):
    """Returns (plan | None, subscription | None, reason)."""
    now = now or datetime.now(timezone.utc)
    sub = current_subscription(user)
    if has_access(sub, now):
        return sub.plan, sub, "subscription"
    slug = config.free_plan_slug() if config.pricing_enabled() else config.pricing_disabled_plan_slug()
    plan = Plan.objects.filter(slug=slug).first() or Plan.objects.filter(slug=config.free_plan_slug()).first()
    return plan, sub, ("pricing_disabled_policy" if not config.pricing_enabled() else "free_plan")


def _apply_plan(values: dict, plan: Plan, source: str) -> None:
    for pf in PlanFeature.objects.filter(plan=plan).select_related("feature"):
        values[pf.feature.key] = Entitlement(pf.enabled, pf.limit_value if pf.enabled else 0, pf.configuration or {}, source)


def resolve_all(user, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    values: dict[str, Entitlement] = {}
    for f in FeatureDefinition.objects.filter(active=True):
        if f.data_type == "boolean":
            values[f.key] = Entitlement(bool(f.default_value) if f.default_value is not None else True)
        else:
            values[f.key] = Entitlement(True, f.default_value if isinstance(f.default_value, int) else None)
    legacy = get_config("default_entitlements", {})
    if isinstance(legacy, dict):
        for key, v in legacy.items():
            if isinstance(v, bool):
                values[key] = Entitlement(v, None if v else 0, source="global_baseline")
            elif isinstance(v, int):
                values[key] = Entitlement(True, v, source="global_baseline")
    plan, _sub, reason = effective_plan(user, now)
    if plan is not None:
        _apply_plan(values, plan, f"plan:{plan.slug}")
    if user is not None and getattr(user, "is_authenticated", False):
        active = (EntitlementOverride.objects.filter(user=user, revoked_at__isnull=True)
                  .exclude(expires_at__lte=now).select_related("feature", "plan").order_by("created_at"))
        overrides = list(active)
        for o in overrides:                                   # temporary premium plans first ...
            if o.kind == EntitlementOverride.Kind.PLAN_TRIAL and o.plan_id:
                _apply_plan(values, o.plan, f"override:plan:{o.plan.slug}")
        for o in overrides:                                   # ... then specific grants / revokes win
            if o.kind != EntitlementOverride.Kind.PLAN_TRIAL and o.feature_id:
                values[o.feature.key] = Entitlement(o.enabled, o.limit_value if o.enabled else 0, {}, f"override:{o.kind}")
    return values


def resolve(user, key: str, now: datetime | None = None) -> Entitlement:
    return resolve_all(user, now).get(key, Entitlement())     # unknown keys: allowed and unlimited (compatible default)
