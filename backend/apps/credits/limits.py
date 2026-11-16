"""Where usage limits meet credits.

A user who exhausts a metered allowance is shown (a) the exact reset time, (b) their credit balance, (c) an optional rewarded
ad and (d) an upgrade option when pricing is on. Credits are spent ONLY when the user explicitly asks for it in the request
(`use_credits: true`); nothing is ever spent silently. Only features an administrator priced in credits can be credit-funded,
and only metered, non-essential features exist here: scanning, decoding and security warnings are never metered at all.
"""
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from apps.analytics import usage
from apps.billing import config as billing_config
from apps.billing import entitlements as ent
from apps.core.entitlements import FeatureLimitReached

from . import config as cfg
from . import rewarded, service

ESSENTIAL_NOTE = ("Decoding a QR code, public verification and security warnings never need credits or an advertisement.")


class UsageLimitReached(FeatureLimitReached):
    """A FeatureLimitReached that carries the full limit-screen data (shown in the error's `details`)."""

    def __init__(self, detail, extra: dict):
        super().__init__(detail)
        self.extra = extra


def credit_cost(user, feature_key: str, now=None) -> int | None:
    """Credits one extra use costs: a plan-level price (entitlement `credits.spend.feature_cost`) wins over the global table."""
    plan_costs = ent.resolve(user, "credits.spend.feature_cost", now).config or {}
    for source in (plan_costs, cfg.get("credits.feature_costs") or {}):
        if isinstance(source, dict) and feature_key in source:
            try:
                cost = int(source[feature_key])
            except (TypeError, ValueError):
                return None
            return cost if cost > 0 else None
    return None


def limit_screen(user, feature_key: str, *, platform: str | None = None, country: str = "", now=None) -> dict:
    now = now or datetime.now(timezone.utc)
    meta = usage.METERED[feature_key]
    limits, used = usage.limits_for(user, feature_key), usage.get_usage(user, feature_key, now)
    resolved = ent.resolve_all(user, now)
    windows, blocking, on_plan = [], [], True
    for w in usage.WINDOWS:
        e = resolved.get(meta["limits"][w], ent.Entitlement())
        on_plan = on_plan and e.enabled
        is_blocking = limits[w] is not None and used[w]["used"] + 1 > limits[w]
        row = {"window": w, "used": used[w]["used"], "limit": limits[w],
               "remaining": None if limits[w] is None else max(0, limits[w] - used[w]["used"]),
               "resets_at": used[w]["resets_at"], "timezone": "UTC", "blocking": is_blocking}
        windows.append(row)
        if is_blocking:
            blocking.append(row)
    resets_at = max((r["resets_at"] for r in blocking), default=None)         # every blocking window must reset first
    balance = service.balance_of(user, now)
    cost = credit_cost(user, feature_key, now)
    if not on_plan:
        credits_reason = "feature_not_on_plan"
    elif cost is None:
        credits_reason = "not_credit_funded"
    elif balance < cost:
        credits_reason = "insufficient_credits"
    else:
        credits_reason = None
    offers = [o for o in rewarded.list_offers(user, platform, country, now)] if platform and on_plan and cost is not None else []
    offers_open = [o for o in offers if o["available"]]
    return {
        "feature": feature_key, "label": meta["label"], "limit_reached": bool(blocking),
        "windows": windows, "resets_at": resets_at, "timezone": "UTC",
        "credits": {"balance": balance, "cost_per_use": cost, "applicable": on_plan and cost is not None,
                    "can_cover": credits_reason is None, "reason": credits_reason,
                    "how": "Send the same request with use_credits=true to spend credits for this one use."},
        "rewarded_ad": {"available": bool(offers_open), "offers": offers_open,
                        "reason": None if offers_open else ("no_eligible_offer" if offers else "not_applicable")},
        "upgrade": {"available": billing_config.pricing_enabled(), "plans_endpoint": "/api/v1/plans/"},
        "wait": {"resets_at": resets_at, "timezone": "UTC"},
        "essential_access": ESSENTIAL_NOTE,
    }


@dataclass
class Charge:
    kind: str                                  # "allowance" | "credits"
    entry: object = None

    def refund(self):
        """Give credits back if the use that they paid for then failed. A free allowance is not refunded (existing behaviour)."""
        if self.kind == "credits" and self.entry is not None:
            service.refund_usage(self.entry)


def consume_or_credits(user, feature_key: str, *, use_credits: bool = False, platform: str | None = None, country: str = "",
                       now=None) -> Charge:
    """Use the allowance; if it is exhausted, optionally (and only on request) pay with credits. Else raise UsageLimitReached."""
    try:
        usage.consume(user, feature_key, limits=usage.limits_for(user, feature_key), now=now)
        return Charge("allowance")
    except FeatureLimitReached as exc:
        screen = limit_screen(user, feature_key, platform=platform, country=country, now=now)
        c = screen["credits"]
        if use_credits and c["can_cover"]:
            try:
                entry = service.spend(user, c["cost_per_use"], feature_key=feature_key,
                                      idempotency_key=f"usage:{feature_key}:{uuid.uuid4()}",
                                      reason=f"Extra use of {screen['label']}", now=now)
                return Charge("credits", entry)
            except service.InsufficientCredits:
                screen["credits"].update(can_cover=False, reason="insufficient_credits")
        raise UsageLimitReached(str(exc.detail), screen) from exc
