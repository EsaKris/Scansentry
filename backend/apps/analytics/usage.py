"""Atomic usage metering. Counters are authoritative and enforced on the backend (never by the client).

consume() locks the day/week/month counter rows, checks every configured limit, and only then increments
them, so concurrent requests cannot jointly exceed a limit.
"""
from datetime import datetime, timedelta, timezone

from django.db import transaction
from django.db.models import F

from apps.core.entitlements import FeatureLimitReached, get_limit

from .models import UsageCounter

WINDOWS = ("day", "week", "month")
# Metered features and the entitlement keys that hold their limits.
METERED = {
    "domain.lookups": {"label": "Domain lookups", "limits": {
        "day": "domain.lookups.daily_limit", "week": "domain.lookups.weekly_limit",
        "month": "domain.lookups.monthly_limit"}},
}


def window_bounds(window: str, now: datetime) -> tuple[datetime, datetime]:
    now = now.astimezone(timezone.utc)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if window == "day":
        return day, day + timedelta(days=1)
    if window == "week":
        start = day - timedelta(days=day.weekday())
        return start, start + timedelta(days=7)
    start = day.replace(day=1)
    end = (start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1))
    return start, end


def limits_for(user, key: str) -> dict:
    return {w: get_limit(user, ent) for w, ent in METERED[key]["limits"].items()}


def consume(user, key: str, *, limits: dict | None = None, amount: int = 1, now: datetime | None = None) -> None:
    """Raise FeatureLimitReached (with the reset time) if any window would exceed its limit; else increment."""
    now = now or datetime.now(timezone.utc)
    limits = limits or {}
    with transaction.atomic():
        rows = {}
        for w in WINDOWS:
            start, end = window_bounds(w, now)
            obj, _ = UsageCounter.objects.select_for_update().get_or_create(
                user=user, feature_key=key, window=w, period_start=start, defaults={"period_end": end})
            rows[w] = obj
        for w in WINDOWS:
            limit = limits.get(w)
            if limit is not None and rows[w].current_usage + amount > limit:
                label = {"day": "daily", "week": "weekly", "month": "monthly"}[w]
                raise FeatureLimitReached(
                    f"You have reached your {label} limit of {limit} for this feature. "
                    f"It resets at {rows[w].period_end.isoformat()} (UTC).")
        for obj in rows.values():
            UsageCounter.objects.filter(pk=obj.pk).update(current_usage=F("current_usage") + amount)


def get_usage(user, key: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    out = {}
    for w in WINDOWS:
        start, end = window_bounds(w, now)
        row = UsageCounter.objects.filter(user=user, feature_key=key, window=w, period_start=start).first()
        out[w] = {"used": row.current_usage if row else 0, "period_start": start, "resets_at": end}
    return out
