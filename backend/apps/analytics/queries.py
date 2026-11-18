"""Owner-scoped analytics aggregations. Bots are always excluded."""
import csv
import io
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from django.db.models import Count, Q
from django.db.models.functions import TruncDay, TruncMonth, TruncWeek

from apps.qr_codes.models import QRCode

from .models import ScanEvent

WARN_STATUSES = ("suspicious", "high_risk", "known_malicious")
INACTIVE_OUTCOMES = ("paused", "disabled", "expired", "blocked")
TRUNC = {"day": TruncDay, "week": TruncWeek, "month": TruncMonth}


def events(user, start, end, qr=None):
    qs = ScanEvent.objects.filter(qr_code__owner=user, is_bot=False, scanned_at__gte=start, scanned_at__lt=end)
    return qs.filter(qr_code=qr) if qr is not None else qs


def _floor(dt, granularity):
    dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if granularity == "week":
        return dt - timedelta(days=dt.weekday())
    if granularity == "month":
        return dt.replace(day=1)
    return dt


def _next(dt, granularity):
    if granularity == "day":
        return dt + timedelta(days=1)
    if granularity == "week":
        return dt + timedelta(days=7)
    return dt.replace(year=dt.year + 1, month=1) if dt.month == 12 else dt.replace(month=dt.month + 1)


def time_series(qs, start, end, granularity: str, tz: ZoneInfo) -> list[dict]:
    rows = (qs.annotate(p=TRUNC[granularity]("scanned_at", tzinfo=tz)).values("p")
            .annotate(scans=Count("id"), unique=Count("visitor_hash", distinct=True)).order_by("p"))
    found = {r["p"].astimezone(tz).date(): r for r in rows}
    out, cur = [], _floor(start.astimezone(tz), granularity)
    last = end.astimezone(tz)
    while cur < last:
        r = found.get(cur.date())
        out.append({"period": cur.date().isoformat(), "scans": r["scans"] if r else 0,
                    "unique_estimate": r["unique"] if r else 0})
        cur = _next(cur, granularity)
    return out


def breakdown(qs, field: str) -> list[dict]:
    rows = qs.values(field).annotate(scans=Count("id")).order_by("-scans", field)
    return [{"key": r[field] or "unknown", "scans": r["scans"]} for r in rows]


def totals(qs) -> dict:
    agg = qs.aggregate(scans=Count("id"), unique=Count("visitor_hash", distinct=True),
                       warnings=Count("id", filter=Q(security_status_at_scan__in=WARN_STATUSES) | Q(outcome="blocked")),
                       inactive=Count("id", filter=Q(outcome__in=INACTIVE_OUTCOMES)))
    return {"scans": agg["scans"], "unique_estimate": agg["unique"], "security_warnings_shown": agg["warnings"],
            "disabled_or_inactive_activity": agg["inactive"]}


def qr_performance(user, start, end):
    f = Q(scan_events__is_bot=False, scan_events__scanned_at__gte=start, scan_events__scanned_at__lt=end)
    return (QRCode.objects.filter(owner=user).select_related("campaign").annotate(
        scans=Count("scan_events", filter=f),
        uniques=Count("scan_events__visitor_hash", filter=f, distinct=True),
        warnings=Count("scan_events", filter=f & (Q(scan_events__security_status_at_scan__in=WARN_STATUSES)
                                                   | Q(scan_events__outcome="blocked"))),
        inactive=Count("scan_events", filter=f & Q(scan_events__outcome__in=INACTIVE_OUTCOMES)),
    ).order_by("-scans", "name"))


def campaign_comparison(rows) -> list[dict]:
    agg: dict = {}
    for r in rows:
        key = r.campaign_id
        a = agg.setdefault(key, {"campaign_id": str(key) if key else None,
                                 "campaign": r.campaign.name if r.campaign else "(no campaign)",
                                 "codes": 0, "scans": 0, "unique_estimate": 0, "security_warnings_shown": 0})
        a["codes"] += 1
        a["scans"] += r.scans
        a["unique_estimate"] += r.uniques
        a["security_warnings_shown"] += r.warnings
    return sorted(agg.values(), key=lambda x: (-x["scans"], x["campaign"]))


def csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow([csv_safe(c) for c in row])
    return buf.getvalue()
