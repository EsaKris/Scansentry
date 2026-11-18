from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.entitlements import FeatureNotAvailable, feature_enabled, get_limit, require_feature
from apps.qr_codes.models import QRCode

from . import queries as Q
from . import usage

MAX_DAYS = 730


class RangeParams(serializers.Serializer):
    days = serializers.IntegerField(min_value=1, max_value=MAX_DAYS, default=30)
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)
    granularity = serializers.ChoiceField(choices=["day", "week", "month"], default="day")
    tz = serializers.CharField(default="UTC", max_length=64)
    qr = serializers.UUIDField(required=False)
    export = serializers.ChoiceField(choices=["csv"], required=False)


def parse_params(request):
    raw = {k: v for k, v in request.query_params.items()}
    raw["date_from"] = raw.pop("from", None)
    raw["date_to"] = raw.pop("to", None)
    ser = RangeParams(data={k: v for k, v in raw.items() if v not in (None, "")})
    ser.is_valid(raise_exception=True)
    d = ser.validated_data
    try:
        tz = ZoneInfo(d["tz"])
    except (ZoneInfoNotFoundError, ValueError):
        raise ValidationError({"tz": "Unknown time zone. Use an IANA name such as Africa/Lagos."})
    if d.get("date_from") or d.get("date_to"):
        end_day = d.get("date_to") or datetime.now(tz).date()
        start_day = d.get("date_from") or (end_day - timedelta(days=d["days"] - 1))
        if start_day > end_day:
            raise ValidationError({"from": "The start date must not be after the end date."})
        if (end_day - start_day).days + 1 > MAX_DAYS:
            raise ValidationError({"from": f"The range may not exceed {MAX_DAYS} days."})
        end_local = datetime.combine(end_day + timedelta(days=1), time.min, tzinfo=tz)
        start_local = datetime.combine(start_day, time.min, tzinfo=tz)
    else:
        end_local = datetime.combine(datetime.now(tz).date() + timedelta(days=1), time.min, tzinfo=tz)
        start_local = end_local - timedelta(days=d["days"])
    return d, tz, start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def csv_response(text: str, name: str) -> HttpResponse:
    resp = HttpResponse(text, content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{name}.csv"'
    resp["Cache-Control"] = "private, no-store"
    resp["X-Content-Type-Options"] = "nosniff"
    return resp


def _range_info(start, end, tz, granularity=None):
    info = {"start": start, "end": end, "timezone": str(tz)}
    if granularity:
        info["granularity"] = granularity
    return info


PARAMS = [OpenApiParameter("days", OpenApiTypes.INT, description="Last N days (default 30)"),
          OpenApiParameter("from", OpenApiTypes.DATE), OpenApiParameter("to", OpenApiTypes.DATE),
          OpenApiParameter("granularity", OpenApiTypes.STR, enum=["day", "week", "month"]),
          OpenApiParameter("tz", OpenApiTypes.STR, description="IANA time zone, e.g. Africa/Lagos"),
          OpenApiParameter("export", OpenApiTypes.STR, enum=["csv"], description="Needs advanced analytics")]


def scan_report(user, qr, start, end, granularity, tz) -> dict:
    qs = Q.events(user, start, end, qr)
    advanced = feature_enabled(user, "qr.analytics.advanced")
    out = {
        "range": _range_info(start, end, tz, granularity),
        "totals": Q.totals(qs),
        "series": Q.time_series(qs, start, end, granularity, tz),
        "breakdowns": {"device": Q.breakdown(qs, "device_category"), "scanner_type": Q.breakdown(qs, "scanner_type"),
                       "outcome": Q.breakdown(qs, "outcome")},
        "locked": [],
        "privacy_note": ("Counts exclude link-preview and crawler traffic. 'Unique' is an estimate per day from a "
                         "daily-rotating hash; no IP address or user agent is stored."),
    }
    if advanced:
        out["breakdowns"].update({"browser": Q.breakdown(qs, "browser_category"),
                                  "country": Q.breakdown(qs, "approximate_country"),
                                  "region": Q.breakdown(qs.exclude(approximate_region=""), "approximate_region"),
                                  "security_status": Q.breakdown(qs, "security_status_at_scan")})
    else:
        out["locked"] = ["browser", "country", "region", "security_status", "export"]
    return out


class OverviewView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=PARAMS, responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        require_feature(request.user, "qr.analytics.basic")
        d, tz, start, end = parse_params(request)
        user = request.user
        qs = Q.events(user, start, end)
        prev = Q.events(user, start - (end - start), start)
        cur_scans, prev_scans = qs.count(), prev.count()
        codes = QRCode.objects.filter(owner=user)
        top = list(Q.qr_performance(user, start, end)[:5])
        return Response({
            "range": _range_info(start, end, tz),
            "totals": {**Q.totals(qs), "previous_period_scans": prev_scans,
                       "change_percent": (None if prev_scans == 0 else round(100 * (cur_scans - prev_scans) / prev_scans, 1))},
            "codes": {"total": codes.count(), "active_dynamic": codes.filter(code_mode="dynamic", status="active").count(),
                      "paused": codes.filter(status="paused").count(), "disabled": codes.filter(status="disabled").count()},
            "top_codes": [{"id": str(r.id), "name": r.name, "scans": r.scans, "unique_estimate": r.uniques} for r in top if r.scans],
            "devices": Q.breakdown(qs, "device_category"),
        })


class ScansView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=PARAMS + [OpenApiParameter("qr", OpenApiTypes.UUID)], responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        require_feature(request.user, "qr.analytics.basic")
        d, tz, start, end = parse_params(request)
        qr = get_object_or_404(QRCode, pk=d["qr"], owner=request.user) if d.get("qr") else None
        report = scan_report(request.user, qr, start, end, d["granularity"], tz)
        if d.get("export") == "csv":
            require_feature(request.user, "qr.analytics.advanced")
            rows = [[r["period"], r["scans"], r["unique_estimate"]] for r in report["series"]]
            return csv_response(Q.to_csv(["period", "scans", "unique_estimate"], rows), "scans")
        return Response(report)


class QRPerformanceView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=PARAMS, responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        require_feature(request.user, "qr.analytics.basic")
        d, tz, start, end = parse_params(request)
        rows = list(Q.qr_performance(request.user, start, end))
        advanced = feature_enabled(request.user, "qr.analytics.advanced")
        if d.get("export") == "csv":
            require_feature(request.user, "qr.analytics.advanced")
            data = [[r.name, r.code_mode, r.status, r.campaign.name if r.campaign else "", r.scans, r.uniques, r.warnings,
                     r.inactive, r.last_scanned_at.isoformat() if r.last_scanned_at else ""] for r in rows]
            return csv_response(Q.to_csv(["name", "mode", "status", "campaign", "scans", "unique_estimate",
                                          "security_warnings_shown", "disabled_or_inactive_activity", "last_scanned_at"], data),
                                "qr-performance")
        return Response({
            "range": _range_info(start, end, tz),
            "codes": [{"id": str(r.id), "name": r.name, "qr_type": r.qr_type, "code_mode": r.code_mode, "status": r.status,
                       "campaign": r.campaign.name if r.campaign else None, "scans": r.scans, "unique_estimate": r.uniques,
                       "security_warnings_shown": r.warnings, "disabled_or_inactive_activity": r.inactive,
                       "last_scanned_at": r.last_scanned_at} for r in rows],
            "campaigns": Q.campaign_comparison(rows) if advanced else None,
            "locked": [] if advanced else ["campaigns", "export"],
        })


class QRAnalyticsView(APIView):
    """GET /qr/{id}/analytics/ - scans for one code (owner only)."""

    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=PARAMS, responses={200: OpenApiTypes.OBJECT})
    def get(self, request, pk):
        require_feature(request.user, "qr.analytics.basic")
        qr = get_object_or_404(QRCode, pk=pk, owner=request.user)
        d, tz, start, end = parse_params(request)
        report = scan_report(request.user, qr, start, end, d["granularity"], tz)
        report["qr"] = {"id": str(qr.id), "name": qr.name, "status": qr.effective_status, "code_mode": qr.code_mode,
                        "last_scanned_at": qr.last_scanned_at}
        if d.get("export") == "csv":
            require_feature(request.user, "qr.analytics.advanced")
            rows = [[r["period"], r["scans"], r["unique_estimate"]] for r in report["series"]]
            return csv_response(Q.to_csv(["period", "scans", "unique_estimate"], rows), f"qr-{qr.id}-scans")
        return Response(report)


class UsageView(APIView):
    """Current usage per metered feature with limits and exact reset times."""

    permission_classes = [IsAuthenticated]
    configured_only = False

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        user = request.user
        features = []
        for key, meta in usage.METERED.items():
            lim, used = usage.limits_for(user, key), usage.get_usage(user, key)
            windows = []
            for w in usage.WINDOWS:
                if self.configured_only and lim[w] is None:
                    continue
                windows.append({"window": w, "used": used[w]["used"], "limit": lim[w],
                                "remaining": None if lim[w] is None else max(0, lim[w] - used[w]["used"]),
                                "resets_at": used[w]["resets_at"], "timezone": "UTC"})
            if windows:
                features.append({"feature": key, "label": meta["label"], "windows": windows})
        body = {"features": features}
        if not self.configured_only:
            active = QRCode.objects.filter(owner=user, code_mode="dynamic", status="active").count()
            body["qr_codes"] = {"active_dynamic": active, "active_dynamic_limit": get_limit(user, "qr.dynamic.active_limit")}
        return Response(body)


class UsageLimitsView(UsageView):
    configured_only = True
