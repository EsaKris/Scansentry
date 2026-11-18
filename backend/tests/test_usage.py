from datetime import datetime, timezone

import pytest

from apps.analytics import usage
from apps.analytics.models import UsageCounter
from apps.core.entitlements import FeatureLimitReached
from apps.core.models import AppConfiguration
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db
URL = "/api/v1/domains/analyze/"
T = datetime(2026, 11, 11, 15, 30, tzinfo=timezone.utc)      # a Wednesday


def test_window_bounds():
    assert usage.window_bounds("day", T) == (datetime(2026, 11, 11, tzinfo=timezone.utc), datetime(2026, 11, 12, tzinfo=timezone.utc))
    assert usage.window_bounds("week", T) == (datetime(2026, 11, 9, tzinfo=timezone.utc), datetime(2026, 11, 16, tzinfo=timezone.utc))
    assert usage.window_bounds("month", T) == (datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 12, 1, tzinfo=timezone.utc))
    dec = datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc)
    assert usage.window_bounds("month", dec)[1] == datetime(2027, 1, 1, tzinfo=timezone.utc)
    assert usage.window_bounds("week", datetime(2026, 11, 9, tzinfo=timezone.utc))[0] == datetime(2026, 11, 9, tzinfo=timezone.utc)   # Monday
    assert usage.window_bounds("week", datetime(2026, 11, 15, 23, tzinfo=timezone.utc))[0] == datetime(2026, 11, 9, tzinfo=timezone.utc)  # Sunday


def test_consume_increments_all_three_windows_atomically(user):
    usage.consume(user, "domain.lookups", now=T)
    usage.consume(user, "domain.lookups", amount=2, now=T)
    got = usage.get_usage(user, "domain.lookups", T)
    assert [got[w]["used"] for w in ("day", "week", "month")] == [3, 3, 3]
    assert UsageCounter.objects.filter(user=user).count() == 3
    assert usage.get_usage(user, "domain.lookups", datetime(2026, 11, 12, 1, tzinfo=timezone.utc))["day"]["used"] == 0   # new day
    assert usage.get_usage(user, "domain.lookups", datetime(2026, 11, 12, 1, tzinfo=timezone.utc))["week"]["used"] == 3


def test_limits_are_enforced_per_window_with_reset_time_and_leave_counters_untouched(user):
    limits = {"day": 2, "week": 3, "month": None}
    usage.consume(user, "domain.lookups", limits=limits, now=T)
    usage.consume(user, "domain.lookups", limits=limits, now=T)
    with pytest.raises(FeatureLimitReached) as e:
        usage.consume(user, "domain.lookups", limits=limits, now=T)
    assert "daily limit of 2" in str(e.value.detail) and "2026-11-12T00:00:00+00:00" in str(e.value.detail)
    assert usage.get_usage(user, "domain.lookups", T)["day"]["used"] == 2           # the refused call did not count
    next_day = datetime(2026, 11, 12, 9, tzinfo=timezone.utc)
    usage.consume(user, "domain.lookups", limits=limits, now=next_day)               # weekly 3rd
    with pytest.raises(FeatureLimitReached) as e:
        usage.consume(user, "domain.lookups", limits=limits, now=next_day)           # weekly limit hit while daily is not
    assert "weekly limit of 3" in str(e.value.detail) and "2026-11-16" in str(e.value.detail)
    assert [usage.get_usage(user, "domain.lookups", next_day)[w]["used"] for w in ("day", "week", "month")] == [1, 3, 3]


def test_a_multi_amount_request_that_would_overshoot_is_refused_whole(user):
    usage.consume(user, "domain.lookups", limits={"day": 5}, amount=4, now=T)
    with pytest.raises(FeatureLimitReached):
        usage.consume(user, "domain.lookups", limits={"day": 5}, amount=2, now=T)
    assert usage.get_usage(user, "domain.lookups", T)["day"]["used"] == 4


def test_counters_are_per_user_and_per_feature(user, other_user):
    usage.consume(user, "domain.lookups", now=T)
    usage.consume(user, "other.feature", now=T)
    assert usage.get_usage(other_user, "domain.lookups", T)["day"]["used"] == 0
    assert usage.get_usage(user, "domain.lookups", T)["day"]["used"] == 1


def test_limits_come_from_configuration_not_code(user):
    assert usage.limits_for(user, "domain.lookups") == {"day": None, "week": None, "month": None}
    AppConfiguration.objects.create(key="default_entitlements", value={"domain.lookups.daily_limit": 7, "domain.lookups.monthly_limit": 50})
    assert usage.limits_for(user, "domain.lookups") == {"day": 7, "week": None, "month": 50}


# ---- through the API ---------------------------------------------------------------------------------------------
def test_domain_lookups_consume_the_allowance_and_report_the_reset(auth_client, senv):
    senv.publish("shop.com")
    AppConfiguration.objects.create(key="default_entitlements", value={"domain.lookups.daily_limit": 2})
    assert auth_client.post(URL, {"value": "shop.com"}, format="json").status_code == 200
    assert auth_client.post(URL, {"value": "shop.com"}, format="json").status_code == 200          # cached results still count
    r = auth_client.post(URL, {"value": "shop.com"}, format="json")
    assert r.status_code == 403 and r.data["error"]["code"] == "limit_reached" and "resets at" in r.data["error"]["message"]


def test_invalid_input_and_anonymous_checks_do_not_use_the_allowance(api, auth_client, senv):
    senv.publish("shop.com")
    AppConfiguration.objects.create(key="default_entitlements", value={"domain.lookups.daily_limit": 1})
    assert auth_client.post(URL, {"value": "localhost"}, format="json").status_code == 400
    assert auth_client.post(URL, {"value": "127.0.0.1"}, format="json").status_code == 400
    assert api.post(URL, {"value": "shop.com"}, format="json").status_code == 200
    assert UsageCounter.objects.count() == 0
    assert auth_client.post(URL, {"value": "shop.com"}, format="json").status_code == 200
    assert auth_client.post(URL, {"value": "shop.com"}, format="json").status_code == 403


def test_usage_endpoints_show_used_limit_remaining_and_reset(auth_client, senv):
    senv.publish("shop.com")
    AppConfiguration.objects.create(key="default_entitlements", value={
        "domain.lookups.daily_limit": 5, "domain.lookups.monthly_limit": 20, "qr.dynamic.active_limit": 3})
    auth_client.post(URL, {"value": "shop.com"}, format="json")
    make_qr(auth_client)
    full = auth_client.get("/api/v1/usage/overview/").data
    f = full["features"][0]
    assert f["feature"] == "domain.lookups" and [w["window"] for w in f["windows"]] == ["day", "week", "month"]
    day = f["windows"][0]
    assert day["used"] == 1 and day["limit"] == 5 and day["remaining"] == 4 and day["timezone"] == "UTC" and day["resets_at"]
    assert f["windows"][1]["limit"] is None and f["windows"][1]["remaining"] is None
    assert full["qr_codes"] == {"active_dynamic": 1, "active_dynamic_limit": 3}
    lim = auth_client.get("/api/v1/usage/limits/").data
    assert [w["window"] for w in lim["features"][0]["windows"]] == ["day", "month"] and "qr_codes" not in lim


def test_usage_requires_authentication(api):
    assert api.get("/api/v1/usage/overview/").status_code == 401
    assert api.get("/api/v1/usage/limits/").status_code == 401
