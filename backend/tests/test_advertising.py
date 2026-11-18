import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.utils import timezone as djtz
from rest_framework.test import APIClient

from apps.advertising.constants import ADMOB_TEST_APP_ID, ADMOB_TEST_UNITS, AD_MANAGER_TEST_UNIT, FORBIDDEN_SURFACES
from apps.advertising.models import AdPlacement, AdPreference, AdProvider, AdProviderReport
from apps.audit.models import AuditLog
from apps.billing.models import EntitlementOverride, FeatureDefinition, Subscription
from apps.core.models import AppConfiguration
from tests.conftest import PASSWORD, make_plan, make_qr

pytestmark = pytest.mark.django_db
S = Subscription.Status
User = get_user_model()
ELIGIBLE = "/api/v1/advertising/eligible-placements/"


def set_cfg(key, value):
    AppConfiguration.objects.update_or_create(key=key, defaults={"value": value})


@pytest.fixture
def ads_on(db):
    """Ads switched on by the administrator, providers and all seeded placements enabled, test mode on (the safe default)."""
    set_cfg("ads_enabled", True)
    AdProvider.objects.update(enabled=True)
    AdPlacement.objects.update(enabled=True)


def ask(client, platform="android", surface="dashboard", **extra):
    params = {"platform": platform, **({"surface": surface} if surface else {}), **extra}
    return client.get(ELIGIBLE, params)


def sub_for(user, plan, status=S.ACTIVE, **kw):
    now = djtz.now()
    d = dict(plan=plan, status=status, current_period_start=now - timedelta(days=5), current_period_end=now + timedelta(days=25))
    if status == S.TRIALING:
        d["trial_ends_at"] = now + timedelta(days=5)
        d["current_period_end"] = now + timedelta(days=5)
    d.update(kw)
    return Subscription.objects.create(user=user, **d)


def override(user, **kw):
    base = dict(user=user, kind="feature", note="support case 55")
    base.update(kw)
    return EntitlementOverride.objects.create(**base)


# ---- defaults / seeding -------------------------------------------------------------------------------------------------
def test_defaults_are_seeded_safely():
    vals = {c.key: c.value for c in AppConfiguration.objects.filter(key__startswith="ads_")}
    assert vals["ads_enabled"] is False and vals["ads_test_mode"] is True and vals["ads_non_personalized_default"] is True
    assert vals["ads_enabled_for_free_users"] is True and vals["ads_enabled_for_trial_users"] is True
    assert vals["ads_enabled_for_paid_users"] is False and vals["ads_enabled_for_enterprise_users"] is False
    assert vals["ads_remove_with_premium"] is True and vals["ads_web_enabled"] is True and vals["ads_android_enabled"] is True
    assert not AdProvider.objects.filter(enabled=True).exists()
    assert {p.key for p in AdProvider.objects.all()} == {"google_adsense", "google_ad_manager", "admob"}
    placements = AdPlacement.objects.all()
    assert placements.count() == 8 and not placements.filter(enabled=True).exists() and not placements.exclude(ad_unit_identifier="").exists()
    assert not AppConfiguration.objects.filter(key__startswith="ads_", is_public=True).exists()


def test_nothing_is_served_until_the_administrator_switches_ads_on(api, auth_client):
    for c in (api, auth_client):
        r = ask(c)
        assert r.status_code == 200 and r.data["eligible"] is False and r.data["reason"] == "ads_disabled" and r.data["placements"] == []


# ---- public config -----------------------------------------------------------------------------------------------------------
def test_public_config_is_safe_and_secret_free(api, ads_on):
    AdProvider.objects.filter(key="admob").update(config={"app_id": "ca-app-pub-1111~2222", "secret": "TOPSECRET", "api_key": "K", "publisher_id": "pub-1"})
    r = api.get("/api/v1/advertising/config/")
    assert r.status_code == 200 and r.data["ads_enabled"] and r.data["platforms"] == {"web": True, "android": True}
    admob = next(p for p in r.data["providers"] if p["key"] == "admob")
    assert admob["config"] == {"app_id": "ca-app-pub-1111~2222", "publisher_id": "pub-1"}
    blob = json.dumps(r.data)
    assert "TOPSECRET" not in blob and "api_key" not in blob and r.data["label"] == "Advertisement"
    assert "scanner" in r.data["ads_never_shown_on"] and "verification" in r.data["ads_never_shown_on"]
    assert set(r.data["allowed_surfaces"]) == {"dashboard", "qr_library", "analytics", "resources", "account"}


def test_config_hides_providers_when_ads_are_off(api, db):
    r = api.get("/api/v1/advertising/config/")
    assert r.data["ads_enabled"] is False and r.data["providers"] == [] and r.data["platforms"] == {"web": False, "android": False}
    AdProvider.objects.update(enabled=True)
    assert api.get("/api/v1/advertising/config/").data["providers"] == []          # master switch still off


# ---- scenarios 11 and 15: free users see ads, ad-free plans do not -----------------------------------------------------------------
def test_scenario_11_free_android_user_sees_a_banner_and_an_ad_free_paid_user_does_not(auth_client, other_client, other_user, plans, ads_on):
    set_cfg("ads_enabled_for_paid_users", True)
    r = ask(auth_client)
    assert r.data["eligible"] and r.data["user_category"] == "free" and r.data["reason"] == "ok"
    p = next(x for x in r.data["placements"] if x["key"] == "android.dashboard.banner")
    assert p["format"] == "banner" and p["provider"] == "admob" and p["ad_unit_id"] == ADMOB_TEST_UNITS["banner"]
    assert p["label"] == "Advertisement" and p["sponsored"] is True and r.data["test_mode"] is True
    sub_for(other_user, plans.pro)                                                   # Pro includes ads.remove
    r2 = ask(other_client)
    assert r2.data["eligible"] is False and r2.data["reason"] == "ad_free_entitlement" and r2.data["user_category"] == "paid" and r2.data["placements"] == []


def test_scenario_15_free_web_user_sees_a_labelled_ad_and_ad_free_does_not(auth_client, other_client, other_user, plans, ads_on):
    set_cfg("ads_enabled_for_paid_users", True)
    r = ask(auth_client, "web", "dashboard")
    p = r.data["placements"][0]
    assert r.data["eligible"] and p["key"] == "web.dashboard.banner" and p["provider"] == "google_adsense" and p["label"] == "Advertisement"
    assert p["adtest"] is True                                                       # AdSense has no test units: the client sets adtest=on
    sub_for(other_user, plans.pro)
    assert ask(other_client, "web", "dashboard").data["reason"] == "ad_free_entitlement"


def test_paid_users_without_ad_removal_see_ads_when_the_administrator_allows(auth_client, user, plans, ads_on):
    sub_for(user, plans.starter)                                                     # Starter has no ads.remove
    assert ask(auth_client).data["reason"] == "category_disabled"                    # paid ads OFF by default
    set_cfg("ads_enabled_for_paid_users", True)
    r = ask(auth_client)
    assert r.data["eligible"] and r.data["user_category"] == "paid"


def test_web_and_android_get_the_same_decision(auth_client, user, plans, ads_on):
    for state in ("free", "paid", "off"):
        if state == "paid":
            sub_for(user, plans.pro)
            set_cfg("ads_enabled_for_paid_users", True)
        if state == "off":
            set_cfg("ads_enabled", False)
        w, a = ask(auth_client, "web", "dashboard").data, ask(auth_client, "android", "dashboard").data
        assert (w["eligible"], w["reason"], w["user_category"]) == (a["eligible"], a["reason"], a["user_category"]), state


# ---- the switches (scenario 23) -------------------------------------------------------------------------------------------------
def test_scenario_23_every_switch_works_independently_without_a_deployment(auth_client, ads_on):
    assert ask(auth_client, "web").data["eligible"] and ask(auth_client, "android").data["eligible"]
    set_cfg("ads_web_enabled", False)
    assert ask(auth_client, "web").data["reason"] == "platform_disabled" and ask(auth_client, "android").data["eligible"]
    set_cfg("ads_web_enabled", True)
    set_cfg("ads_android_enabled", False)
    assert ask(auth_client, "android").data["reason"] == "platform_disabled" and ask(auth_client, "web").data["eligible"]
    set_cfg("ads_android_enabled", True)
    set_cfg("ads_enabled_for_free_users", False)
    assert ask(auth_client, "web").data["reason"] == "category_disabled" and ask(auth_client, "android").data["reason"] == "category_disabled"
    set_cfg("ads_enabled_for_free_users", True)
    set_cfg("ads_enabled", False)
    assert ask(auth_client, "web").data["reason"] == "ads_disabled"


@pytest.mark.parametrize("category,flag", [("free", "ads_enabled_for_free_users"), ("trial", "ads_enabled_for_trial_users"),
                                           ("paid", "ads_enabled_for_paid_users"), ("enterprise", "ads_enabled_for_enterprise_users")])
def test_each_account_category_has_its_own_switch(auth_client, user, plans, ads_on, category, flag):
    ent = make_plan("enterprise", "Enterprise", ngn="9000", order=9)                # no ads.remove: only the switch decides
    plan = {"trial": plans.starter, "paid": plans.starter, "enterprise": ent, "free": None}[category]
    if plan is not None:
        sub_for(user, plan, status=S.TRIALING if category == "trial" else S.ACTIVE)
    for other in ("ads_enabled_for_free_users", "ads_enabled_for_trial_users", "ads_enabled_for_paid_users", "ads_enabled_for_enterprise_users"):
        set_cfg(other, False)
    assert ask(auth_client).data["reason"] == "category_disabled" and ask(auth_client).data["user_category"] == category
    set_cfg(flag, True)
    r = ask(auth_client)
    assert r.data["eligible"] and r.data["user_category"] == category


def test_anonymous_visitors_follow_the_free_switch_and_the_placement_opt_in(api, ads_on):
    assert ask(api).data["reason"] == "no_placements"                                # no placement allows anonymous by default
    AdPlacement.objects.filter(key="android.dashboard.banner").update(allow_anonymous=True)
    r = ask(api)
    assert r.data["eligible"] and r.data["user_category"] == "anonymous" and [p["key"] for p in r.data["placements"]] == ["android.dashboard.banner"]
    set_cfg("ads_enabled_for_free_users", False)
    assert ask(api).data["reason"] == "category_disabled"


# ---- scenario 16: trials ------------------------------------------------------------------------------------------------------------
def test_scenario_16_trial_users_see_ads_even_though_the_trial_plan_includes_ad_removal(auth_client, user, plans, ads_on):
    sub_for(user, plans.pro, status=S.TRIALING)                                     # Pro includes ads.remove; trials unlock Pro features
    r = ask(auth_client)
    assert r.data["eligible"] and r.data["user_category"] == "trial" and r.data["placements"]
    from apps.core.entitlements import feature_enabled
    assert feature_enabled(user, "ads.remove") is True                              # the entitlement exists, but does not remove ads in a trial


def test_trial_advertising_is_one_switch_away_from_off(auth_client, user, plans, ads_on):
    sub_for(user, plans.pro, status=S.TRIALING)
    set_cfg("ads_enabled_for_trial_users", False)
    assert ask(auth_client).data["reason"] == "category_disabled"
    set_cfg("ads_enabled_for_trial_users", True)
    assert ask(auth_client).data["eligible"]


def test_an_explicit_admin_grant_of_ad_removal_does_apply_to_trial_users(auth_client, user, plans, ads_on):
    sub_for(user, plans.pro, status=S.TRIALING)
    o = override(user, feature=FeatureDefinition.objects.get(key="ads.remove"))
    assert ask(auth_client).data["reason"] == "ad_free_entitlement"
    EntitlementOverride.objects.filter(pk=o.pk).update(revoked_at=djtz.now())
    assert ask(auth_client).data["eligible"]


def test_temporary_premium_access_counts_as_a_trial_for_ads(auth_client, user, plans, ads_on):
    override(user, kind="plan_trial", plan=plans.pro, expires_at=djtz.now() + timedelta(days=3))
    r = ask(auth_client)
    assert r.data["user_category"] == "trial" and r.data["eligible"]


def test_plan_derived_ad_removal_can_be_switched_off_but_explicit_grants_still_work(auth_client, user, plans, ads_on):
    set_cfg("ads_enabled_for_paid_users", True)
    sub_for(user, plans.pro)
    assert ask(auth_client).data["reason"] == "ad_free_entitlement"
    set_cfg("ads_remove_with_premium", False)
    assert ask(auth_client).data["eligible"]                                         # plan no longer removes ads
    override(user, kind="promotion", feature=FeatureDefinition.objects.get(key="ads.remove"))
    assert ask(auth_client).data["reason"] == "ad_free_entitlement"


def test_ad_free_status_follows_the_subscription_in_real_time(auth_client, user, plans, ads_on):
    set_cfg("ads_enabled_for_paid_users", True)
    s = sub_for(user, plans.pro)
    assert ask(auth_client).data["reason"] == "ad_free_entitlement"
    Subscription.objects.filter(pk=s.pk).update(current_period_end=djtz.now() - timedelta(days=30))        # lapsed beyond grace
    r = ask(auth_client)
    assert r.data["eligible"] and r.data["user_category"] == "free"


def test_enterprise_plans_are_identified_by_an_admin_editable_list(auth_client, user, plans, ads_on):
    big = make_plan("whale", "Whale", ngn="50000", order=9)
    sub_for(user, big)
    set_cfg("ads_enabled_for_paid_users", True)
    assert ask(auth_client).data["user_category"] == "paid"
    set_cfg("ads_enterprise_plan_slugs", ["whale"])
    assert ask(auth_client).data["user_category"] == "enterprise" and ask(auth_client).data["reason"] == "category_disabled"


# ---- scenario 12: security-critical screens are always ad-free ----------------------------------------------------------------------------
@pytest.mark.parametrize("surface", sorted(FORBIDDEN_SURFACES))
@pytest.mark.parametrize("platform", ["web", "android"])
def test_scenario_12_forbidden_screens_never_get_ads(api, auth_client, ads_on, surface, platform):
    AdPlacement.objects.update(allow_anonymous=True)
    for client in (api, auth_client):
        r = ask(client, platform, surface)
        assert r.status_code == 200 and r.data["eligible"] is False and r.data["reason"] == "surface_restricted" and r.data["placements"] == []


def test_no_setting_can_unlock_a_forbidden_screen(auth_client, ads_on):
    for key in ("ads_enabled_for_free_users", "ads_enabled_for_trial_users", "ads_enabled_for_paid_users", "ads_enabled_for_enterprise_users"):
        set_cfg(key, True)
    set_cfg("ads_test_mode", False)
    for surface in ("scanner", "verification", "security_warning", "qr_generation"):
        assert ask(auth_client, "web", surface).data["reason"] == "surface_restricted"


def test_a_placement_on_a_forbidden_screen_cannot_be_saved(db):
    p = AdPlacement.objects.get(key="android.dashboard.banner")
    p.surface = "verification"
    with pytest.raises(ValidationError) as e:
        p.save()
    assert "never allowed" in str(e.value)
    with pytest.raises(ValidationError):
        AdPlacement.objects.create(key="x.y", display_name="X", platform="android", surface="scanner", format="banner", provider=p.provider)
    p.surface = "nonsense"
    with pytest.raises(ValidationError):
        p.save()


def test_even_a_placement_forced_into_the_database_is_not_served(auth_client, ads_on):
    AdPlacement.objects.filter(key="android.dashboard.banner").update(surface="verification")        # bypasses validation on purpose
    r = ask(auth_client, "android", None)                                                          # client asks for everything
    assert "android.dashboard.banner" not in {p["key"] for p in r.data["placements"]}
    assert all(p["surface"] in {"dashboard", "qr_library", "analytics", "resources", "account"} for p in r.data["placements"])


def test_unknown_screens_and_platforms_are_refused(auth_client, ads_on):
    assert ask(auth_client, surface="mystery").data["reason"] == "unknown_surface"
    assert auth_client.get(ELIGIBLE).status_code == 400 and auth_client.get(ELIGIBLE, {"platform": "ios"}).status_code == 400


def test_security_flows_never_contain_ads(api, auth_client, ads_on, senv):
    qr = make_qr(auth_client).data
    senv.publish("shop.com")
    bodies = [api.get(f"/api/v1/scanner/verify/{qr['public_token']}/").data, api.post("/api/v1/scanner/analyze/", {"content": "https://shop.com/"}, format="json").data,
              api.post("/api/v1/security/analyze/", {"url": "https://shop.com/"}, format="json").data,
              api.post("/api/v1/domains/analyze/", {"value": "shop.com"}, format="json").data]
    for body in bodies:
        blob = json.dumps(body, default=str).lower()
        assert "placement" not in blob and "ad_unit" not in blob and "sponsored" not in blob


# ---- placements: rules, formats, providers ----------------------------------------------------------------------------------------------
def test_only_enabled_placements_of_enabled_providers_are_served(auth_client, ads_on):
    AdPlacement.objects.filter(key="android.dashboard.banner").update(enabled=False)
    assert "android.dashboard.banner" not in {p["key"] for p in ask(auth_client, "android", None).data["placements"]}
    AdProvider.objects.filter(key="admob").update(enabled=False)
    assert ask(auth_client, "android", None).data["reason"] == "no_placements"


def test_surface_filter(auth_client, ads_on):
    keys = lambda s: {p["key"] for p in ask(auth_client, "android", s).data["placements"]}
    assert keys("dashboard") == {"android.dashboard.banner"} and keys("qr_library") == {"android.qr_library.banner"}
    assert keys(None) >= {"android.dashboard.banner", "android.qr_library.banner", "android.analytics.banner", "android.resources.native"}


def test_per_placement_plan_rules(auth_client, user, plans, ads_on):
    set_cfg("ads_enabled_for_paid_users", True)
    set_cfg("ads_remove_with_premium", False)
    AdPlacement.objects.filter(key="android.dashboard.banner").update(eligible_plan_rules={"categories": ["paid"]})
    assert ask(auth_client).data["reason"] == "no_placements"                         # a free user is outside the placement's categories
    sub_for(user, plans.starter)
    assert ask(auth_client).data["eligible"]
    AdPlacement.objects.filter(key="android.dashboard.banner").update(eligible_plan_rules={"exclude_plans": ["starter"]})
    assert ask(auth_client).data["reason"] == "no_placements"
    AdPlacement.objects.filter(key="android.dashboard.banner").update(eligible_plan_rules={"include_plans": ["pro"]})
    assert ask(auth_client).data["reason"] == "no_placements"
    AdPlacement.objects.filter(key="android.dashboard.banner").update(eligible_plan_rules={"include_plans": ["starter"]})
    assert ask(auth_client).data["eligible"]


def test_rewarded_placements_are_not_served_as_standard_ads(auth_client, ads_on):
    AdPlacement.objects.filter(key="android.dashboard.banner").update(format="rewarded")
    assert ask(auth_client).data["reason"] == "no_placements"


def test_frequency_hints_merge_global_and_placement_settings(auth_client, ads_on):
    set_cfg("ads_frequency_limits", {"max_per_session": 5, "min_seconds_between": 90})
    AdPlacement.objects.filter(key="android.dashboard.banner").update(frequency_configuration={"max_per_session": 2})
    p = ask(auth_client).data["placements"][0]
    assert p["frequency"] == {"max_per_session": 2, "min_seconds_between": 90}


@pytest.mark.parametrize("kw,field", [
    (dict(provider_key="admob", platform="web"), "platform"), (dict(provider_key="google_adsense", platform="android"), "platform"),
    (dict(provider_key="google_adsense", platform="web", format="banner"), "format"), (dict(provider_key="admob", platform="android", format="display"), "format"),
    (dict(ad_unit_identifier="ca-app-pub-3940256099942544/6300978111"), "ad_unit_identifier"), (dict(ad_unit_identifier="/6499/example/banner"), "ad_unit_identifier"),
    (dict(frequency_configuration={"max_per_session": -1}), "frequency_configuration"), (dict(frequency_configuration={"max_per_session": "3"}), "frequency_configuration"),
    (dict(eligible_plan_rules={"categories": ["vip"]}), "eligible_plan_rules"),
])
def test_invalid_placements_are_rejected(db, kw, field):
    kw = dict(kw)
    prov = AdProvider.objects.get(key=kw.pop("provider_key", "admob"))
    base = dict(key="t.test", display_name="T", platform="android", surface="dashboard", format="banner", provider=prov)
    base.update(kw)
    with pytest.raises(ValidationError) as e:
        AdPlacement.objects.create(**base)
    assert field in e.value.message_dict


# ---- test mode vs production ----------------------------------------------------------------------------------------------------------------
def test_test_mode_serves_official_test_units_and_never_the_stored_production_ids(auth_client, ads_on):
    AdPlacement.objects.filter(key="android.dashboard.banner").update(ad_unit_identifier="ca-app-pub-1234567890123456/1111111111")
    AdProvider.objects.filter(key="admob").update(config={"app_id": "ca-app-pub-1234567890123456~9999999999"})
    r = ask(auth_client)
    p = r.data["placements"][0]
    assert p["ad_unit_id"] == ADMOB_TEST_UNITS["banner"] and p["provider_config"]["app_id"] == ADMOB_TEST_APP_ID
    assert "1234567890123456" not in json.dumps(r.data)
    native = ask(auth_client, "android", "resources").data["placements"][0]
    assert native["format"] == "native" and native["ad_unit_id"] == ADMOB_TEST_UNITS["native"]
    web = ask(auth_client, "web", "resources").data["placements"][0]
    assert web["provider"] == "google_ad_manager" and web["ad_unit_id"] == AD_MANAGER_TEST_UNIT


def test_production_mode_serves_only_real_configured_ids(auth_client, ads_on):
    set_cfg("ads_test_mode", False)
    AdProvider.objects.filter(key="admob").update(config={"app_id": "ca-app-pub-1234567890123456~9999999999"})
    r = ask(auth_client)
    assert r.data["eligible"] is False and r.data["reason"] == "no_placements" and r.data["test_mode"] is False       # no ids configured yet
    AdPlacement.objects.filter(key="android.dashboard.banner").update(ad_unit_identifier="ca-app-pub-1234567890123456/1111111111")
    r = ask(auth_client)
    p = r.data["placements"][0]
    assert p["ad_unit_id"] == "ca-app-pub-1234567890123456/1111111111" and p["provider_config"]["app_id"] == "ca-app-pub-1234567890123456~9999999999"
    assert ADMOB_TEST_UNITS["banner"] not in json.dumps(r.data) and ADMOB_TEST_APP_ID not in json.dumps(r.data)


def test_a_google_test_id_forced_into_the_database_is_never_served_in_production(auth_client, ads_on):
    set_cfg("ads_test_mode", False)
    AdPlacement.objects.filter(key="android.dashboard.banner").update(ad_unit_identifier=ADMOB_TEST_UNITS["banner"])      # bypasses validation
    assert ask(auth_client).data["reason"] == "no_placements"


def test_adsense_uses_the_stored_slot_and_a_test_flag(auth_client, ads_on):
    AdPlacement.objects.filter(key="web.dashboard.banner").update(ad_unit_identifier="1234567890")
    p = ask(auth_client, "web", "dashboard").data["placements"][0]
    assert p["ad_unit_id"] == "1234567890" and p["adtest"] is True
    set_cfg("ads_test_mode", False)
    p = ask(auth_client, "web", "dashboard").data["placements"][0]
    assert p["ad_unit_id"] == "1234567890" and p["adtest"] is False


# ---- consent & personalisation -----------------------------------------------------------------------------------------------------------------
def test_non_personalised_ads_are_the_privacy_first_default(api, auth_client, ads_on):
    for c in (api, auth_client):
        r = ask(c)
        assert r.data["request_non_personalized_ads"] is True and "consent platform" in r.data["consent_note"]


def test_the_users_own_choice_can_only_make_ads_less_personalised(auth_client, ads_on):
    assert auth_client.get("/api/v1/advertising/preferences/").data["personalized_ads"] is None
    set_cfg("ads_non_personalized_default", False)
    assert ask(auth_client).data["request_non_personalized_ads"] is False
    assert auth_client.patch("/api/v1/advertising/preferences/", {"personalized_ads": False}, format="json").data["personalized_ads"] is False
    assert ask(auth_client).data["request_non_personalized_ads"] is True               # the user opted out of personalisation
    auth_client.patch("/api/v1/advertising/preferences/", {"personalized_ads": True}, format="json")
    assert ask(auth_client).data["request_non_personalized_ads"] is False
    set_cfg("ads_non_personalized_default", True)
    assert ask(auth_client).data["request_non_personalized_ads"] is True               # the privacy-first default wins over the user's "yes"


def test_preferences_are_private_and_validated(api, auth_client, other_client, user):
    assert api.get("/api/v1/advertising/preferences/").status_code == 401
    auth_client.patch("/api/v1/advertising/preferences/", {"personalized_ads": True, "user": 5}, format="json")
    assert AdPreference.objects.get(user=user).personalized_ads is True
    assert other_client.get("/api/v1/advertising/preferences/").data["personalized_ads"] is None
    assert auth_client.patch("/api/v1/advertising/preferences/", {"personalized_ads": "maybe"}, format="json").status_code == 400
    assert auth_client.put("/api/v1/advertising/preferences/", {}, format="json").status_code == 405


# ---- administration ------------------------------------------------------------------------------------------------------------------------------
def staff(email, perms=(), superuser=False):
    u = User.objects.create_user(email, PASSWORD, is_staff=True, is_superuser=superuser, email_verified=True)
    for code in perms:
        u.user_permissions.add(Permission.objects.get(codename=code))
    c = APIClient()
    tok = c.post("/api/v1/auth/login/", {"email": email, "password": PASSWORD}).data["access"]
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {tok}")
    c.user = u
    return c


@pytest.mark.parametrize("path", ["/api/v1/admin/advertising/overview/", "/api/v1/admin/advertising/simulate/?platform=web"])
def test_admin_endpoints_need_the_manage_ads_permission(api, auth_client, path):
    assert api.get(path).status_code == 401 and auth_client.get(path).status_code == 403
    assert staff("a@example.com").get(path).status_code == 403
    assert staff("b@example.com", ["manage_pricing", "view_payments", "grant_entitlements"]).get(path).status_code == 403      # billing roles are not ad roles
    assert staff("c@example.com", ["manage_ads"]).get(path).status_code == 200
    assert staff("root@example.com", superuser=True).get(path).status_code == 200


def test_overview_warns_about_test_mode_and_misconfiguration(db):
    admin = staff("ads@example.com", ["manage_ads"])
    d = admin.get("/api/v1/admin/advertising/overview/").data
    assert any("master switch" in w for w in d["warnings"]) and any("Test mode is ON" in w for w in d["warnings"])
    assert d["switches"]["ads_enabled"] is False and d["placements"] == {"total": 8, "enabled": 0}
    set_cfg("ads_enabled", True)
    AdPlacement.objects.filter(key="android.dashboard.banner").update(enabled=True)
    AdPlacement.objects.filter(key="web.dashboard.banner").update(enabled=True)
    set_cfg("ads_test_mode", False)
    d = admin.get("/api/v1/admin/advertising/overview/").data
    probs = {(p["placement"], p["problem"]) for p in d["misconfigured_placements"]}
    assert ("android.dashboard.banner", "production mode needs a real ad unit id") in probs
    assert ("android.dashboard.banner", "its provider is disabled") in probs and not any("Test mode is ON" in w for w in d["warnings"])
    AdPlacement.objects.filter(key="android.dashboard.banner").update(ad_unit_identifier=ADMOB_TEST_UNITS["banner"])
    assert any("real ad unit id" in p["problem"] for p in admin.get("/api/v1/admin/advertising/overview/").data["misconfigured_placements"])


def test_reporting_is_unavailable_rather_than_invented_and_otherwise_exactly_what_was_reported(db):
    admin = staff("ads@example.com", ["manage_ads"])
    d = admin.get("/api/v1/admin/advertising/overview/").data
    assert d["reporting"]["available"] is False and "never estimates or invents" in d["reporting"]["reason"] and "impressions" not in d["reporting"]
    prov = AdProvider.objects.get(key="admob")
    today = djtz.now().date()
    AdProviderReport.objects.create(provider=prov, platform="android", date=today, requests=1000, impressions=800, estimated_revenue="1.2500", currency="USD", source="import")
    AdProviderReport.objects.create(provider=prov, platform="android", date=today - timedelta(days=1), requests=500, impressions=None)
    AdProviderReport.objects.create(provider=prov, platform="android", date=today - timedelta(days=90), requests=999999, impressions=999999)       # outside window
    r = admin.get("/api/v1/admin/advertising/overview/").data["reporting"]
    assert r["available"] and r["requests"] == 1500 and r["impressions"] == 800 and r["estimated_revenue"] == "1.2500"
    assert r["days_with_data"] == 2 and r["currencies"] == ["USD"] and "as reported by the ad provider" in r["note"]


def test_simulator_uses_the_real_decision_engine(user, plans, ads_on):
    admin = staff("ads@example.com", ["manage_ads"])
    sub_for(user, plans.pro)
    set_cfg("ads_enabled_for_paid_users", True)
    q = lambda who, **kw: admin.get("/api/v1/admin/advertising/simulate/", {"user": who, "platform": "android", "surface": "dashboard", **kw})
    assert q(user.email).data["reason"] == "ad_free_entitlement" and q(str(user.pk)).data["user_category"] == "paid"
    assert q("anonymous").data["reason"] == "no_placements"
    assert q(user.email, surface="verification").data["reason"] == "surface_restricted"
    assert q("ghost@example.com").status_code == 404 and q("not-a-uuid").status_code == 404
    assert admin.get("/api/v1/admin/advertising/simulate/?platform=tv").status_code == 400


# ---- Django admin: roles and audit ---------------------------------------------------------------------------------------------------------------
def grant(user, *codenames):
    for c in codenames:
        user.user_permissions.add(Permission.objects.get(codename=c))


def test_advertising_settings_need_the_ads_permission_and_pricing_settings_do_not_accept_it(client, db):
    u = User.objects.create_user("ops@example.com", PASSWORD, is_staff=True)
    grant(u, "view_appconfiguration", "change_appconfiguration")
    client.force_login(u)
    row = AppConfiguration.objects.get(key="ads_enabled")
    url = f"/admin/core/appconfiguration/{row.pk}/change/"
    form = {"key": "ads_enabled", "value": "true", "description": "", "is_public": ""}
    assert client.post(url, form).status_code == 403 and AppConfiguration.objects.get(key="ads_enabled").value is False
    grant(u, "manage_pricing")                                                       # the billing role is not the advertising role
    client.force_login(User.objects.get(pk=u.pk))
    assert client.post(url, form).status_code == 403
    grant(u, "manage_ads")
    client.force_login(User.objects.get(pk=u.pk))
    assert client.post(url, form).status_code == 302 and AppConfiguration.objects.get(key="ads_enabled").value is True
    assert AuditLog.objects.filter(action="config.changed", actor=u).exists()
    pricing_row = AppConfiguration.objects.get(key="pricing_enabled")
    u2 = User.objects.create_user("ops2@example.com", PASSWORD, is_staff=True)
    grant(u2, "view_appconfiguration", "change_appconfiguration", "manage_ads")
    client.force_login(u2)
    assert client.post(f"/admin/core/appconfiguration/{pricing_row.pk}/change/", {"key": "pricing_enabled", "value": "true", "description": "", "is_public": "on"}).status_code == 403


def test_placement_admin_needs_the_ads_permission_and_validates_forms(client, db):
    p = AdPlacement.objects.get(key="android.dashboard.banner")
    url = f"/admin/advertising/adplacement/{p.pk}/change/"
    u = User.objects.create_user("ops@example.com", PASSWORD, is_staff=True)
    grant(u, "view_adplacement", "change_adplacement")
    client.force_login(u)
    assert b'name="_save"' not in client.get(url).content and client.post(url, {"display_name": "Hacked"}).status_code == 403
    grant(u, "manage_ads")
    client.force_login(User.objects.get(pk=u.pk))
    assert b'name="_save"' in client.get(url).content
    form = dict(key=p.key, display_name="Android dashboard banner", platform="android", surface="verification", format="banner", provider=p.provider.pk,
                enabled="on", ad_unit_identifier="", eligible_plan_rules="{}", frequency_configuration="{}", display_rules="{}")
    bad = client.post(url, form)
    assert bad.status_code == 200 and b"never allowed" in bad.content and AdPlacement.objects.get(pk=p.pk).surface == "dashboard"
    ok = client.post(url, {**form, "surface": "dashboard", "ad_unit_identifier": "ca-app-pub-1234567890123456/1111111111"})
    assert ok.status_code == 302
    assert AdPlacement.objects.get(pk=p.pk).ad_unit_identifier.endswith("1111111111") and AuditLog.objects.filter(action="advertising.adplacement_saved").exists()
    test_id = client.post(url, {**form, "surface": "dashboard", "ad_unit_identifier": ADMOB_TEST_UNITS["banner"]})
    assert test_id.status_code == 200 and b"must never be stored" in test_id.content


def test_admin_pages_load(client, db):
    su = User.objects.create_superuser("root@example.com", PASSWORD)
    client.force_login(su)
    for m in ("adprovider", "adplacement", "adproviderreport", "adpreference"):
        assert client.get(f"/admin/advertising/{m}/").status_code == 200, m


def test_the_decision_engine_itself_refuses_unknown_platforms(ads_on):
    from apps.advertising.decision import decide
    for platform in ("ios", "tv", "", "WEB"):
        d = decide(None, platform, "dashboard")
        assert d.eligible is False and d.reason == "unknown_platform" and d.placements == []
