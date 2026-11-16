from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.advertising.models import AdProvider
from apps.credits import service
from apps.credits.models import RewardedAdOffer, RewardedAdSession, UsageCreditLedger
from tests.conftest import make_plan, set_config, start_session
from tests.test_advertising import sub_for

pytestmark = pytest.mark.django_db
OFFERS = "/api/v1/credits/rewarded-offers/"
SESSIONS = "/api/v1/credits/rewarded-sessions/"
S = RewardedAdSession.Status


def offers(client, platform="android"):
    return client.get(OFFERS, {"platform": platform})


def create(client, offer, platform="android"):
    return client.post(SESSIONS, {"offer": str(offer.id), "platform": platform}, format="json")


# ---- switches (defaults are OFF) ---------------------------------------------------------------------------------------------
def test_everything_is_off_by_default(auth_client):
    r = offers(auth_client)
    assert r.status_code == 200 and r.data["enabled"] is False and r.data["reason"] == "rewarded_ads_disabled" and r.data["offers"] == []


def test_rewarded_endpoints_need_a_login(api, rewards_on):
    assert api.get(OFFERS, {"platform": "android"}).status_code == 401
    assert api.post(SESSIONS, {}, format="json").status_code == 401
    assert api.get("/api/v1/credits/balance/").status_code == 401


def test_master_and_platform_switches_are_independent(auth_client, rewards_on):
    assert offers(auth_client).data["offers"][0]["available"] is True
    set_config("rewarded_ads_android_enabled", False)
    r = offers(auth_client)
    assert r.data["enabled"] is False and r.data["reason"] == "platform_disabled"
    set_config("rewarded_ads_android_enabled", True)
    set_config("rewarded_ads_enabled", False)
    assert offers(auth_client).data["reason"] == "rewarded_ads_disabled"


def test_a_platform_must_be_given(auth_client, rewards_on):
    assert auth_client.get(OFFERS).status_code == 400
    assert auth_client.get(OFFERS, {"platform": "ios"}).status_code == 400


def test_the_offer_states_the_exact_reward_and_the_terms_before_anything_starts(auth_client, rewards_on):
    o = offers(auth_client).data["offers"][0]
    assert o["reward_amount"] == 5 and o["reward_label"] == "5 ScanSentry Credits" and o["verification"] == "server_side_verification"
    assert "no cash value" in o["terms"] and "never need credits" in o["terms"]
    assert RewardedAdSession.objects.count() == 0                         # listing offers starts nothing


def test_nothing_plays_automatically_a_session_needs_an_explicit_post(auth_client, rewards_on):
    offers(auth_client)
    auth_client.get("/api/v1/credits/balance/")
    assert RewardedAdSession.objects.count() == 0


def test_disabled_offer_is_not_listed_and_cannot_start(auth_client, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(enabled=False)
    assert offers(auth_client).data["offers"] == []
    assert create(auth_client, rewards_on.offer).status_code == 409


def test_offer_schedule_window(auth_client, rewards_on):
    now = timezone.now()
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(starts_at=now + timedelta(days=1))
    assert offers(auth_client).data["offers"][0]["reason"] == "offer_not_active"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(starts_at=None, ends_at=now - timedelta(minutes=1))
    assert offers(auth_client).data["offers"][0]["reason"] == "offer_not_active"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(ends_at=now + timedelta(days=1))
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_a_disabled_provider_makes_the_offer_unavailable(auth_client, rewards_on):
    AdProvider.objects.filter(key="admob").update(enabled=False)
    assert offers(auth_client).data["offers"][0]["reason"] == "provider_disabled"


def test_production_mode_needs_a_real_ad_unit(auth_client, rewards_on):
    set_config("rewarded_ads_test_mode", False)
    assert offers(auth_client).data["offers"][0]["reason"] == "ad_unit_not_configured"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(ad_unit_identifier="ca-app-pub-1111111111111111/2222222222")
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_google_test_ad_units_can_never_be_stored_as_production_ids(rewards_on):
    with pytest.raises(ValidationError):
        RewardedAdOffer.objects.create(name="x", platform="android", provider=rewards_on.provider, reward_amount=1,
                                       ad_unit_identifier="ca-app-pub-3940256099942544/5224354917")


# ---- ordinary ad networks can never be a reward mechanism ---------------------------------------------------------------------
def test_adsense_and_banner_providers_cannot_back_a_rewarded_offer():
    adsense = AdProvider.objects.get(key="google_adsense")
    with pytest.raises(ValidationError) as e:
        RewardedAdOffer.objects.create(name="bad", platform="web", provider=adsense, reward_amount=1)
    assert "provider" in e.value.message_dict


def test_an_offer_must_match_what_its_provider_serves(rewards_on):
    with pytest.raises(ValidationError) as e:
        RewardedAdOffer.objects.create(name="bad", platform="web", provider=rewards_on.provider, reward_amount=1)      # AdMob is Android
    assert "platform" in e.value.message_dict
    with pytest.raises(ValidationError):
        RewardedAdOffer.objects.create(name="bad2", platform="both", provider=rewards_on.provider, reward_amount=1)


def test_offer_validation_rejects_bad_config(rewards_on):
    p = rewards_on.provider
    for kw in ({"eligible_categories": ["vip"]}, {"eligible_plans": "free"}, {"configuration": {"allowed_countries": ["NGA"]}},
               {"ends_at": timezone.now(), "starts_at": timezone.now() + timedelta(days=1)}):
        with pytest.raises(ValidationError):
            RewardedAdOffer.objects.create(name="bad", platform="android", provider=p, reward_amount=1, **kw)


def test_the_ads_endpoint_never_serves_a_rewarded_unit_as_an_ordinary_placement(auth_client, rewards_on):
    set_config("ads_enabled", True)
    r = auth_client.get("/api/v1/advertising/eligible-placements/", {"platform": "android", "surface": "dashboard"})
    assert all(p["format"] != "rewarded" for p in r.data["placements"])
    body = str(offers(auth_client).data)
    assert "eligible_plan_rules" not in body


# ---- eligibility: plans, categories, entitlement, country ------------------------------------------------------------------------
def test_the_rewarded_credits_entitlement_can_switch_a_plan_off(user, auth_client, rewards_on):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key="ads.rewarded_credits"),
                                       enabled=False, note="support case 12")
    assert offers(auth_client).data["offers"][0]["reason"] == "not_entitled"


def test_category_and_plan_eligibility(user, auth_client, rewards_on, pricing):
    plan = make_plan("pro", "Pro", ngn="5000.00", features={"ads.remove": (True, None)})
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(eligible_categories=["free", "trial"])
    assert offers(auth_client).data["offers"][0]["available"] is True               # a free user
    sub_for(user, plan)
    assert offers(auth_client).data["offers"][0]["reason"] == "category_not_eligible"   # now paid
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(eligible_categories=[], eligible_plans=["starter"])
    assert offers(auth_client).data["offers"][0]["reason"] == "plan_not_eligible"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(eligible_plans=["pro"])
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_country_rules_need_a_known_country(auth_client, rewards_on, settings):
    settings.GEO_COUNTRY_HEADER = "CF-IPCountry"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(configuration={"allowed_countries": ["NG", "GH"]})
    assert offers(auth_client).data["offers"][0]["reason"] == "country_unknown"      # unknown country + a restriction: not eligible
    assert auth_client.get(OFFERS, {"platform": "android"}, HTTP_CF_IPCOUNTRY="NG").data["offers"][0]["available"] is True
    assert auth_client.get(OFFERS, {"platform": "android"}, HTTP_CF_IPCOUNTRY="US").data["offers"][0]["reason"] == "country_not_eligible"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(configuration={"blocked_countries": ["US"]})
    assert auth_client.get(OFFERS, {"platform": "android"}, HTTP_CF_IPCOUNTRY="US").data["offers"][0]["reason"] == "country_not_eligible"


def test_no_country_rules_means_no_country_needed(auth_client, rewards_on):
    assert offers(auth_client).data["offers"][0]["available"] is True


# ---- sessions ---------------------------------------------------------------------------------------------------------------------
def test_session_creation_returns_a_single_use_token_and_exact_reward(auth_client, rewards_on, user):
    r = create(auth_client, rewards_on.offer)
    assert r.status_code == 201
    d = r.data
    assert d["status"] == "created" and d["reward_amount"] == 5 and d["credits_granted"] == 0 and len(d["session_token"]) >= 40
    assert d["client"]["ssv"] == {"user_id": str(user.pk), "custom_data": d["session_token"]}      # echoed back in the signed callback
    assert d["client"]["ad_unit_id"] == "ca-app-pub-3940256099942544/5224354917" and d["client"]["test_mode"] is True
    assert "cash value" in d["reminder"]
    assert service.balance_of(user) == 0                                                           # creating a session grants nothing


def test_session_tokens_are_unique_and_unguessable(auth_client, rewards_on):
    tokens = set()
    for _ in range(5):
        tokens.add(create(auth_client, rewards_on.offer).data["session_token"])
    assert len(tokens) == 5 and all(len(t) >= 40 for t in tokens)


def test_the_session_token_is_only_shown_when_created(auth_client, rewards_on):
    d = create(auth_client, rewards_on.offer).data
    again = auth_client.get(f"{SESSIONS}{d['id']}/")
    assert "session_token" not in again.data and d["session_token"] not in str(again.data)


def test_sessions_are_private_to_their_owner(auth_client, other_client, rewards_on):
    d = create(auth_client, rewards_on.offer).data
    assert other_client.get(f"{SESSIONS}{d['id']}/").status_code == 404
    assert other_client.post(f"{SESSIONS}{d['id']}/events/", {"event": "started"}, format="json").status_code == 404
    assert other_client.post(f"{SESSIONS}{d['id']}/complete/").status_code == 404


def test_a_new_session_supersedes_an_unstarted_one(auth_client, rewards_on):
    first = create(auth_client, rewards_on.offer).data
    create(auth_client, rewards_on.offer)
    s = RewardedAdSession.objects.get(pk=first["id"])
    assert s.status == S.CLOSED_WITHOUT_REWARD and s.close_reason == "superseded"


def test_a_started_ad_cannot_be_replaced_while_it_is_running(auth_client, rewards_on):
    start_session(auth_client, rewards_on.offer)
    r = create(auth_client, rewards_on.offer)
    assert r.status_code == 409 and r.data["error"]["code"] == "session_in_progress"


def test_an_expired_started_session_no_longer_blocks_a_new_one(auth_client, rewards_on):
    _d, s = start_session(auth_client, rewards_on.offer)
    RewardedAdSession.objects.filter(pk=s.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
    assert create(auth_client, rewards_on.offer).status_code == 201
    assert RewardedAdSession.objects.get(pk=s.pk).status == S.EXPIRED


def test_polling_an_overdue_session_shows_expired(auth_client, rewards_on):
    d = create(auth_client, rewards_on.offer).data
    RewardedAdSession.objects.filter(pk=d["id"]).update(expires_at=timezone.now() - timedelta(seconds=1))
    r = auth_client.get(f"{SESSIONS}{d['id']}/")
    assert r.data["status"] == "expired" and r.data["credits_granted"] == 0 and "expired" in r.data["next_step"]


def test_session_ttl_is_configurable(auth_client, rewards_on):
    set_config("rewarded_session_ttl_seconds", 60)
    d = create(auth_client, rewards_on.offer).data
    s = RewardedAdSession.objects.get(pk=d["id"])
    assert 55 <= (s.expires_at - s.created_at).total_seconds() <= 65


# ---- client events can never grant credits -----------------------------------------------------------------------------------------
@pytest.mark.parametrize("event", ["ad_available", "started", "client_reward_reported", "closed_early", "cancelled", "no_fill", "load_failed", "timeout"])
def test_no_client_event_ever_grants_credits(auth_client, rewards_on, user, event):
    d = create(auth_client, rewards_on.offer).data
    r = auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": event}, format="json")
    assert r.status_code == 200 and r.data["credits_granted"] == 0
    assert service.balance_of(user) == 0 and UsageCreditLedger.objects.count() == 0
    assert RewardedAdSession.objects.get(pk=d["id"]).status != S.REWARDED


def test_requested_loaded_opened_clicked_or_closed_is_not_a_completion(auth_client, rewards_on, user):
    d = create(auth_client, rewards_on.offer).data
    for ev in ("ad_available", "started", "client_reward_reported", "closed_early"):
        auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": ev}, format="json")
    assert service.balance_of(user) == 0
    s = RewardedAdSession.objects.get(pk=d["id"])
    assert s.status == S.CLOSED_WITHOUT_REWARD and s.client_reward_reported_at is not None


def test_unknown_events_are_refused(auth_client, rewards_on):
    d = create(auth_client, rewards_on.offer).data
    for bad in ("rewarded", "grant", "impression", "click", ""):
        assert auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": bad}, format="json").status_code == 400


def test_a_failed_ad_does_not_penalise_the_user(auth_client, rewards_on, user):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(cooldown_seconds=3600, maximum_claims_per_day=1)
    d = create(auth_client, rewards_on.offer).data
    auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": "no_fill"}, format="json")
    r = offers(auth_client)
    assert r.data["offers"][0]["available"] is True                        # no cooldown, no claim used
    assert r.data["offers"][0]["claims"][0]["claimed"] == 0
    assert create(auth_client, rewards_on.offer).status_code == 201


def test_terminal_sessions_cannot_be_moved_by_the_client(auth_client, rewards_on):
    d = create(auth_client, rewards_on.offer).data
    RewardedAdSession.objects.filter(pk=d["id"]).update(status=S.REWARDED)
    r = auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": "closed_early"}, format="json")
    assert r.data["status"] == "rewarded"
    RewardedAdSession.objects.filter(pk=d["id"]).update(status=S.REJECTED)
    assert auth_client.post(f"{SESSIONS}{d['id']}/events/", {"event": "started"}, format="json").data["status"] == "rejected"


# ---- caps, cooldown, suspension (checked at session creation; re-checked at grant time in test_credits_callbacks) ------------------------
def make_reward(user, offer, minutes_ago=0, key=None):
    s = RewardedAdSession.objects.create(user=user, rewarded_ad_offer=offer, platform="android", provider="admob",
                                         unique_session_token=key or f"t{RewardedAdSession.objects.count()}{minutes_ago}",
                                         expected_reward_amount=offer.reward_amount, status=S.REWARDED,
                                         expires_at=timezone.now() + timedelta(hours=1),
                                         completed_at=timezone.now() - timedelta(minutes=minutes_ago))
    return s


def test_claim_caps_per_window(user, auth_client, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_day=2)
    make_reward(user, rewards_on.offer)
    assert offers(auth_client).data["offers"][0]["available"] is True
    make_reward(user, rewards_on.offer)
    o = offers(auth_client).data["offers"][0]
    assert o["reason"] == "claim_cap_reached" and o["claims"][0] == {**o["claims"][0], "claimed": 2, "limit": 2, "remaining": 0}
    assert create(auth_client, rewards_on.offer).status_code == 409


def test_weekly_and_monthly_claim_caps(user, auth_client, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_week=1)
    make_reward(user, rewards_on.offer)
    assert offers(auth_client).data["offers"][0]["reason"] == "claim_cap_reached"
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_week=None, maximum_claims_per_month=1)
    assert offers(auth_client).data["offers"][0]["reason"] == "claim_cap_reached"


def test_claim_caps_are_per_user(user, other_user, auth_client, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_day=1)
    make_reward(other_user, rewards_on.offer)
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_cooldown_between_rewards(user, auth_client, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(cooldown_seconds=600)
    make_reward(user, rewards_on.offer, minutes_ago=2)
    o = offers(auth_client).data["offers"][0]
    assert o["reason"] == "cooldown" and o["next_available_at"] is not None
    assert create(auth_client, rewards_on.offer).data["error"]["code"] == "cooldown"
    RewardedAdSession.objects.all().delete()
    make_reward(user, rewards_on.offer, minutes_ago=11)
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_credit_earning_caps_come_from_the_plan_entitlements(user, auth_client, rewards_on):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    for key, limit in (("credits.earn.daily_limit", 8),):
        EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key=key), enabled=True,
                                           limit_value=limit, note="cap test")
    service.grant(user, 5, UsageCreditLedger.Type.REWARDED_AD_EARNED, idempotency_key="earned-1")
    o = offers(auth_client).data["offers"][0]
    assert o["reason"] == "earning_cap_reached"                          # 5 earned + 5 more would exceed 8 today
    assert offers(auth_client).data["earning_limits"][0] == {**offers(auth_client).data["earning_limits"][0], "earned": 5, "limit": 8, "remaining": 3}


def test_admin_grants_do_not_use_up_the_earning_cap(user, auth_client, rewards_on):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key="credits.earn.daily_limit"),
                                       enabled=True, limit_value=8, note="cap test")
    service.grant(user, 500, UsageCreditLedger.Type.ADMIN_GRANT, idempotency_key="gift-1")
    assert offers(auth_client).data["offers"][0]["available"] is True


def test_earning_can_be_suspended_per_user(user, auth_client, rewards_on):
    w = service.wallet_for(user)
    w.earning_suspended = True
    w.save()
    assert offers(auth_client).data["offers"][0]["reason"] == "earning_suspended"
    assert create(auth_client, rewards_on.offer).status_code == 409


# ---- web: not verifiable by the provider ---------------------------------------------------------------------------------------------
@pytest.fixture
def web_offer(db):
    ad_manager = AdProvider.objects.get(key="google_ad_manager")
    AdProvider.objects.filter(pk=ad_manager.pk).update(enabled=True)
    ad_manager.refresh_from_db()
    set_config("rewarded_ads_enabled", True)
    set_config("rewarded_ads_web_enabled", True)
    return RewardedAdOffer.objects.create(name="Web offer", enabled=True, platform="web", provider=ad_manager, reward_amount=3,
                                          configuration={"test_ad_unit_identifier": "/1234/test_rewarded"})


def test_web_rewards_are_unavailable_by_default_because_the_provider_cannot_verify_them(auth_client, web_offer):
    o = offers(auth_client, "web").data["offers"][0]
    assert o["available"] is False and o["reason"] == "verification_unavailable"
    assert create(auth_client, web_offer, "web").status_code == 409


def test_web_offers_open_up_only_when_the_administrator_accepts_client_attestation(auth_client, web_offer):
    set_config("rewarded_web_client_attested_enabled", True)
    o = offers(auth_client, "web").data["offers"][0]
    assert o["available"] is True and o["verification"] == "client_attested"


def test_web_test_mode_needs_a_configured_test_ad_unit(auth_client, web_offer):
    set_config("rewarded_web_client_attested_enabled", True)
    RewardedAdOffer.objects.filter(pk=web_offer.pk).update(configuration={})
    assert offers(auth_client, "web").data["offers"][0]["reason"] == "ad_unit_not_configured"
