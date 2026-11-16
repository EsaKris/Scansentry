import time
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from django.utils import timezone

from apps.advertising.models import AdProvider
from apps.credits import service, verifiers
from apps.credits.models import RewardCallbackEvent, RewardedAdOffer, RewardedAdSession, UsageCreditLedger
from tests.conftest import set_config, start_session
from tests.rewards_sim import KEY_ID, TEST_UNIT

pytestmark = pytest.mark.django_db
S = RewardedAdSession.Status
T = UsageCreditLedger.Type
CB = "/api/v1/advertising/reward-callbacks/admob/"


@pytest.fixture
def sess(auth_client, rewards_on):
    _d, s = start_session(auth_client, rewards_on.offer)
    return s


def earned(user):
    return UsageCreditLedger.objects.filter(user=user, transaction_type=T.REWARDED_AD_EARNED)


def reload(s):
    s.refresh_from_db()
    return s


# ---- the happy path ------------------------------------------------------------------------------------------------------
def test_a_valid_signed_callback_grants_the_configured_credits_once(api, admob, sess, user):
    r = admob.call(api, sess)
    assert r.status_code == 200 and r.data == {"status": "accepted", "code": "accepted"}
    assert service.balance_of(user) == 5 and earned(user).count() == 1
    s = reload(sess)
    assert s.status == S.REWARDED and s.provider_verification_status == "verified" and s.provider_transaction_id == "tx-0001"
    assert earned(user).get().rewarded_ad_session_id == s.pk


def test_the_amount_comes_from_our_offer_not_from_the_provider(api, admob, sess, user):
    admob.call(api, sess, params_override={"reward_amount": "9999", "reward_item": "gold"})
    assert service.balance_of(user) == 5


def test_changing_the_offer_after_session_creation_does_not_change_the_reward(api, admob, sess, user, rewards_on):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(reward_amount=500)
    admob.call(api, sess)
    assert service.balance_of(user) == 5                          # the amount shown to the user at the start is what they get


def test_a_callback_needs_no_login_its_authenticity_is_the_signature(api, admob, sess):
    assert admob.call(api, sess).status_code == 200


def test_a_callback_works_before_the_client_reports_anything(api, admob, auth_client, rewards_on, user):
    _d, s = start_session(auth_client, rewards_on.offer, started=False)
    assert admob.call(api, s).data["code"] == "accepted"


def test_credits_expire_according_to_the_offer(api, admob, sess, user, rewards_on):
    RewardedAdSession.objects.filter(pk=sess.pk).update(credit_expiry_days=10)
    admob.call(api, sess)
    entry = earned(user).get()
    assert entry.lot.expires_at is not None
    assert timedelta(days=9) < entry.lot.expires_at - timezone.now() <= timedelta(days=10)


def test_credits_never_expire_when_the_offer_says_so(api, admob, sess, user):
    admob.call(api, sess)
    assert earned(user).get().lot.expires_at is None


def test_the_callback_works_over_post_too(api, admob, sess, user):
    r = api.post(CB + "?" + admob.query(sess))
    assert r.status_code == 200 and service.balance_of(user) == 5


# ---- forged / tampered -------------------------------------------------------------------------------------------------------
def test_a_forged_signature_grants_nothing(api, admob, sess, user):
    attacker = ec.generate_private_key(ec.SECP256R1())
    r = admob.call(api, sess, signer=attacker)
    assert r.status_code == 403 and r.data["error"]["code"] == "invalid_callback"
    assert service.balance_of(user) == 0 and reload(sess).status == S.STARTED


def test_an_invalid_signature_leaves_the_session_untouched_so_it_cannot_be_griefed(api, admob, sess):
    admob.call(api, sess, signer=ec.generate_private_key(ec.SECP256R1()))
    assert reload(sess).status == S.STARTED and reload(sess).rejection_reason == ""
    assert admob.call(api, sess).data["code"] == "accepted"                    # the real callback still works


@pytest.mark.parametrize("field,value", [("transaction_id", "tx-evil"), ("user_id", "someone-else"), ("timestamp", "1"),
                                         ("ad_unit", "999"), ("custom_data", "other"), ("reward_amount", "50")])
def test_changing_any_signed_parameter_breaks_the_signature(api, admob, sess, user, field, value):
    q = admob.query(sess)
    import re
    tampered = re.sub(rf"(?<![a-z_]){field}=[^&]*", f"{field}={value}", q, count=1)
    assert tampered != q
    r = api.get(CB + "?" + tampered)
    assert r.status_code == 403 and service.balance_of(user) == 0


def test_an_unknown_key_id_is_rejected(api, admob, sess, user):
    r = admob.call(api, sess, key_id="123")
    assert r.status_code == 403 and service.balance_of(user) == 0


def test_an_attacker_cannot_append_unsigned_parameters(api, admob, sess, user):
    """Anything after `signature` is not covered by it, so it is refused outright (parameter pollution)."""
    for extra in ("&custom_data=mine", "&transaction_id=other", "&user_id=x", "&foo=bar"):
        r = admob.call(api, sess, extra_after=extra)
        assert r.status_code == 400, extra
    assert service.balance_of(user) == 0


def test_repeated_parameters_are_refused(api, admob, sess, user):
    q = admob.query(sess)
    r = api.get(CB + "?custom_data=evil&" + q)
    assert r.status_code == 400 and service.balance_of(user) == 0


@pytest.mark.parametrize("qs", ["", "a=b", "signature=abc&key_id=1", "transaction_id=1&signature=%%%&key_id=1"])
def test_malformed_callbacks_are_refused(api, admob, qs, user):
    r = api.get(CB + ("?" + qs if qs else ""))
    assert r.status_code in (400, 403) and service.balance_of(user) == 0


def test_an_oversized_query_is_refused(api, admob):
    assert api.get(CB + "?" + "a=" + "x" * 5000).status_code == 400


def test_an_unknown_session_token_grants_nothing(api, admob, sess, user):
    r = admob.call(api, sess, custom_data="not-a-real-token")
    assert r.status_code == 200 and r.data["code"] == "session_not_found" and service.balance_of(user) == 0


def test_a_callback_for_someone_elses_session_fails_the_user_check(api, admob, sess, other_user, user):
    r = admob.call(api, sess, user_id=str(other_user.pk))
    assert r.data["code"] == "user_mismatch" and service.balance_of(user) == 0 and service.balance_of(other_user) == 0
    assert reload(sess).status == S.STARTED


def test_a_callback_for_a_different_ad_unit_is_refused(api, admob, sess, user):
    r = admob.call(api, sess, ad_unit="1111111111")
    assert r.data["code"] == "ad_unit_mismatch" and service.balance_of(user) == 0


def test_unknown_or_unverifiable_providers_have_no_callback(api):
    assert api.get("/api/v1/advertising/reward-callbacks/google_ad_manager/?a=b").status_code == 404
    assert api.get("/api/v1/advertising/reward-callbacks/nonsense/").status_code == 404


# ---- duplicates, replays -------------------------------------------------------------------------------------------------------
def test_a_duplicate_callback_credits_once(api, admob, sess, user):
    first = admob.call(api, sess)
    second = admob.call(api, sess)
    third = admob.call(api, sess)
    assert [first.data["code"], second.data["code"], third.data["code"]] == ["accepted", "duplicate", "duplicate"]
    assert second.status_code == 200                                        # a retry must be acknowledged, not errored
    assert service.balance_of(user) == 5 and earned(user).count() == 1


def test_a_different_signed_transaction_for_a_rewarded_session_is_a_replay(api, admob, sess, user):
    admob.call(api, sess, tx="tx-A")
    r = admob.call(api, sess, tx="tx-B")
    assert r.data["code"] == "replay" and service.balance_of(user) == 5


def test_a_transaction_id_can_never_pay_two_sessions(api, admob, auth_client, rewards_on, user):
    _d, s1 = start_session(auth_client, rewards_on.offer)
    admob.call(api, s1, tx="shared")
    _d, s2 = start_session(auth_client, rewards_on.offer)
    r = admob.call(api, s2, tx="shared")
    assert r.data["code"] == "replay" and service.balance_of(user) == 5
    assert reload(s2).status == S.STARTED


def test_concurrent_looking_duplicates_still_make_one_ledger_row(api, admob, sess, user):
    for _ in range(5):
        admob.call(api, sess)
    assert UsageCreditLedger.objects.filter(idempotency_key="reward:admob:tx-0001").count() == 1
    assert service.reconcile()["consistent"]


def test_rejected_sessions_stay_rejected(api, admob, sess, user):
    RewardedAdSession.objects.filter(pk=sess.pk).update(status=S.REJECTED)
    assert admob.call(api, sess).data["code"] == "rejected" and service.balance_of(user) == 0


# ---- timing: expired, early, delayed -------------------------------------------------------------------------------------------
def test_a_reward_moment_after_the_session_expired_is_refused(api, admob, sess, user):
    RewardedAdSession.objects.filter(pk=sess.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
    r = admob.call(api, sess, ts=time.time())
    assert r.data["code"] == "session_expired" and service.balance_of(user) == 0
    s = reload(sess)
    assert s.status == S.REJECTED and s.rejection_reason == "session_expired"


def test_a_reward_moment_before_the_session_existed_is_refused(api, admob, sess, user):
    r = admob.call(api, sess, ts=time.time() - 3600)
    assert r.data["code"] == "reward_before_session" and service.balance_of(user) == 0


def test_a_delayed_callback_is_honoured_if_the_user_was_rewarded_in_time(api, admob, sess, user):
    """Google may deliver late: what matters is WHEN the user was rewarded, not when the callback arrived."""
    reward_time = time.time() - 600
    RewardedAdSession.objects.filter(pk=sess.pk).update(created_at=timezone.now() - timedelta(minutes=12),
                                                        expires_at=timezone.now() - timedelta(minutes=1))
    r = admob.call(api, sess, ts=reward_time)
    assert r.data["code"] == "accepted" and service.balance_of(user) == 5


def test_a_callback_that_arrives_after_the_session_was_swept_as_expired_is_still_honoured_if_the_reward_was_in_time(api, admob, sess, user):
    RewardedAdSession.objects.filter(pk=sess.pk).update(status=S.EXPIRED)
    assert admob.call(api, sess).data["code"] == "accepted" and service.balance_of(user) == 5


def test_a_closed_early_report_does_not_stop_a_genuine_provider_completion(api, admob, auth_client, sess, user):
    auth_client.post(f"/api/v1/credits/rewarded-sessions/{sess.pk}/events/", {"event": "closed_early"}, format="json")
    assert admob.call(api, sess).data["code"] == "accepted"          # the provider's completion definition is authoritative


def test_a_callback_that_is_far_too_late_is_refused(api, admob, sess, user):
    set_config("rewarded_ssv_max_delay_seconds", 60)
    RewardedAdSession.objects.filter(pk=sess.pk).update(created_at=timezone.now() - timedelta(hours=1), expires_at=timezone.now() + timedelta(hours=1))
    r = admob.call(api, sess, ts=time.time() - 300)
    assert r.data["code"] == "callback_too_late" and service.balance_of(user) == 0


# ---- provider trouble ---------------------------------------------------------------------------------------------------------
def test_when_the_key_server_is_down_nothing_is_granted_and_the_provider_is_told_to_retry(api, admob, sess, user):
    admob.available = False
    r = admob.call(api, sess)
    assert r.status_code == 503 and service.balance_of(user) == 0 and reload(sess).status == S.STARTED
    admob.available = True
    from django.core.cache import cache
    cache.clear()
    assert admob.call(api, sess).data["code"] == "accepted"            # the retry succeeds


def test_keys_are_cached_and_refreshed_at_most_once_for_an_unknown_id(api, admob, sess):
    admob.call(api, sess, tx="a")
    admob.call(api, sess, tx="b")
    assert admob.key_fetches == 1
    for _ in range(3):
        admob.call(api, sess, key_id="999")                           # unknown key id: one bounded refresh, not one per request
    assert admob.key_fetches <= 2


def test_a_rotated_key_is_picked_up(api, admob, sess, user):
    admob.call(api, sess, tx="old")
    new_private = ec.generate_private_key(ec.SECP256R1())
    admob.keys["7777"] = admob.pem(new_private)
    verifiers_cache = __import__("django.core.cache", fromlist=["cache"]).cache
    verifiers_cache.delete(verifiers.REFETCH_COOLDOWN_KEY)
    _d, s2 = start_session(api_client_for(user), RewardedAdOffer.objects.first())
    r = admob.call(api, s2, key_id="7777", signer=new_private, tx="new")
    assert r.data["code"] == "accepted"


def api_client_for(user):
    from rest_framework.test import APIClient
    c = APIClient()
    c.force_authenticate(user)
    return c


def test_the_key_server_is_reached_through_the_ssrf_guard(monkeypatch):
    seen = {}

    class FakeGuard:
        def fetch(self, url, **kw):
            seen.update(url=url, **kw)
            from apps.domain_intel.netsafe import FetchResult
            return FetchResult(url=url, status=200, body=b'{"keys":[{"keyId":1,"pem":"p","base64":"b"}]}')

    monkeypatch.setattr("apps.domain_intel.service.build_guard", lambda *a, **k: FakeGuard())
    assert verifiers.fetch_keys() == {"1": "p"}
    assert seen["url"] == verifiers.KEYS_URL and seen["require_https"] is True


@pytest.mark.parametrize("body,status", [(b"not json", 200), (b'{"keys": []}', 200), (b"{}", 200), (b"", 500)])
def test_an_unreadable_key_list_is_a_transient_failure_never_a_pass(monkeypatch, body, status):
    class FakeGuard:
        def fetch(self, url, **kw):
            from apps.domain_intel.netsafe import FetchResult
            return FetchResult(url=url, status=status, body=body)

    monkeypatch.setattr("apps.domain_intel.service.build_guard", lambda *a, **k: FakeGuard())
    with pytest.raises(verifiers.VerificationFailure) as e:
        verifiers.fetch_keys()
    assert e.value.transient


def test_timestamps_are_normalised(monkeypatch):
    now = time.time()
    for raw in (int(now), int(now * 1000), int(now * 1_000_000)):
        assert abs(verifiers.reward_timestamp(str(raw)).timestamp() - now) < 2
    for bad in ("x", "0", "-5", "99999999999999999999999"):
        with pytest.raises(verifiers.VerificationFailure):
            verifiers.reward_timestamp(bad)


# ---- switches, caps and cooldown are enforced again when granting -----------------------------------------------------------------
def test_switching_rewards_off_before_the_callback_arrives_stops_the_grant(api, admob, sess, user):
    set_config("rewarded_ads_enabled", False)
    r = admob.call(api, sess)
    assert r.data["code"] == "rewards_disabled" and service.balance_of(user) == 0


def test_the_claim_cap_is_enforced_at_grant_time(api, admob, auth_client, rewards_on, user):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(maximum_claims_per_day=1)
    _d, s1 = start_session(auth_client, rewards_on.offer)
    RewardedAdSession.objects.filter(pk=s1.pk).update(status=S.CLOSED_WITHOUT_REWARD)
    _d, s2 = start_session(auth_client, rewards_on.offer)
    assert admob.call(api, s2, tx="two").data["code"] == "accepted"
    r = admob.call(api, s1, tx="one")                                       # a second completion that day
    assert r.data["code"] == "claim_cap_reached" and service.balance_of(user) == 5


def test_the_cooldown_is_enforced_at_grant_time(api, admob, auth_client, rewards_on, user):
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(cooldown_seconds=3600)
    _d, s1 = start_session(auth_client, rewards_on.offer)
    RewardedAdSession.objects.filter(pk=s1.pk).update(status=S.CLOSED_WITHOUT_REWARD)
    _d, s2 = start_session(auth_client, rewards_on.offer)
    admob.call(api, s2, tx="first")
    assert admob.call(api, s1, tx="second").data["code"] == "cooldown" and service.balance_of(user) == 5


def test_the_earning_cap_is_enforced_at_grant_time(api, admob, sess, user):
    from apps.billing.models import EntitlementOverride, FeatureDefinition
    EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key="credits.earn.daily_limit"),
                                       enabled=True, limit_value=4, note="cap")
    assert admob.call(api, sess).data["code"] == "earning_cap_reached" and service.balance_of(user) == 0


def test_a_suspended_wallet_earns_nothing(api, admob, sess, user):
    w = service.wallet_for(user)
    w.earning_suspended = True
    w.save()
    assert admob.call(api, sess).data["code"] == "earning_suspended" and service.balance_of(user) == 0


def test_production_mode_refuses_google_test_ads(api, admob, auth_client, rewards_on, user):
    """A test ad (or a callback for one) must never produce real credits in production."""
    RewardedAdOffer.objects.filter(pk=rewards_on.offer.pk).update(ad_unit_identifier="ca-app-pub-1111111111111111/2222222222")
    set_config("rewarded_ads_test_mode", False)
    _d, s = start_session(auth_client, rewards_on.offer)
    assert s.ad_unit_id == "ca-app-pub-1111111111111111/2222222222"
    r = admob.call(api, s, ad_unit=TEST_UNIT)
    assert r.data["code"] in ("ad_unit_mismatch", "test_ad_in_production") and service.balance_of(user) == 0
    RewardedAdSession.objects.filter(pk=s.pk).update(ad_unit_id="ca-app-pub-3940256099942544/5224354917")
    r = admob.call(api, s, ad_unit=TEST_UNIT, tx="tx-test-ad")
    assert r.data["code"] == "test_ad_in_production" and service.balance_of(user) == 0


# ---- audit trail -----------------------------------------------------------------------------------------------------------
def test_every_callback_attempt_is_recorded_without_ip_or_signature(api, admob, sess):
    admob.call(api, sess, signer=ec.generate_private_key(ec.SECP256R1()))
    admob.call(api, sess)
    admob.call(api, sess)
    outcomes = list(RewardCallbackEvent.objects.order_by("id").values_list("outcome", flat=True))
    assert outcomes == ["invalid_signature", "accepted", "duplicate"]
    fields = {f.name for f in RewardCallbackEvent._meta.get_fields()}
    assert not ({"ip_address", "ip", "signature", "raw_query", "payload"} & fields)


# ---- web: client attestation (off by default) -----------------------------------------------------------------------------------
@pytest.fixture
def web(auth_client, db):
    ad_manager = AdProvider.objects.get(key="google_ad_manager")
    AdProvider.objects.filter(pk=ad_manager.pk).update(enabled=True)
    ad_manager.refresh_from_db()
    set_config("rewarded_ads_enabled", True)
    set_config("rewarded_ads_web_enabled", True)
    offer = RewardedAdOffer.objects.create(name="Web", enabled=True, platform="web", provider=ad_manager, reward_amount=3,
                                           configuration={"test_ad_unit_identifier": "/1234/test_rewarded"})
    return offer


def complete(client, s):
    return client.post(f"/api/v1/credits/rewarded-sessions/{s.pk}/complete/")


def web_session(client, offer):
    set_config("rewarded_web_client_attested_enabled", True)
    return start_session(client, offer, platform="web")[1]


def test_web_completion_is_refused_while_attestation_is_off(auth_client, web, user):
    set_config("rewarded_web_client_attested_enabled", True)
    _d, s = start_session(auth_client, web, platform="web")
    set_config("rewarded_web_client_attested_enabled", False)
    r = complete(auth_client, s)
    assert r.status_code == 409 and r.data["error"]["code"] == "verification_unavailable" and service.balance_of(user) == 0


def test_web_completion_grants_once_when_enabled_and_started_long_enough(auth_client, web, user):
    s = web_session(auth_client, web)
    RewardedAdSession.objects.filter(pk=s.pk).update(started_at=timezone.now() - timedelta(seconds=30))
    r = complete(auth_client, s)
    assert r.status_code == 200 and r.data["outcome"] == "accepted" and r.data["balance"] == 3
    assert reload(s).provider_verification_status == "client_attested"       # honestly labelled: not provider-verified
    again = complete(auth_client, s)
    assert again.data["outcome"] in ("duplicate", "replay") and service.balance_of(user) == 3


def test_web_completion_needs_a_started_session(auth_client, web, user):
    set_config("rewarded_web_client_attested_enabled", True)
    _d, s = start_session(auth_client, web, platform="web", started=False)
    assert complete(auth_client, s).data["outcome"] == "not_started" and service.balance_of(user) == 0


def test_web_completion_cannot_be_instant(auth_client, web, user):
    s = web_session(auth_client, web)
    assert complete(auth_client, s).data["outcome"] == "completed_too_quickly" and service.balance_of(user) == 0


def test_web_completion_after_expiry_is_refused(auth_client, web, user):
    s = web_session(auth_client, web)
    RewardedAdSession.objects.filter(pk=s.pk).update(started_at=timezone.now() - timedelta(minutes=30), expires_at=timezone.now() - timedelta(seconds=1))
    assert complete(auth_client, s).data["outcome"] == "session_expired" and service.balance_of(user) == 0


def test_web_attestation_respects_caps_and_cooldown(auth_client, web, user):
    RewardedAdOffer.objects.filter(pk=web.pk).update(maximum_claims_per_day=1)
    s1 = web_session(auth_client, web)
    RewardedAdSession.objects.filter(pk=s1.pk).update(started_at=timezone.now() - timedelta(seconds=30))
    complete(auth_client, s1)
    RewardedAdOffer.objects.filter(pk=web.pk).update(maximum_claims_per_day=5, cooldown_seconds=3600)
    r = auth_client.post("/api/v1/credits/rewarded-sessions/", {"offer": str(web.id), "platform": "web"}, format="json")
    assert r.status_code == 409 and r.data["error"]["code"] == "cooldown"


def test_android_sessions_cannot_use_the_attestation_shortcut(auth_client, rewards_on, user):
    set_config("rewarded_web_client_attested_enabled", True)
    _d, s = start_session(auth_client, rewards_on.offer)
    RewardedAdSession.objects.filter(pk=s.pk).update(started_at=timezone.now() - timedelta(minutes=5))
    r = complete(auth_client, s)
    assert r.status_code == 409 and service.balance_of(user) == 0


def test_web_attestation_cannot_complete_someone_elses_session(auth_client, other_client, web, other_user):
    s = web_session(auth_client, web)
    RewardedAdSession.objects.filter(pk=s.pk).update(started_at=timezone.now() - timedelta(seconds=30))
    assert complete(other_client, s).status_code == 404 and service.balance_of(other_user) == 0
