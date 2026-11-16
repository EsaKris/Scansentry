"""Rewarded-ad offers, sessions and settlement.

The one rule: credits are granted ONLY by `settle()`, and `settle()` is only reached from a verified provider completion
(AdMob server-side verification) or, for web, an explicitly enabled and heavily constrained client attestation. Requesting,
loading, opening, clicking or closing an ad never reaches it.
"""
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from django.db import transaction
from django.db.models import Sum

from apps.advertising import settings_store as ad_cfg
from apps.advertising.constants import (ADMOB_TEST_UNITS, PROVIDER_CAPABILITIES, is_test_identifier)
from apps.advertising.decision import _provider_public, categorize
from apps.advertising.models import AdPreference
from apps.analytics.usage import WINDOWS, window_bounds
from apps.billing import entitlements as ent

from . import config as cfg
from . import service
from .models import RewardedAdOffer, RewardedAdSession, UsageCreditLedger

S = RewardedAdSession.Status
V = RewardedAdSession.Verification
EARN_LIMIT_KEYS = {"day": "credits.earn.daily_limit", "week": "credits.earn.weekly_limit", "month": "credits.earn.monthly_limit"}
CLAIM_FIELDS = {"day": "maximum_claims_per_day", "week": "maximum_claims_per_week", "month": "maximum_claims_per_month"}
TERMS = ("ScanSentry Credits are usage units only. They have no cash value and cannot be withdrawn, transferred, sold or used to "
         "buy subscriptions. You choose whether to watch; scanning and security warnings never need credits or an advertisement.")
CLOCK_SKEW = timedelta(seconds=60)


class RewardNotAvailable(Exception):
    def __init__(self, reason: str, extra: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.extra = extra or {}


def _now(now=None) -> datetime:
    return now or datetime.now(timezone.utc)


# ---- switches & provider support ---------------------------------------------------------------------------------------
def switch_reason(platform: str) -> str | None:
    if not cfg.flag("rewarded_ads_enabled"):
        return "rewarded_ads_disabled"
    if platform not in ("web", "android") or not cfg.flag(f"rewarded_ads_{platform}_enabled"):
        return "platform_disabled"
    return None


def verification_mode(provider_key: str, platform: str) -> str | None:
    """How a completion on this provider/platform can be verified, or None if it cannot be (then no credits are possible)."""
    if provider_key == "admob" and platform == "android":
        return "server_side_verification"
    if provider_key == "google_ad_manager" and platform == "web":
        return "client_attested" if cfg.flag("rewarded_web_client_attested_enabled") else None
    return None


def ad_unit_for(offer: RewardedAdOffer, platform: str, test_mode: bool) -> str | None:
    key = offer.provider.key
    if test_mode:
        if key == "admob":
            return ADMOB_TEST_UNITS["rewarded"]
        return (offer.configuration or {}).get("test_ad_unit_identifier") or None
    ident = (offer.ad_unit_identifier or "").strip()
    return ident if ident and not is_test_identifier(ident) else None


# ---- helpers ------------------------------------------------------------------------------------------------------------
def country_of(request) -> str:
    from django.conf import settings
    header = getattr(settings, "GEO_COUNTRY_HEADER", "")
    if not header:
        return ""
    value = request.META.get("HTTP_" + header.upper().replace("-", "_"), "").strip().upper()
    return value if len(value) == 2 and value.isalpha() else ""


def _claims(user, offer, window: str, now) -> int:
    start, end = window_bounds(window, now)
    return RewardedAdSession.objects.filter(user=user, rewarded_ad_offer=offer, status=S.REWARDED,
                                            completed_at__gte=start, completed_at__lt=end).count()


def _earned(user, window: str, now) -> int:
    start, end = window_bounds(window, now)
    return (UsageCreditLedger.objects.filter(user=user, transaction_type=UsageCreditLedger.Type.REWARDED_AD_EARNED,
                                             created_at__gte=start, created_at__lt=end).aggregate(s=Sum("amount"))["s"] or 0)


def _last_reward(user, offer):
    return (RewardedAdSession.objects.filter(user=user, rewarded_ad_offer=offer, status=S.REWARDED, completed_at__isnull=False)
            .order_by("-completed_at").first())


def earning_windows(user, now) -> list:
    """Credits earnable per window (an entitlement) against what was already earned: the 'reward opportunities'."""
    out = []
    for w in WINDOWS:
        e = ent.resolve(user, EARN_LIMIT_KEYS[w], now)
        limit = 0 if not e.enabled else e.limit
        earned = _earned(user, w, now)
        out.append({"window": w, "earned": earned, "limit": limit, "remaining": None if limit is None else max(0, limit - earned),
                    "resets_at": window_bounds(w, now)[1], "timezone": "UTC"})
    return out


def claim_windows(user, offer, now) -> list:
    out = []
    for w in WINDOWS:
        limit = getattr(offer, CLAIM_FIELDS[w])
        used = _claims(user, offer, w, now)
        out.append({"window": w, "claimed": used, "limit": limit, "remaining": None if limit is None else max(0, limit - used),
                    "resets_at": window_bounds(w, now)[1], "timezone": "UTC"})
    return out


def check_offer(user, offer: RewardedAdOffer, platform: str, country: str, now) -> str | None:
    """None when this user may earn from this offer right now, else the reason. Switches, caps and cooldown are re-checked when granting."""
    reason = switch_reason(platform)
    if reason:
        return reason
    if not offer.enabled:
        return "offer_disabled"
    if (offer.starts_at and now < offer.starts_at) or (offer.ends_at and now >= offer.ends_at):
        return "offer_not_active"
    if offer.platform not in (platform, "both"):
        return "platform_mismatch"
    if not offer.provider.enabled or platform not in offer.provider.platforms.split(","):
        return "provider_disabled"
    caps = PROVIDER_CAPABILITIES.get(offer.provider.key)
    if caps is None or "rewarded" not in caps[1]:
        return "provider_unsupported"
    if verification_mode(offer.provider.key, platform) is None:
        return "verification_unavailable"
    test_mode = cfg.flag("rewarded_ads_test_mode")
    if ad_unit_for(offer, platform, test_mode) is None:
        return "ad_unit_not_configured"
    if not ent.resolve(user, "ads.rewarded_credits", now).enabled:
        return "not_entitled"
    category, plan_slug = categorize(user, now)
    cats = offer.eligible_categories or []
    if cats and category not in cats:
        return "category_not_eligible"
    if offer.eligible_plans and plan_slug not in offer.eligible_plans:
        return "plan_not_eligible"
    rules = offer.configuration or {}
    allowed, blocked = rules.get("allowed_countries") or [], rules.get("blocked_countries") or []
    if (allowed or blocked) and not country:
        return "country_unknown"
    if country and ((allowed and country not in allowed) or country in blocked):
        return "country_not_eligible"
    if service.wallet_for(user).earning_suspended:
        return "earning_suspended"
    for w in WINDOWS:
        limit = getattr(offer, CLAIM_FIELDS[w])
        if limit is not None and _claims(user, offer, w, now) >= limit:
            return "claim_cap_reached"
    for row in earning_windows(user, now):
        if row["limit"] is not None and row["earned"] + offer.reward_amount > row["limit"]:
            return "earning_cap_reached"
    if offer.cooldown_seconds:
        last = _last_reward(user, offer)
        if last and now < last.completed_at + timedelta(seconds=offer.cooldown_seconds):
            return "cooldown"
    return None


def offer_payload(user, offer: RewardedAdOffer, platform: str, country: str, now) -> dict:
    reason = check_offer(user, offer, platform, country, now)
    last = _last_reward(user, offer) if offer.cooldown_seconds else None
    next_at = last.completed_at + timedelta(seconds=offer.cooldown_seconds) if last else None
    return {
        "id": str(offer.id), "name": offer.name, "description": offer.description, "platform": platform,
        "provider": offer.provider.key, "available": reason is None, "reason": reason,
        "reward_amount": offer.reward_amount, "reward_label": f"{offer.reward_amount} ScanSentry Credits",
        "credits_expire_after_days": offer.credit_expiry_days, "eligible_features": offer.eligible_features or None,
        "claims": claim_windows(user, offer, now), "cooldown_seconds": offer.cooldown_seconds,
        "next_available_at": next_at if next_at and next_at > now else None, "terms": TERMS,
        "verification": verification_mode(offer.provider.key, platform),
    }


def list_offers(user, platform: str, country: str, now=None) -> list:
    now = _now(now)
    if platform not in ("web", "android"):
        return []
    qs = RewardedAdOffer.objects.filter(platform__in=(platform, "both")).select_related("provider")
    return [offer_payload(user, o, platform, country, now) for o in qs if o.enabled]


# ---- sessions -----------------------------------------------------------------------------------------------------------
def create_session(user, offer_id, platform: str, country: str, now=None) -> tuple[RewardedAdSession, dict]:
    now = _now(now)
    offer = RewardedAdOffer.objects.select_related("provider").filter(pk=offer_id).first()
    if offer is None or not offer.enabled:
        raise RewardNotAvailable("offer_not_found")
    with transaction.atomic():
        service.wallet_for(user, lock=True)                        # serialises this user's session creation
        # sessions nobody finished are closed so they can never be completed later
        RewardedAdSession.objects.filter(user=user, status__in=(S.CREATED, S.AD_AVAILABLE, S.STARTED), expires_at__lte=now) \
            .update(status=S.EXPIRED)
        if RewardedAdSession.objects.filter(user=user, status=S.STARTED, expires_at__gt=now).exists():
            raise RewardNotAvailable("session_in_progress")
        reason = check_offer(user, offer, platform, country, now)
        if reason:
            raise RewardNotAvailable(reason)
        RewardedAdSession.objects.filter(user=user, status__in=(S.CREATED, S.AD_AVAILABLE)) \
            .update(status=S.CLOSED_WITHOUT_REWARD, close_reason="superseded")
        test_mode = cfg.flag("rewarded_ads_test_mode")
        session = RewardedAdSession.objects.create(
            user=user, rewarded_ad_offer=offer, platform=platform, provider=offer.provider.key,
            unique_session_token=secrets.token_urlsafe(32), expected_reward_amount=offer.reward_amount,
            credit_expiry_days=offer.credit_expiry_days, ad_unit_id=ad_unit_for(offer, platform, test_mode) or "",
            expires_at=now + timedelta(seconds=cfg.number("rewarded_session_ttl_seconds") or 900))
    return session, client_instructions(session, offer, user, test_mode)


def client_instructions(session, offer, user, test_mode: bool) -> dict:
    pref = AdPreference.objects.filter(user=user).first()
    non_personalized = ad_cfg.flag("ads_non_personalized_default") or (pref is not None and pref.personalized_ads is False)
    mode = verification_mode(session.provider, session.platform)
    out = {"provider": session.provider, "provider_config": _provider_public(offer.provider, test_mode), "ad_unit_id": session.ad_unit_id,
           "test_mode": test_mode, "request_non_personalized_ads": non_personalized, "verification": mode}
    if mode == "server_side_verification":      # the client passes these to the SDK; the provider echoes them in the signed callback
        out["ssv"] = {"user_id": str(user.pk), "custom_data": session.unique_session_token}
    return out


def session_payload(session: RewardedAdSession, *, include_token: bool = False) -> dict:
    out = {"id": str(session.id), "status": session.status, "platform": session.platform, "provider": session.provider,
           "reward_amount": session.expected_reward_amount, "created_at": session.created_at, "expires_at": session.expires_at,
           "completed_at": session.completed_at, "close_reason": session.close_reason or None,
           "rejection_reason": session.rejection_reason or None, "verification": session.provider_verification_status,
           "credits_granted": session.expected_reward_amount if session.status == S.REWARDED else 0,
           "next_step": {"rewarded": "Credits were added to your wallet.", "rejected": "No credits were granted.",
                         "closed_without_reward": "No credits were granted. You can wait for your allowance to reset or view plans.",
                         "expired": "This ad session expired. No credits were granted."}.get(
                             session.status, "Complete the ad; credits are added only after the provider confirms it.")}
    if include_token:
        out["session_token"] = session.unique_session_token
    return out


def expire_if_due(session: RewardedAdSession, now=None) -> RewardedAdSession:
    """An unfinished session past its deadline becomes EXPIRED (a provider callback whose reward moment fell inside the session
    window can still be honoured later; see settle())."""
    now = _now(now)
    if session.status in (S.CREATED, S.AD_AVAILABLE, S.STARTED) and now >= session.expires_at:
        RewardedAdSession.objects.filter(pk=session.pk, status__in=(S.CREATED, S.AD_AVAILABLE, S.STARTED)).update(status=S.EXPIRED)
        session.refresh_from_db()
    return session


CLIENT_EVENTS = {"ad_available", "started", "closed_early", "cancelled", "no_fill", "load_failed", "timeout", "client_reward_reported"}


def record_event(session: RewardedAdSession, event: str, now=None) -> RewardedAdSession:
    """Client-reported progress. NEVER grants credits: it only moves the session between non-final states."""
    now = _now(now)
    if event not in CLIENT_EVENTS:
        raise ValueError("unknown event")
    with transaction.atomic():
        s = RewardedAdSession.objects.select_for_update().get(pk=session.pk)
        if s.status in (S.REWARDED, S.REJECTED, S.EXPIRED):
            return s                                              # final: nothing to change (never un-reward or un-reject)
        if now >= s.expires_at:
            s.status = S.EXPIRED
        elif event == "ad_available" and s.status == S.CREATED:
            s.status = S.AD_AVAILABLE
        elif event == "started" and s.status in (S.CREATED, S.AD_AVAILABLE):
            s.status, s.started_at = S.STARTED, now
        elif event == "client_reward_reported":
            s.client_reward_reported_at = now                      # informational (helps spot a client that says "earned" but gets no callback)
        elif event in ("closed_early", "cancelled", "no_fill", "load_failed", "timeout"):
            s.status, s.close_reason = S.CLOSED_WITHOUT_REWARD, event
        s.save()
        return s


# ---- settlement ---------------------------------------------------------------------------------------------------------
def _reject(s: RewardedAdSession, reason: str, now) -> SimpleNamespace:
    s.status, s.rejection_reason, s.provider_verification_status = S.REJECTED, reason, V.FAILED
    s.save(update_fields=["status", "rejection_reason", "provider_verification_status"])
    return SimpleNamespace(code=reason, session=s, entry=None, granted=False)


def settle(session_token: str, *, provider: str, transaction_id: str, reward_at: datetime, verification: str,
           expected_user_id: str | None = None, ad_unit: str | None = None, now=None) -> SimpleNamespace:
    """Grant the session's credits exactly once. Returns an outcome with `code`: accepted | duplicate | replay | session_not_found |
    session_mismatch | user_mismatch | ad_unit_mismatch | and every rejection reason. Only verified completions may call this."""
    now = _now(now)
    with transaction.atomic():
        s = RewardedAdSession.objects.select_for_update().select_related("rewarded_ad_offer__provider", "user") \
            .filter(unique_session_token=session_token).first()
        if s is None:
            return SimpleNamespace(code="session_not_found", session=None, entry=None, granted=False)
        if s.provider != provider:
            return SimpleNamespace(code="session_mismatch", session=s, entry=None, granted=False)
        if expected_user_id is not None and str(s.user_id) != str(expected_user_id):
            return SimpleNamespace(code="user_mismatch", session=s, entry=None, granted=False)
        if ad_unit is not None and s.ad_unit_id and s.ad_unit_id.rsplit("/", 1)[-1] != ad_unit.rsplit("/", 1)[-1]:
            return SimpleNamespace(code="ad_unit_mismatch", session=s, entry=None, granted=False)
        if s.status == S.REWARDED:                                    # a provider retry, or someone replaying a callback
            same = s.provider_transaction_id == transaction_id
            return SimpleNamespace(code="duplicate" if same else "replay", session=s, entry=None, granted=False)
        if s.status == S.REJECTED:
            return SimpleNamespace(code="rejected", session=s, entry=None, granted=False)
        if RewardedAdSession.objects.filter(provider=provider, provider_transaction_id=transaction_id).exclude(pk=s.pk).exists():
            return SimpleNamespace(code="replay", session=s, entry=None, granted=False)

        # when the user was rewarded must fall inside this session's life; delayed delivery is fine, a stale or early event is not
        if reward_at < s.created_at - CLOCK_SKEW:
            return _reject(s, "reward_before_session", now)
        if reward_at > s.expires_at:
            return _reject(s, "session_expired", now)
        if now - reward_at > timedelta(seconds=cfg.number("rewarded_ssv_max_delay_seconds") or 86400):
            return _reject(s, "callback_too_late", now)
        if not cfg.flag("rewarded_ads_test_mode") and _is_test_ad(s.ad_unit_id, ad_unit):
            return _reject(s, "test_ad_in_production", now)

        reason = _grant_time_reason(s, now, reward_at)
        if reason:
            return _reject(s, reason, now)

        entry, _created = service.grant(
            s.user, s.expected_reward_amount, UsageCreditLedger.Type.REWARDED_AD_EARNED,
            idempotency_key=f"reward:{provider}:{transaction_id}", session=s, provider_transaction_id=transaction_id,
            reason=f"Rewarded ad completed ({verification}).", feature_key="",
            expires_at=service.expiry_for(s.credit_expiry_days, now), now=now)
        s.status, s.provider_transaction_id, s.completed_at = S.REWARDED, transaction_id, now
        s.provider_verification_status = verification
        s.save(update_fields=["status", "provider_transaction_id", "completed_at", "provider_verification_status"])
        return SimpleNamespace(code="accepted", session=s, entry=entry, granted=True)


def _is_test_ad(served_unit: str, callback_unit: str | None) -> bool:
    """AdMob's callback carries only the numeric part of the unit id, so compare that against Google's known test units too."""
    test_numbers = {u.rsplit("/", 1)[-1] for u in ADMOB_TEST_UNITS.values()}
    return (is_test_identifier(served_unit or "") or is_test_identifier(callback_unit or "")
            or (callback_unit or "").rsplit("/", 1)[-1] in test_numbers)


def _grant_time_reason(s: RewardedAdSession, now, reward_at) -> str | None:
    """Switches, caps and cooldown are enforced again at the moment of granting (country rules need the request, so they apply at creation)."""
    offer = s.rewarded_ad_offer
    reason = switch_reason(s.platform)
    if reason:
        return "rewards_disabled"
    if not offer.enabled or not offer.provider.enabled:
        return "rewards_disabled"
    if verification_mode(s.provider, s.platform) is None:
        return "verification_unavailable"
    if not ent.resolve(s.user, "ads.rewarded_credits", now).enabled:
        return "not_entitled"
    if service.wallet_for(s.user).earning_suspended:
        return "earning_suspended"
    for w in WINDOWS:
        limit = getattr(offer, CLAIM_FIELDS[w])
        if limit is not None and _claims(s.user, offer, w, now) >= limit:
            return "claim_cap_reached"
    for row in earning_windows(s.user, now):
        if row["limit"] is not None and row["earned"] + s.expected_reward_amount > row["limit"]:
            return "earning_cap_reached"
    if offer.cooldown_seconds:
        last = _last_reward(s.user, offer)
        if last and reward_at < last.completed_at + timedelta(seconds=offer.cooldown_seconds):
            return "cooldown"
    return None


def attest_web_completion(session: RewardedAdSession, now=None) -> SimpleNamespace:
    """Web only, and only when an administrator explicitly accepted client attestation (Ad Manager has no server-side verification
    for web). The user must own the session, it must have been reported as started, and enough time must have passed to have watched."""
    now = _now(now)
    if verification_mode(session.provider, session.platform) != "client_attested":
        return SimpleNamespace(code="verification_unavailable", session=session, entry=None, granted=False)
    if now >= session.expires_at:                                  # a completion after expiry is never accepted
        return SimpleNamespace(code="session_expired", session=session, entry=None, granted=False)
    if session.started_at is None:
        return SimpleNamespace(code="not_started", session=session, entry=None, granted=False)
    if (now - session.started_at).total_seconds() < cfg.number("rewarded_attested_min_watch_seconds"):
        return SimpleNamespace(code="completed_too_quickly", session=session, entry=None, granted=False)
    return settle(session.unique_session_token, provider=session.provider, transaction_id=f"attested:{session.pk}",
                  reward_at=now, verification=V.CLIENT_ATTESTED, expected_user_id=str(session.user_id),
                  now=now)
