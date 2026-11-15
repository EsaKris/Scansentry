"""The ONE ad-eligibility decision. Web and Android both call it through the API, so they cannot disagree, and ad-free
plans / forbidden screens are enforced on the server rather than trusted to client code."""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from apps.billing import entitlements as ent
from apps.billing.models import EntitlementOverride, Subscription

from . import settings_store as cfg
from .constants import (ADMOB_TEST_APP_ID, ADMOB_TEST_UNITS, AD_MANAGER_TEST_UNIT, ALLOWED_SURFACES, FORBIDDEN_SURFACES,
                        PLATFORMS, SPONSORED_LABEL, is_test_identifier)
from .models import AdPlacement, AdPreference

S = Subscription.Status
PUBLIC_PROVIDER_KEYS = ("app_id", "publisher_id", "network_code", "ad_client", "ad_unit_path_prefix")
CATEGORY_FLAG = {"anonymous": "ads_enabled_for_free_users", "free": "ads_enabled_for_free_users",
                 "trial": "ads_enabled_for_trial_users", "paid": "ads_enabled_for_paid_users",
                 "enterprise": "ads_enabled_for_enterprise_users"}


@dataclass
class Decision:
    eligible: bool
    reason: str
    category: str
    platform: str
    surface: str | None = None
    request_non_personalized_ads: bool = True
    test_mode: bool = True
    placements: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def categorize(user, now: datetime) -> tuple[str, str | None]:
    """anonymous | free | trial | paid | enterprise, and the effective plan slug."""
    if user is None or not getattr(user, "is_authenticated", False):
        return "anonymous", None
    sub = ent.current_subscription(user)
    if ent.has_access(sub, now):
        if sub.status == S.TRIALING:
            return "trial", sub.plan.slug
        if sub.plan.slug in cfg.get("ads_enterprise_plan_slugs"):
            return "enterprise", sub.plan.slug
        return "paid", sub.plan.slug
    plan, _s, _r = ent.effective_plan(user, now)
    temporary = EntitlementOverride.objects.filter(user=user, kind="plan_trial", revoked_at__isnull=True).exclude(expires_at__lte=now).exists()
    return ("trial" if temporary else "free"), (plan.slug if plan else None)


def is_ad_free(user, category: str, now: datetime) -> tuple[bool, str]:
    """Does the user's effective `ads.remove` entitlement remove ads?

    * a trial (or temporary premium access) never removes ads just because the PLAN includes ads.remove: trials may keep
      showing ads when the administrator allows it. Only an explicit, individual admin grant removes them for a trial user
    * explicit admin grants (override:feature / override:promotion) always count
    * plan-derived ad removal honours the `ads_remove_with_premium` switch"""
    if category == "anonymous":
        return False, ""
    e = ent.resolve(user, "ads.remove", now)
    if not e.enabled:
        return False, ""
    src = e.source
    if src in ("override:feature", "override:promotion"):
        return True, src
    if category == "trial":
        return False, src
    return (cfg.flag("ads_remove_with_premium"), src)


def _provider_public(p, test_mode: bool) -> dict:
    out = {k: v for k, v in (p.config or {}).items() if k in PUBLIC_PROVIDER_KEYS and isinstance(v, str)}
    if test_mode and p.key == "admob":
        out["app_id"] = ADMOB_TEST_APP_ID
    return out


def _unit(p: AdPlacement, test_mode: bool):
    """(ad_unit_id, adtest, usable). Test mode serves Google's official test units; production never does."""
    key = p.provider.key
    if test_mode:
        if key == "admob":
            return ADMOB_TEST_UNITS.get(p.format), False, p.format in ADMOB_TEST_UNITS
        if key == "google_ad_manager":
            return AD_MANAGER_TEST_UNIT, False, True
        return p.ad_unit_identifier, True, True                     # AdSense has no test units: the client sets adtest=on
    ident = (p.ad_unit_identifier or "").strip()
    return ident, False, bool(ident) and not is_test_identifier(ident)


def _rules_allow(p: AdPlacement, category: str, plan_slug: str | None) -> bool:
    r = p.eligible_plan_rules or {}
    cats = r.get("categories")
    if cats and category not in cats:
        return False
    if r.get("include_plans") and plan_slug not in r["include_plans"]:
        return False
    if plan_slug in (r.get("exclude_plans") or []):
        return False
    return True


def decide(user, platform: str, surface: str | None = None, now: datetime | None = None) -> Decision:
    now = now or datetime.now(timezone.utc)
    category, plan_slug = categorize(user, now)
    test_mode = cfg.flag("ads_test_mode")
    pref = AdPreference.objects.filter(user=user).first() if category != "anonymous" else None
    non_personalized = cfg.flag("ads_non_personalized_default") or (pref is not None and pref.personalized_ads is False)
    base = dict(category=category, platform=platform, surface=surface, request_non_personalized_ads=non_personalized, test_mode=test_mode)

    if platform not in PLATFORMS:
        return Decision(False, "unknown_platform", **base)
    if surface in FORBIDDEN_SURFACES:
        return Decision(False, "surface_restricted", **base)           # checked first: no setting can override it
    if surface is not None and surface not in ALLOWED_SURFACES:
        return Decision(False, "unknown_surface", **base)
    if not cfg.flag("ads_enabled"):
        return Decision(False, "ads_disabled", **base)
    if not cfg.flag(f"ads_{platform}_enabled"):
        return Decision(False, "platform_disabled", **base)
    if not cfg.flag(CATEGORY_FLAG[category]):
        return Decision(False, "category_disabled", **base)
    free_of_ads, _src = is_ad_free(user, category, now)
    if free_of_ads:
        return Decision(False, "ad_free_entitlement", **base)

    qs = AdPlacement.objects.filter(enabled=True, platform=platform, provider__enabled=True).exclude(format="rewarded") \
        .select_related("provider").order_by("surface", "key")
    if surface is not None:
        qs = qs.filter(surface=surface)
    out, skipped = [], []
    for p in qs:
        if p.surface in FORBIDDEN_SURFACES or p.surface not in ALLOWED_SURFACES:
            skipped.append((p.key, "forbidden_surface"))              # defence in depth: even a row forced into the DB is not served
            continue
        if platform not in p.provider.platforms.split(","):
            skipped.append((p.key, "provider_platform_mismatch"))
            continue
        if category == "anonymous" and not p.allow_anonymous:
            continue
        if not _rules_allow(p, category, plan_slug):
            continue
        unit, adtest, usable = _unit(p, test_mode)
        if not usable:
            skipped.append((p.key, "missing_or_test_unit_in_production"))
            continue
        freq = {**(cfg.get("ads_frequency_limits") or {}), **(p.frequency_configuration or {})}
        out.append({"key": p.key, "display_name": p.display_name, "surface": p.surface, "format": p.format,
                    "provider": p.provider.key, "provider_config": _provider_public(p.provider, test_mode),
                    "ad_unit_id": unit, "adtest": adtest, "frequency": freq, "display_rules": p.display_rules or {},
                    "label": SPONSORED_LABEL, "sponsored": True})
    if not out:
        return Decision(False, "no_placements", skipped=skipped, **base)
    return Decision(True, "ok", placements=out, skipped=skipped, **base)
