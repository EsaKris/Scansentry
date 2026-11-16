import logging
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Count, Sum
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema, extend_schema_field
from rest_framework import serializers, status
from rest_framework.exceptions import APIException, NotFound, ValidationError
from rest_framework.generics import ListAPIView, get_object_or_404
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.analytics import usage
from apps.audit.services import record_audit

from . import config as cfg
from . import limits, rewarded, service, verifiers
from .models import RewardCallbackEvent, RewardedAdSession, UsageCreditLedger, UsageCreditWallet

log = logging.getLogger(__name__)
User = get_user_model()
S = RewardedAdSession.Status
T = UsageCreditLedger.Type
PLATFORMS = ("web", "android")


# ---- errors --------------------------------------------------------------------------------------------------------------
class RewardUnavailable(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "reward_unavailable"
    default_detail = "A rewarded ad is not available right now. You can still wait for your allowance to reset or view plans."

    def __init__(self, reason: str, extra: dict | None = None):
        super().__init__(self.default_detail, code=reason)
        self.extra = {"reason": reason, **(extra or {})}


class InvalidCallback(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "invalid_callback"


class MalformedCallback(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "malformed_callback"


class VerificationUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_code = "verification_unavailable"
    default_detail = "The provider's verification keys are temporarily unavailable. Please retry."


class RewardSessionThrottle(UserRateThrottle):
    scope = "reward_session"


class RewardCallbackThrottle(AnonRateThrottle):
    scope = "reward_callback"


def _platform(request) -> str:
    platform = (request.query_params.get("platform") or (request.data.get("platform") if hasattr(request.data, "get") else "") or "").lower()
    if platform not in PLATFORMS:
        raise ValidationError({"platform": f"Use one of: {', '.join(PLATFORMS)}."})
    return platform


# ---- wallet ---------------------------------------------------------------------------------------------------------------
NOTE = "ScanSentry Credits have no cash value and cannot be withdrawn, transferred, sold or used to buy subscriptions."


class BalanceView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        now = timezone.now()
        body = service.summary(request.user, now)
        body["earning_limits"] = rewarded.earning_windows(request.user, now)
        body["note"] = NOTE
        resp = Response(body)
        resp["Cache-Control"] = "private, no-store"
        return resp


class CreditHistorySerializer(serializers.ModelSerializer):
    type = serializers.CharField(source="transaction_type")
    expires_at = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.DATETIME)
    def get_expires_at(self, obj):
        lot = getattr(obj, "lot", None)
        return lot.expires_at if lot is not None else None

    class Meta:
        model = UsageCreditLedger
        fields = ("id", "type", "amount", "balance_after", "feature_key", "reason", "expires_at", "created_at")


class HistoryView(ListAPIView):
    """The signed-in user's own credit movements, newest first. `?type=` filters."""

    serializer_class = CreditHistorySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return UsageCreditLedger.objects.none()
        qs = UsageCreditLedger.objects.filter(user=self.request.user).select_related("lot")
        t = self.request.query_params.get("type")
        return qs.filter(transaction_type=t) if t else qs


class LimitScreenView(APIView):
    """Everything a client needs for its 'limit reached' screen. Anyone can ask; it never spends or grants anything."""

    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=[OpenApiParameter("feature", OpenApiTypes.STR, required=True),
                               OpenApiParameter("platform", OpenApiTypes.STR, enum=list(PLATFORMS))], responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        feature = request.query_params.get("feature", "")
        if feature not in usage.METERED:
            raise ValidationError({"feature": f"Use one of: {', '.join(sorted(usage.METERED))}."})
        platform = (request.query_params.get("platform") or "").lower() or None
        if platform and platform not in PLATFORMS:
            raise ValidationError({"platform": f"Use one of: {', '.join(PLATFORMS)}."})
        resp = Response(limits.limit_screen(request.user, feature, platform=platform, country=rewarded.country_of(request)))
        resp["Cache-Control"] = "private, no-store"
        return resp


# ---- rewarded ads ---------------------------------------------------------------------------------------------------------
class OffersView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(parameters=[OpenApiParameter("platform", OpenApiTypes.STR, enum=list(PLATFORMS), required=True)],
                   responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        platform = _platform(request)
        now = timezone.now()
        reason = rewarded.switch_reason(platform)
        resp = Response({"platform": platform, "enabled": reason is None, "reason": reason,
                         "offers": [] if reason else rewarded.list_offers(request.user, platform, rewarded.country_of(request), now),
                         "earning_limits": rewarded.earning_windows(request.user, now), "terms": rewarded.TERMS,
                         "balance": service.balance_of(request.user, now)})
        resp["Cache-Control"] = "private, no-store"
        return resp


class SessionCreateSerializer(serializers.Serializer):
    offer = serializers.UUIDField()
    platform = serializers.ChoiceField(choices=PLATFORMS)


class SessionsView(APIView):
    """Create a short-lived, single-use rewarded-ad session. The user must opt in: nothing plays automatically."""

    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    throttle_classes = [RewardSessionThrottle]

    @extend_schema(request=SessionCreateSerializer, responses={201: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = SessionCreateSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            session, instructions = rewarded.create_session(request.user, ser.validated_data["offer"], ser.validated_data["platform"],
                                                            rewarded.country_of(request))
        except rewarded.RewardNotAvailable as exc:
            raise RewardUnavailable(exc.reason)
        return Response({**rewarded.session_payload(session, include_token=True), "client": instructions,
                         "reminder": rewarded.TERMS}, status=status.HTTP_201_CREATED)


def _own_session(request, pk) -> RewardedAdSession:
    return get_object_or_404(RewardedAdSession, pk=pk, user=request.user)


class SessionDetailView(APIView):
    """Poll this after the ad: credits appear once the provider's verified completion has been processed."""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request, pk):
        session = _own_session(request, pk)
        session = rewarded.expire_if_due(session)
        resp = Response({**rewarded.session_payload(session), "balance": service.balance_of(request.user)})
        resp["Cache-Control"] = "private, no-store"
        return resp


class EventSerializer(serializers.Serializer):
    event = serializers.ChoiceField(choices=sorted(rewarded.CLIENT_EVENTS))


class SessionEventView(APIView):
    """Client-reported progress (ad loaded / started / closed / no fill ...). It can NEVER grant credits."""

    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    @extend_schema(request=EventSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request, pk):
        ser = EventSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        session = rewarded.record_event(_own_session(request, pk), ser.validated_data["event"])
        return Response(rewarded.session_payload(session))


class SessionCompleteView(APIView):
    """WEB ONLY, DISABLED BY DEFAULT. Google Ad Manager has no server-side verification for web rewarded ads, so a completion can
    only be client-attested. It works only when an administrator enabled `rewarded_web_client_attested_enabled`, and still needs a
    started session of your own, a plausible watch time, caps and cooldown. Android rewards never use this endpoint."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [RewardSessionThrottle]

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    def post(self, request, pk):
        session = _own_session(request, pk)
        outcome = rewarded.attest_web_completion(session)
        session.refresh_from_db()
        RewardCallbackEvent.objects.create(provider=session.provider, outcome=f"attested_{outcome.code}", session=session,
                                           provider_transaction_id=f"attested:{session.pk}")
        if outcome.code in ("verification_unavailable",):
            raise RewardUnavailable("verification_unavailable", {"message": "This platform's rewarded ads cannot be verified by the server."})
        return Response({**rewarded.session_payload(session), "outcome": outcome.code, "balance": service.balance_of(request.user)})


class CallbackView(APIView):
    """Provider reward callbacks. Authenticity is the provider's signature, not a login: forged, tampered, expired, duplicated and
    replayed callbacks never issue credits. AdMob sends a GET; POST is accepted for providers that post. 200 = handled (do not retry),
    403 = bad signature, 400 = malformed, 503 = verification keys unavailable (retry)."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_classes = [RewardCallbackThrottle]
    http_method_names = ["get", "post", "head", "options"]

    @extend_schema(parameters=[OpenApiParameter("provider", OpenApiTypes.STR, OpenApiParameter.PATH)], responses={200: OpenApiTypes.OBJECT})
    def get(self, request, provider):
        return self._handle(request, provider)

    @extend_schema(parameters=[OpenApiParameter("provider", OpenApiTypes.STR, OpenApiParameter.PATH)], request=None,
                   responses={200: OpenApiTypes.OBJECT})
    def post(self, request, provider):
        return self._handle(request, provider)

    def _handle(self, request, provider):
        verify = verifiers.VERIFIERS.get(provider)
        if verify is None:
            raise NotFound("This provider does not send verifiable reward callbacks. "
                           "Google Ad Manager web rewarded ads have no server-side verification (use the session 'complete' flow if enabled).")
        try:
            claim = verify(request.META.get("QUERY_STRING", ""))
        except verifiers.VerificationFailure as exc:
            RewardCallbackEvent.objects.create(provider=provider, outcome=exc.code)
            if exc.transient:
                raise VerificationUnavailable()
            if exc.code == "malformed":
                raise MalformedCallback("The callback is malformed.")
            raise InvalidCallback("The callback signature could not be verified.")
        outcome = rewarded.settle(claim.session_token, provider=provider, transaction_id=claim.transaction_id, reward_at=claim.reward_at,
                                  verification=RewardedAdSession.Verification.VERIFIED, expected_user_id=claim.user_id, ad_unit=claim.ad_unit)
        RewardCallbackEvent.objects.create(provider=provider, outcome=outcome.code, session=outcome.session,
                                           provider_transaction_id=claim.transaction_id[:200])
        if outcome.code == "accepted":
            log.info("reward granted: session %s", outcome.session.pk)
        # 200 for every handled outcome (even a refusal): the provider must not keep retrying something retrying cannot fix
        return Response({"status": outcome.code if outcome.code in ("accepted", "duplicate") else "rejected", "code": outcome.code})


# ---- administration -------------------------------------------------------------------------------------------------------
class CanManageCredits(BasePermission):
    message = "This action needs the 'manage_credits' permission."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_active and u.is_staff and (u.is_superuser or u.has_perm("credits.manage_credits")))


class CanViewCreditReports(BasePermission):
    message = "This action needs the 'view_credit_reports' permission."

    def has_permission(self, request, view):
        u = request.user
        return bool(u and u.is_authenticated and u.is_active and u.is_staff and (
            u.is_superuser or u.has_perm("credits.view_credit_reports") or u.has_perm("credits.manage_credits")))


class AdminOverviewView(APIView):
    permission_classes = [CanViewCreditReports]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        now = timezone.now()
        since = now - timedelta(days=30)
        sums = dict(UsageCreditLedger.objects.values_list("transaction_type").annotate(s=Sum("amount")))
        threshold = cfg.number("rewarded_abuse_daily_threshold")
        flagged = (RewardedAdSession.objects.filter(status=S.REWARDED, completed_at__gte=now - timedelta(days=1))
                   .values("user__email").annotate(n=Count("id")).filter(n__gt=threshold).order_by("-n")[:25])
        warnings = []
        if cfg.flag("rewarded_ads_test_mode"):
            warnings.append("Rewarded ads are in TEST mode: Google's test units are used and test-unit callbacks are accepted.")
        if cfg.flag("rewarded_web_client_attested_enabled"):
            warnings.append("Web rewards are CLIENT-ATTESTED, not provider-verified (Ad Manager has no web server-side verification). "
                            "They can be farmed by a determined user; keep caps and cooldowns tight.")
        recon = service.reconcile()
        if not recon["consistent"]:
            warnings.append("The credit ledger, wallets and lots DISAGREE. Investigate before issuing more credits.")
        return Response({
            "switches": {k: cfg.get(k) for k in cfg.DEFAULTS},
            "credits": {"issued_from_rewarded_ads": sums.get(T.REWARDED_AD_EARNED, 0),
                        "issued_other": sums.get(T.PROMOTIONAL_CREDIT, 0) + sums.get(T.ADMIN_GRANT, 0) + sums.get(T.USAGE_REFUND, 0),
                        "spent": -sums.get(T.FEATURE_USAGE, 0), "expired": -sums.get(T.CREDIT_EXPIRY, 0),
                        "removed_by_administrators": -sums.get(T.ADMIN_REVERSAL, 0),
                        "outstanding": UsageCreditWallet.objects.aggregate(s=Sum("available_balance"))["s"] or 0,
                        "reconciliation": recon},
            "rewarded_sessions_30d": dict(RewardedAdSession.objects.filter(created_at__gte=since).values_list("status").annotate(n=Count("id"))),
            "callbacks_30d": dict(RewardCallbackEvent.objects.filter(received_at__gte=since).values_list("outcome").annotate(n=Count("id"))),
            "rewards_by_verification_30d": dict(RewardedAdSession.objects.filter(status=S.REWARDED, completed_at__gte=since)
                                                .values_list("provider_verification_status").annotate(n=Count("id"))),
            "unusual_reward_patterns": [{"user": r["user__email"], "rewards_last_24h": r["n"]} for r in flagged],
            "warnings": warnings})


class AdjustSerializer(serializers.Serializer):
    user = serializers.CharField(max_length=254, help_text="User email or id")
    kind = serializers.ChoiceField(choices=["grant", "promotional", "reversal"])
    amount = serializers.IntegerField(min_value=1, max_value=1_000_000, help_text="Always positive; a reversal removes this many")
    reason = serializers.CharField(min_length=5, max_length=300, help_text="Internal note, required")
    expires_in_days = serializers.IntegerField(required=False, min_value=1, max_value=3650)
    request_id = serializers.UUIDField(required=False, help_text="Send the same id when retrying so the adjustment is applied once")


class AdminAdjustView(APIView):
    """Audited administrator grant / promotional credit / reversal. Needs a reason; never edits history, it appends to the ledger."""

    permission_classes = [CanManageCredits]
    parser_classes = [JSONParser]

    @extend_schema(request=AdjustSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = AdjustSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        q = {"email__iexact": d["user"]} if "@" in d["user"] else {"pk": d["user"]}
        try:
            target = User.objects.filter(**q).first()
        except Exception:
            target = None
        if target is None:
            raise NotFound("No such user.")
        now = timezone.now()
        before = service.balance_of(target, now)
        key = f"admin:{d.get('request_id') or uuid.uuid4()}"
        try:
            if d["kind"] == "reversal":
                entry = service.debit(target, d["amount"], T.ADMIN_REVERSAL, idempotency_key=key, reason=d["reason"], now=now)
                created = True
            else:
                entry, created = service.grant(
                    target, d["amount"], T.ADMIN_GRANT if d["kind"] == "grant" else T.PROMOTIONAL_CREDIT, idempotency_key=key,
                    reason=d["reason"], expires_at=service.expiry_for(d.get("expires_in_days"), now), now=now)
        except service.InsufficientCredits:
            raise ValidationError({"amount": "The user does not have that many credits to reverse."})
        except service.IdempotencyConflict:
            raise ValidationError({"request_id": "This request id was already used for a different adjustment."})
        after = service.balance_of(target, now)
        if created:
            record_audit(actor=request.user, action=f"credits.admin_{d['kind']}", obj=entry,
                         before={"balance": before}, after={"balance": after, "amount": entry.amount, "user": str(target.pk), "reason": d["reason"]})
        return Response({"entry": str(entry.pk), "applied": created, "balance_before": before, "balance_after": after})
