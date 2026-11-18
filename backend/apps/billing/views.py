from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.db.models import Count, Sum
from django.utils import timezone
from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework import generics, serializers
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny, BasePermission, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from . import admin_ops, config, service, webhooks
from .entitlements import access_until, effective_plan, has_access, resolve_all
from .models import (EntitlementOverride, PaymentTransaction, PaymentWebhookEvent, Plan, PlanFeature, Subscription)
from .providers import PLANNED, PROVIDERS, get_provider

User = get_user_model()


# ---- public ------------------------------------------------------------------------------------------------------
def plan_payload(plan: Plan, currency: str | None = None) -> dict:
    prices = [{"currency": p.currency, "amount": str(p.amount)} for p in plan.prices.all() if p.active
              and (not currency or p.currency == currency)]
    return {"name": plan.name, "slug": plan.slug, "description": plan.description, "is_free": plan.is_free,
            "billing_interval": plan.billing_interval, "trial_days": plan.trial_days, "featured": plan.featured,
            "prices": prices,
            "features": [{"key": pf.feature.key, "name": pf.feature.name, "enabled": pf.enabled, "limit": pf.limit_value}
                         for pf in plan.features.all() if pf.feature.assignable and pf.feature.active]}


class PlansView(APIView):
    """Public pricing page data. When pricing is switched off nothing is offered for purchase."""

    authentication_classes: list = []
    permission_classes = [AllowAny]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        enabled = config.pricing_enabled()
        plans = []
        if enabled:
            qs = (Plan.objects.filter(status=Plan.Status.ACTIVE, is_public=True)
                  .prefetch_related("prices", "features__feature"))
            cur = (request.query_params.get("currency") or "").upper() or None
            plans = [plan_payload(p, cur) for p in qs if p.is_free or any(
                x.active and (not cur or x.currency == cur) for x in p.prices.all())]
        resp = Response({"pricing_enabled": enabled, "purchase_enabled": enabled, "plans": plans})
        resp["Cache-Control"] = "public, max-age=60"
        return resp


class WebhookView(APIView):
    """Provider callbacks. Public by necessity; protected by signature verification."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    parser_classes: list = []
    throttle_classes: list = []

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    def post(self, request, provider):
        headers = {k[5:].lower().replace("_", "-"): v for k, v in request.META.items() if k.startswith("HTTP_")}
        status, body = webhooks.process(provider, request.body, headers)
        return Response(body, status=status)


# ---- signed-in users --------------------------------------------------------------------------------------------------
def subscription_payload(user) -> dict:
    now = timezone.now()
    plan, sub, reason = effective_plan(user, now)
    return {
        "pricing_enabled": config.pricing_enabled(),
        "effective_plan": {"slug": plan.slug, "name": plan.name, "reason": reason} if plan else None,
        "subscription": None if sub is None else {
            "status": sub.status, "plan": sub.plan.slug, "plan_name": sub.plan.name, "billing_provider": sub.billing_provider or None,
            "currency": sub.currency or None, "current_period_start": sub.current_period_start,
            "current_period_end": sub.current_period_end, "trial_ends_at": sub.trial_ends_at,
            "cancel_at_period_end": sub.cancel_at_period_end, "cancelled_at": sub.cancelled_at,
            "access_until": access_until(sub), "has_access": has_access(sub, now)},
    }


class SubscriptionView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        return Response(subscription_payload(request.user))


class EntitlementsView(APIView):
    """What this user may do. Web and Android use this same decision; the backend enforces it regardless."""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        plan, _sub, reason = effective_plan(request.user)
        ents = resolve_all(request.user)
        return Response({"plan": plan.slug if plan else None, "reason": reason,
                         "entitlements": {k: {"enabled": e.enabled, "limit": e.limit, "source": e.source} for k, e in sorted(ents.items())}})


class CheckoutSerializer(serializers.Serializer):
    plan = serializers.SlugField()
    currency = serializers.CharField(max_length=3, required=False, allow_blank=True, default="")
    provider = serializers.CharField(max_length=20, required=False, allow_blank=True, default="")
    start_trial = serializers.BooleanField(default=False)


class CheckoutView(APIView):
    """The client sends WHICH plan; it can never send a price. The amount is read from the database."""

    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "billing_checkout"

    @extend_schema(request=CheckoutSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = CheckoutSerializer(data=request.data)          # unknown fields (e.g. "amount") are ignored by design
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        if d["start_trial"]:
            sub = service.start_trial(request.user, plan_slug=d["plan"])
            return Response({"trial_started": True, **subscription_payload(request.user)})
        providers = config.enabled_providers()
        provider = d["provider"] or (providers[0] if providers else "")
        return Response(service.start_checkout(request.user, plan_slug=d["plan"], currency=d["currency"], provider_key=provider))


class VerifySerializer(serializers.Serializer):
    reference = serializers.CharField(max_length=120)


class CheckoutVerifyView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "billing_checkout"

    @extend_schema(request=VerifySerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = VerifySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        tx = service.verify_checkout(request.user, ser.validated_data["reference"])
        return Response({"reference": tx.provider_reference, "status": tx.status, **subscription_payload(request.user)})


class CancelSerializer(serializers.Serializer):
    immediately = serializers.BooleanField(default=False)


class CancelView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    @extend_schema(request=CancelSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = CancelSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        result = service.cancel_subscription(request.user, immediately=ser.validated_data["immediately"])
        return Response({**result, **subscription_payload(request.user)})


class ResumeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=None, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        service.resume_subscription(request.user)
        return Response(subscription_payload(request.user))


class TransactionSerializer(serializers.ModelSerializer):
    plan = serializers.SlugRelatedField(slug_field="slug", read_only=True)

    class Meta:
        model = PaymentTransaction
        fields = ("id", "plan", "provider", "provider_reference", "amount", "currency", "status", "payment_method",
                  "failure_reason", "paid_at", "created_at")
        read_only_fields = fields


class TransactionsView(generics.ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return PaymentTransaction.objects.none()
        return PaymentTransaction.objects.filter(user=self.request.user).select_related("plan")


# ---- administration (role-based) ---------------------------------------------------------------------------------------------
def has_billing_perm(codename: str):
    class _Perm(BasePermission):
        message = f"This action needs the '{codename}' permission."

        def has_permission(self, request, view):
            u = request.user
            return bool(u and u.is_authenticated and u.is_active and u.is_staff and (u.is_superuser or u.has_perm(f"billing.{codename}")))
    _Perm.__name__ = f"Has_{codename}"
    return _Perm


def find_user(value) -> User:
    q = {"email__iexact": value} if "@" in str(value) else {"pk": value}
    try:
        user = User.objects.filter(**q).first()
    except (ValueError, TypeError, Exception):
        user = None
    if user is None:
        raise NotFound("No such user.")
    return user


class AdminOverviewView(APIView):
    permission_classes = [has_billing_perm("view_payments")]

    @extend_schema(responses={200: OpenApiTypes.OBJECT})
    def get(self, request):
        now = timezone.now()
        by_status = {r["status"]: r["n"] for r in Subscription.objects.filter(is_current=True).values("status").annotate(n=Count("id"))}
        revenue = lambda qs: {r["currency"]: str(Decimal(r["total"]).quantize(Decimal("0.01"))) for r in qs.values("currency").annotate(total=Sum("amount"))}
        paid = PaymentTransaction.objects.filter(status=PaymentTransaction.Status.SUCCESS)
        return Response({
            "pricing_enabled": config.pricing_enabled(),
            "subscriptions_by_status": by_status,
            "revenue_all_time": revenue(paid), "revenue_last_30_days": revenue(paid.filter(paid_at__gte=now - timedelta(days=30))),
            "refunded_transactions": PaymentTransaction.objects.filter(status=PaymentTransaction.Status.REFUNDED).count(),
            "webhook_events_failed": PaymentWebhookEvent.objects.filter(processing_status="failed").count(),
            "providers": [{"key": k, "name": c.display_name, "enabled": k in config.enabled_providers(), "configured": get_provider(k).configured(),
                           "currencies": sorted(c.supported_currencies), "setup": c.note} for k, c in PROVIDERS.items()]
                         + [{"key": k, "implemented": False, "note": v} for k, v in PLANNED.items()],
            "note": "Revenue figures come from verified provider payments in our own records, not from provider dashboards.",
        })


class WebhookEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentWebhookEvent
        fields = ("id", "provider", "provider_event_id", "event_type", "processing_status", "attempts", "error_message",
                  "created_at", "processed_at")
        read_only_fields = fields


class AdminWebhookEventsView(generics.ListAPIView):
    serializer_class = WebhookEventSerializer
    permission_classes = [has_billing_perm("view_payments")]

    def get_queryset(self):
        qs = PaymentWebhookEvent.objects.all()
        st = self.request.query_params.get("status")
        return qs.filter(processing_status=st) if st else qs


class OverrideSerializer(serializers.Serializer):
    user = serializers.CharField()
    kind = serializers.ChoiceField(choices=["feature", "promotion", "plan_trial"], default="feature")
    feature = serializers.CharField(required=False)
    plan = serializers.SlugField(required=False)
    enabled = serializers.BooleanField(default=True)
    limit = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    days = serializers.IntegerField(required=False, min_value=1, max_value=3650)
    note = serializers.CharField(allow_blank=True, default="")


class AdminOverrideCreateView(APIView):
    permission_classes = [has_billing_perm("grant_entitlements")]
    parser_classes = [JSONParser]

    @extend_schema(request=OverrideSerializer, responses={201: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = OverrideSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        user = find_user(d["user"])
        if d["kind"] == "plan_trial":
            if not d.get("plan") or not d.get("days"):
                raise ValidationError({"plan": "Provide 'plan' and 'days' for temporary plan access."})
            o = admin_ops.grant_plan_access(request.user, user, d["plan"], days=d["days"], note=d["note"])
        else:
            if not d.get("feature"):
                raise ValidationError({"feature": "Provide the feature key."})
            o = admin_ops.grant_feature(request.user, user, d["feature"], enabled=d["enabled"], limit=d.get("limit"),
                                        expires_at=d.get("expires_at"), note=d["note"], kind=d["kind"])
        return Response({"id": o.id, "kind": o.kind, "user": str(user.pk), "expires_at": o.expires_at}, status=201)


class NoteSerializer(serializers.Serializer):
    note = serializers.CharField(allow_blank=True, default="")


class AdminOverrideRevokeView(APIView):
    permission_classes = [has_billing_perm("grant_entitlements")]
    parser_classes = [JSONParser]

    @extend_schema(request=NoteSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request, pk):
        ser = NoteSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        o = EntitlementOverride.objects.filter(pk=pk).select_related("user").first()
        if o is None:
            raise NotFound()
        admin_ops.revoke_override(request.user, o, note=ser.validated_data["note"])
        return Response({"id": o.id, "revoked": True})


class SubscriptionActionSerializer(serializers.Serializer):
    user = serializers.CharField()
    days = serializers.IntegerField(required=False, min_value=1, max_value=3650)
    note = serializers.CharField(allow_blank=True, default="")


class AdminSubscriptionActionView(APIView):
    permission_classes = [has_billing_perm("manage_subscriptions")]
    parser_classes = [JSONParser]
    action = ""

    @extend_schema(request=SubscriptionActionSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = SubscriptionActionSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        d = ser.validated_data
        user = find_user(d["user"])
        if self.action == "extend":
            if not d.get("days"):
                raise ValidationError({"days": "This field is required."})
            sub = admin_ops.extend_subscription(request.user, user, days=d["days"], note=d["note"])
        elif self.action == "suspend":
            sub = admin_ops.suspend_subscription(request.user, user, note=d["note"])
        else:
            sub = admin_ops.restore_subscription(request.user, user, note=d["note"])
        return Response({"status": sub.status, "current_period_end": sub.current_period_end})
