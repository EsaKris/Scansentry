import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

PASSWORD = "Str0ng-Passphrase-42"


@pytest.fixture
def api():
    return APIClient()


@pytest.fixture
def user(db):
    return get_user_model().objects.create_user(
        email="ada@example.com", password=PASSWORD, display_name="Ada"
    )


@pytest.fixture
def auth_client(user):
    """A separate client from `api`, so tests using both really have one signed-in and one anonymous caller."""
    client = APIClient()
    resp = client.post("/api/v1/auth/login/", {"email": user.email, "password": PASSWORD})
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
    client.refresh_token = resp.data["refresh"]
    return client


@pytest.fixture
def other_user(db):
    return get_user_model().objects.create_user(
        email="grace@example.com", password=PASSWORD, display_name="Grace")


@pytest.fixture
def other_client(other_user):
    c = APIClient()
    resp = c.post("/api/v1/auth/login/", {"email": other_user.email, "password": PASSWORD})
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
    return c


@pytest.fixture(autouse=True)
def _media(settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path / "media"


def make_qr(client, **overrides):
    body = {"name": "Menu", "qr_type": "url", "code_mode": "dynamic",
            "data": {"url": "https://example.com/menu"}}
    body.update(overrides)
    return client.post("/api/v1/qr/", body, format="json")


# ---- shared fake-internet environment for domain / security tests ------------------------------------------
@pytest.fixture
def senv(monkeypatch, tmp_path):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    from django.core.cache import cache

    from apps.domain_intel import service as domain_service
    from apps.domain_intel.rdap import parse_rdap_domain
    from tests.netfakes import World, http_response
    from tests.test_domain_unit import SAMPLE

    cache.clear()
    w = World(tmp_path)
    monkeypatch.setattr(domain_service, "build_dns_client", lambda: w.dns)
    monkeypatch.setattr(domain_service, "build_guard", lambda dns=None: w.guard)
    state = {"result": None, "flags": None}

    def rdap_result(flags=None):
        now = datetime.now(timezone.utc)
        data = parse_rdap_domain({**SAMPLE, **({"status": flags} if flags else {})}, now=now)
        return {"ok": True, "status": data["status"], "data": data, "source": "https://rdap.test/domain/x",
                "error": None, "observed_at": now.isoformat()}

    monkeypatch.setattr(domain_service, "lookup_rdap",
                        lambda reg, tld, guard, now=None: state["result"] or rdap_result(state["flags"]))

    def publish(host, ip="93.184.216.34", body="<h1>site</h1>", status=200):
        w.site(host, ip, https=lambda r: http_response(status, body))
        w.dns.set(host, "NS", ["a.ns.example.net.", "b.ns.example.net."])
        return w

    return SimpleNamespace(world=w, rdap_state=state, publish=publish, domain_service=domain_service)


def enable_provider(key, **fields):
    from apps.threat_intel.models import ThreatProvider
    ThreatProvider.objects.filter(key=key).update(enabled=True, **fields)


# ---- billing fixtures ----------------------------------------------------------------------------------------------
@pytest.fixture
def pricing(db):
    """Pricing switched ON (the product owner flipping the master switch)."""
    from apps.core.models import AppConfiguration
    AppConfiguration.objects.update_or_create(key="pricing_enabled", defaults={"value": True, "is_public": True})


@pytest.fixture
def pay_settings(settings):
    settings.PAYSTACK_SECRET_KEY = "sk_test_secret"
    settings.FLUTTERWAVE_SECRET_KEY = "flw_test_secret"
    settings.FLUTTERWAVE_WEBHOOK_HASH = "fw-hash-123"
    settings.FRONTEND_URL = "https://app.scansentry.test"
    return settings


def make_plan(slug, name, *, ngn=None, usd=None, interval="month", trial=0, grace=0, order=1, features=None, **kw):
    from apps.billing.models import FeatureDefinition, Plan, PlanFeature, PlanPrice
    plan = Plan.objects.create(slug=slug, name=name, billing_interval=interval, trial_days=trial, grace_period_days=grace,
                               display_order=order, is_free=kw.pop("is_free", ngn is None and usd is None), **kw)
    if ngn is not None:
        PlanPrice.objects.create(plan=plan, currency="NGN", amount=ngn)
    if usd is not None:
        PlanPrice.objects.create(plan=plan, currency="USD", amount=usd)
    for key, (enabled, limit) in (features or {}).items():
        PlanFeature.objects.create(plan=plan, feature=FeatureDefinition.objects.get(key=key), enabled=enabled, limit_value=limit)
    return plan


@pytest.fixture
def plans(db):
    from types import SimpleNamespace
    from apps.billing.models import FeatureDefinition, Plan, PlanFeature
    free = Plan.objects.get(slug="free")
    PlanFeature.objects.create(plan=free, feature=FeatureDefinition.objects.get(key="qr.dynamic.active_limit"), enabled=True, limit_value=3)
    starter = make_plan("starter", "Starter", ngn="2000.00", usd="2.00", order=1, grace=2,
                        features={"qr.dynamic.active_limit": (True, 10)})
    pro = make_plan("pro", "Pro", ngn="5000.00", usd="5.00", order=2, trial=7, grace=3,
                    features={"qr.dynamic.active_limit": (True, 100), "ads.remove": (True, None), "qr.pdf_export": (True, None)})
    return SimpleNamespace(free=free, starter=starter, pro=pro)


@pytest.fixture
def ps(senv, pay_settings):
    from tests.billing_sim import PaystackSim
    return PaystackSim(senv)
