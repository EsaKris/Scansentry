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
