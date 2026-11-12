import pytest

from apps.core.config import get_config
from apps.core.models import AppConfiguration
from apps.organizations.models import Organization, OrganizationMembership
from django.db import IntegrityError, transaction

pytestmark = pytest.mark.django_db


def test_health(api):
    r = api.get("/api/v1/health/")
    assert r.status_code == 200 and r.data["database"] == "ok"


def test_public_config_exposes_only_public_rows(api):
    AppConfiguration.objects.create(key="brand_color", value="#0B1F3A", is_public=True)
    AppConfiguration.objects.create(key="internal_note", value="secret", is_public=False)
    r = api.get("/api/v1/config/")
    assert r.data == {"pricing_enabled": False, "brand_color": "#0B1F3A"}      # pricing starts switched off (seeded)


def test_get_config_default_and_wrapped_value():
    assert get_config("missing", 5) == 5
    AppConfiguration.objects.create(key="ads_enabled", value={"value": True})
    assert get_config("ads_enabled") is True


def test_membership_is_unique(user):
    org = Organization.objects.create(name="Acme", slug="acme", owner=user)
    OrganizationMembership.objects.create(organization=org, user=user, role="owner")
    with pytest.raises(IntegrityError), transaction.atomic():
        OrganizationMembership.objects.create(organization=org, user=user)


def test_unknown_route_returns_structured_error(api):
    r = api.get("/api/v1/auth/me/", HTTP_AUTHORIZATION="Bearer nonsense")
    assert r.status_code == 401
    assert r.data["error"]["message"]


def test_openapi_schema_generates(api):
    r = api.get("/api/v1/schema/")
    assert r.status_code == 200
