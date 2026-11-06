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
def auth_client(api, user):
    resp = api.post("/api/v1/auth/login/", {"email": user.email, "password": PASSWORD})
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
    api.refresh_token = resp.data["refresh"]
    return api


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
