import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator

from apps.accounts import emails
from apps.audit.models import AuditLog
from tests.conftest import PASSWORD

User = get_user_model()
pytestmark = pytest.mark.django_db


def test_register_creates_user_and_sends_verification(api):
    r = api.post("/api/v1/auth/register/", {
        "email": "New@Example.com", "password": PASSWORD, "display_name": "New"})
    assert r.status_code == 201
    u = User.objects.get(email="new@example.com")
    assert not u.email_verified and u.check_password(PASSWORD)
    assert len(mail.outbox) == 1 and "verify" in mail.outbox[0].subject.lower()
    assert AuditLog.objects.filter(action="account.registered").exists()


def test_register_existing_email_does_not_reveal_account(api, user):
    new = api.post("/api/v1/auth/register/", {"email": "fresh@example.com", "password": PASSWORD})
    dup = api.post("/api/v1/auth/register/", {"email": user.email.upper(), "password": PASSWORD})
    assert dup.status_code == new.status_code == 201
    assert dup.data == new.data
    assert User.objects.filter(email__iexact=user.email).count() == 1


def test_register_rejects_weak_password(api):
    r = api.post("/api/v1/auth/register/", {"email": "x@example.com", "password": "password123"})
    assert r.status_code == 400
    assert r.data["error"]["code"] == "validation_error"


def test_login_returns_tokens_and_rejects_bad_password(api, user):
    ok = api.post("/api/v1/auth/login/", {"email": user.email, "password": PASSWORD})
    assert ok.status_code == 200 and {"access", "refresh"} <= set(ok.data)
    bad = api.post("/api/v1/auth/login/", {"email": user.email, "password": "wrong-password"})
    assert bad.status_code == 401


def test_me_requires_auth(api):
    assert api.get("/api/v1/auth/me/").status_code == 401


def test_me_get_and_patch_only_display_name(auth_client, user):
    assert auth_client.get("/api/v1/auth/me/").data["email"] == user.email
    r = auth_client.patch("/api/v1/auth/me/", {
        "display_name": "Ada L.", "is_staff": True, "email_verified": True, "email": "x@y.com"})
    assert r.status_code == 200
    user.refresh_from_db()
    assert user.display_name == "Ada L."
    assert not user.is_staff and not user.email_verified and user.email == "ada@example.com"


def test_refresh_rotates_and_logout_blacklists(auth_client, api):
    refresh = auth_client.refresh_token
    r = api.post("/api/v1/auth/token/refresh/", {"refresh": refresh})
    assert r.status_code == 200 and r.data["refresh"] != refresh
    # old refresh token is blacklisted after rotation
    assert api.post("/api/v1/auth/token/refresh/", {"refresh": refresh}).status_code == 401
    out = auth_client.post("/api/v1/auth/logout/", {"refresh": r.data["refresh"]})
    assert out.status_code == 204
    assert api.post("/api/v1/auth/token/refresh/", {"refresh": r.data["refresh"]}).status_code == 401


def test_verify_email_flow(api, user):
    token = emails.make_verification_token(user)
    assert api.post("/api/v1/auth/verify-email/", {"token": token}).status_code == 200
    user.refresh_from_db()
    assert user.email_verified
    assert api.post("/api/v1/auth/verify-email/", {"token": "garbage"}).status_code == 400


def test_verify_email_token_expires(api, user, settings):
    token = emails.make_verification_token(user)
    settings.EMAIL_VERIFICATION_MAX_AGE = -1
    assert api.post("/api/v1/auth/verify-email/", {"token": token}).status_code == 400


def test_password_reset_request_does_not_enumerate(api, user):
    known = api.post("/api/v1/auth/password-reset/", {"email": user.email})
    unknown = api.post("/api/v1/auth/password-reset/", {"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.data == unknown.data
    assert len(mail.outbox) == 1  # only the real account got an email


def test_password_reset_confirm(api, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    new_pw = "An0ther-Strong-Pass-99"
    r = api.post("/api/v1/auth/password-reset/confirm/",
                 {"uid": uid, "token": token, "new_password": new_pw})
    assert r.status_code == 200
    user.refresh_from_db()
    assert user.check_password(new_pw)
    # token is single-use (password hash changed)
    again = api.post("/api/v1/auth/password-reset/confirm/",
                     {"uid": uid, "token": token, "new_password": "Yet-Another-Pass-11"})
    assert again.status_code == 400


def test_password_reset_confirm_rejects_bad_token_and_weak_password(api, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    assert api.post("/api/v1/auth/password-reset/confirm/",
                    {"uid": uid, "token": "bad", "new_password": PASSWORD}).status_code == 400
    token = default_token_generator.make_token(user)
    weak = api.post("/api/v1/auth/password-reset/confirm/",
                    {"uid": uid, "token": token, "new_password": "12345"})
    assert weak.status_code == 400


def test_deletion_request_is_recorded_and_audited(auth_client, user):
    r = auth_client.post("/api/v1/auth/me/deletion-request/")
    assert r.status_code == 202
    user.refresh_from_db()
    assert user.deletion_requested_at is not None
    assert AuditLog.objects.filter(action="account.deletion_requested").count() == 1


def test_login_is_rate_limited(api, user, monkeypatch):
    from rest_framework.throttling import ScopedRateThrottle
    from django.core.cache import cache
    cache.clear()
    monkeypatch.setitem(ScopedRateThrottle.THROTTLE_RATES, "auth_login", "3/min")
    codes = [api.post("/api/v1/auth/login/", {"email": user.email, "password": "nope-nope-nope"}).status_code
             for _ in range(5)]
    assert 429 in codes
