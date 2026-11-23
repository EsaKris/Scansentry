"""Account deletion (anonymisation) and personal-data export."""
import io
import json
from datetime import timedelta
from decimal import Decimal

import pytest
from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.utils import timezone
from PIL import Image
from rest_framework.test import APIClient

from apps.accounts import deletion, export
from apps.audit.models import AuditLog
from apps.credits import service
from apps.credits.models import UsageCreditLedger
from tests.conftest import PASSWORD, make_plan, make_qr, set_config
from tests.test_advertising import sub_for

pytestmark = pytest.mark.django_db
User = get_user_model()
EMAIL, NAME = "erase.me.please@example.com", "Erase Me Please"
ME = "/api/v1/auth/me/deletion-request/"
EXPORT = "/api/v1/auth/me/export/"


def png() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), "navy").save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture
def person(db, senv):
    """A user with data in most of the places the product keeps it, plus a client signed in as them."""
    from apps.abuse_reports.models import AbuseReport
    from apps.advertising.models import AdPreference
    from apps.billing.models import EntitlementOverride, FeatureDefinition, PaymentTransaction
    from apps.notifications.models import Notification
    u = User.objects.create_user(email=EMAIL, password=PASSWORD, display_name=NAME, email_verified=True)
    c = APIClient()
    tokens = c.post("/api/v1/auth/login/", {"email": EMAIL, "password": PASSWORD}, format="json").data
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
    qr = make_qr(c).data
    from apps.qr_codes.models import QRCode
    q = QRCode.objects.get(pk=qr["id"])
    q.logo.save("logo.png", ContentFile(png()), save=True)
    Notification.objects.create(user=u, kind="qr.disabled", severity="info", title="Your code was paused", body="Paused.")
    senv.publish("shop.com")
    c.post("/api/v1/domains/analyze/", {"value": "shop.com"}, format="json")
    PaymentTransaction.objects.create(user=u, provider="paystack", provider_reference="ref-keep-1", amount=Decimal("5000.00"), currency="NGN", status="success")
    service.grant(u, 9, UsageCreditLedger.Type.ADMIN_GRANT, idempotency_key="gift", reason="welcome")
    AdPreference.objects.create(user=u, personalized_ads=False)
    AbuseReport.objects.create(reporter=u, submitted_url="https://bad.example/x", category="suspicious_qr", description="looks fake",
                               reviewer_notes="STAFF-ONLY NOTE", reporter_hash="HASHVALUE123", target_key="https://bad.example")
    EntitlementOverride.objects.create(user=u, kind="feature", feature=FeatureDefinition.objects.get(key="qr.svg_export"), enabled=True, note="STAFF OVERRIDE NOTE")
    return u, c, tokens, q


def age(user, days):
    User.objects.filter(pk=user.pk).update(deletion_requested_at=timezone.now() - timedelta(days=days))
    user.refresh_from_db()


def whole_database_text(needles):
    """Every value in every column of every table, so a leftover copy of personal data anywhere is found."""
    hits = []
    for model in apps.get_models():
        for row in model.objects.all().values():
            blob = json.dumps(row, default=str).lower()
            hits += [(model._meta.label, n) for n in needles if n.lower() in blob]
    return hits


# ---- request / status / cancel ---------------------------------------------------------------------------------------------------
def test_requesting_deletion_returns_the_schedule_and_what_will_happen(person):
    u, c, *_ = person
    r = c.post(ME)
    assert r.status_code == 202 and r.data["requested"] is True and r.data["grace_days"] == 14 and r.data["can_cancel"] is True
    assert r.data["scheduled_for"] is not None and any("stop working" in n for n in r.data["notes"])
    assert AuditLog.objects.filter(action="account.deletion_requested", actor=u).count() == 1


def test_requesting_twice_does_not_restart_the_clock(person):
    u, c, *_ = person
    c.post(ME)
    first = User.objects.get(pk=u.pk).deletion_requested_at
    c.post(ME)
    assert User.objects.get(pk=u.pk).deletion_requested_at == first
    assert AuditLog.objects.filter(action="account.deletion_requested").count() == 1


def test_status_shows_nothing_pending_by_default(person):
    _, c, *_ = person
    r = c.get(ME)
    assert r.status_code == 200 and r.data["requested"] is False and r.data["scheduled_for"] is None


def test_a_request_can_be_cancelled_and_nothing_is_erased(person):
    u, c, *_ = person
    c.post(ME)
    r = c.delete(ME)
    assert r.status_code == 200 and r.data["requested"] is False
    age(u, 0)
    assert deletion.process_due()["anonymized"] == 0
    assert AuditLog.objects.filter(action="account.deletion_cancelled", actor=u).count() == 1
    assert User.objects.get(pk=u.pk).is_active


def test_the_grace_period_is_configurable(person):
    u, c, *_ = person
    set_config("account.deletion_grace_days", 3)
    assert c.post(ME).data["grace_days"] == 3
    age(u, 4)
    assert deletion.process_due()["anonymized"] == 1


def test_deletion_endpoints_need_a_login(api):
    assert api.post(ME).status_code == 401 and api.get(ME).status_code == 401 and api.delete(ME).status_code == 401


def test_nothing_is_erased_before_the_grace_period_ends(person):
    u, c, *_ = person
    c.post(ME)
    age(u, 13)
    assert deletion.process_due()["anonymized"] == 0
    assert User.objects.get(pk=u.pk).email == EMAIL


# ---- the erasure itself ------------------------------------------------------------------------------------------------------------
def test_erasure_leaves_an_anonymous_tombstone(person):
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    assert deletion.process_due() == {"anonymized": 1, "deferred": []}
    t = User.objects.get(pk=u.pk)
    assert t.email.endswith("@deleted.invalid") and EMAIL not in t.email and t.display_name == "" and t.anonymized_at is not None
    assert not t.is_active and not t.is_staff and not t.has_usable_password() and not t.email_verified


def test_no_personal_data_remains_anywhere_in_the_database(person):
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    assert whole_database_text([EMAIL, "erase.me.please", NAME, "Erase Me"]) == []


def test_the_erased_person_can_no_longer_sign_in_or_use_old_tokens(person, api):
    u, c, tokens, _ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    assert api.post("/api/v1/auth/login/", {"email": EMAIL, "password": PASSWORD}, format="json").status_code in (400, 401)
    assert api.post("/api/v1/auth/token/refresh/", {"refresh": tokens["refresh"]}, format="json").status_code in (400, 401)
    assert c.get("/api/v1/auth/me/").status_code in (401, 403)


def test_the_email_address_becomes_available_again(person, api):
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    r = api.post("/api/v1/auth/register/", {"email": EMAIL, "password": "Another-Strong-pass-77!", "display_name": "New Me"}, format="json")
    assert r.status_code == 201


def test_qr_codes_and_their_files_are_removed_and_the_printed_code_stops_resolving(person, api):
    from apps.qr_codes.models import QRCode
    u, c, _, q = person
    token, logo = q.public_token, q.logo.name
    assert default_storage.exists(logo)
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    assert not QRCode.objects.filter(owner=u).exists() and not default_storage.exists(logo)
    assert api.get(f"/api/v1/scanner/verify/{token}/").status_code == 404


def test_personal_records_are_deleted(person):
    from apps.advertising.models import AdPreference
    from apps.billing.models import EntitlementOverride
    from apps.credits.models import UsageCreditWallet
    from apps.domain_intel.models import DomainLookup
    from apps.notifications.models import Notification
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    for model in (Notification, DomainLookup, AdPreference, EntitlementOverride, UsageCreditLedger, UsageCreditWallet):
        assert not model.objects.filter(user=u).exists(), model


def test_payment_records_are_kept_without_personal_details(person):
    from apps.billing.models import PaymentTransaction
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    p = PaymentTransaction.objects.get(provider_reference="ref-keep-1")
    assert p.amount == Decimal("5000.00") and p.user_id == u.pk and p.user.email.endswith("@deleted.invalid")


def test_abuse_reports_stay_for_moderation_but_lose_their_author(person):
    from apps.abuse_reports.models import AbuseReport
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    r = AbuseReport.objects.get(submitted_url="https://bad.example/x")
    assert r.reporter_id is None and r.category == "suspicious_qr"


def test_erasure_is_audited_without_personal_data(person):
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    log = AuditLog.objects.get(action="account.anonymized")
    assert log.object_id == str(u.pk) and EMAIL not in json.dumps(log.after_state or {})


def test_running_the_job_again_changes_nothing(person):
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    assert deletion.process_due()["anonymized"] == 1
    assert deletion.process_due() == {"anonymized": 0, "deferred": []}
    assert AuditLog.objects.filter(action="account.anonymized").count() == 1


def test_other_peoples_data_is_untouched(person, other_user, other_client):
    from apps.qr_codes.models import QRCode
    u, c, *_ = person
    mine = make_qr(other_client).data["id"]
    service.grant(other_user, 4, UsageCreditLedger.Type.ADMIN_GRANT, idempotency_key="theirs")
    c.post(ME)
    age(u, 15)
    deletion.process_due()
    assert QRCode.objects.filter(pk=mine).exists() and service.balance_of(other_user) == 4 and User.objects.get(pk=other_user.pk).is_active


# ---- things that must NOT be erased automatically ---------------------------------------------------------------------------------------
def test_a_paid_period_is_honoured_then_the_account_is_erased(person):
    from apps.billing.models import Subscription
    u, c, *_ = person
    plan = make_plan("pro", "Pro", ngn="5000.00")
    sub = sub_for(u, plan)
    c.post(ME)
    age(u, 15)
    s = deletion.process_due()
    assert s["anonymized"] == 0 and s["deferred"][0]["reasons"][0].startswith("paid_access_until")
    sub.refresh_from_db()
    assert sub.cancel_at_period_end is True                                   # renewal stopped now
    assert User.objects.get(pk=u.pk).anonymized_at is None
    later = timezone.now() + timedelta(days=40)
    assert deletion.process_due(later)["anonymized"] == 1
    assert Subscription.objects.filter(user=u).exists()                       # history kept for accounting


def test_staff_accounts_are_never_erased_automatically(person):
    u, c, *_ = person
    User.objects.filter(pk=u.pk).update(is_staff=True)
    c.post(ME)
    age(u, 15)
    s = deletion.process_due()
    assert s["anonymized"] == 0 and s["deferred"][0]["reasons"][0].startswith("staff_account")


def test_an_organisation_owner_with_members_must_transfer_first(person, other_user):
    from apps.organizations.models import Organization, OrganizationMembership
    u, c, *_ = person
    org = Organization.objects.create(name="Acme", slug="acme", owner=u)
    OrganizationMembership.objects.create(organization=org, user=u, role="owner", status="active")
    OrganizationMembership.objects.create(organization=org, user=other_user, role="member", status="active")
    c.post(ME)
    age(u, 15)
    s = deletion.process_due()
    assert s["anonymized"] == 0 and "owns_organization_with_members" in s["deferred"][0]["reasons"][0]
    assert Organization.objects.filter(pk=org.pk).exists()


def test_a_sole_member_organisation_is_deleted_with_its_owner(person):
    from apps.organizations.models import Organization, OrganizationMembership
    u, c, *_ = person
    org = Organization.objects.create(name="Solo", slug="solo", owner=u)
    OrganizationMembership.objects.create(organization=org, user=u, role="owner", status="active")
    c.post(ME)
    age(u, 15)
    assert deletion.process_due()["anonymized"] == 1 and not Organization.objects.filter(pk=org.pk).exists()


def test_the_management_command_reports_what_it_did(person, capsys):
    from django.core.management import call_command
    u, c, *_ = person
    c.post(ME)
    age(u, 15)
    call_command("process_account_deletions")
    assert "Anonymised 1 account(s); deferred 0." in capsys.readouterr().out


# ---- the safety net: every relation to a user must be decided -------------------------------------------------------------------------------
def test_every_model_that_points_at_a_user_has_a_deletion_decision():
    missing = deletion.user_relations() - set(deletion.POLICY)
    assert not missing, f"Decide what account deletion does with: {sorted(missing)} (add to apps/accounts/deletion.py POLICY)"


def test_the_policy_has_no_stale_entries():
    assert not set(deletion.POLICY) - deletion.user_relations()


def test_every_policy_value_is_a_known_decision():
    assert set(deletion.POLICY.values()) <= {"delete", "keep", "detach", "via_parent", "staff"}


# ---- data export ----------------------------------------------------------------------------------------------------------------------
def export_json(c, password=PASSWORD):
    return c.post(EXPORT, {"password": password}, format="json")


def test_export_needs_a_login_and_the_password(person, api):
    _, c, *_ = person
    assert api.post(EXPORT, {"password": PASSWORD}, format="json").status_code == 401
    assert c.post(EXPORT, {}, format="json").status_code == 400
    wrong = export_json(c, "not-the-password")
    assert wrong.status_code == 403 and "account" not in wrong.data and EMAIL not in json.dumps(wrong.data)


def test_export_contains_the_users_own_data(person):
    u, c, _, q = person
    d = export_json(c).data
    assert d["account"]["email"] == EMAIL and d["account"]["display_name"] == NAME
    assert [x["name"] for x in d["qr_codes"]["items"]] == ["Menu"] and d["qr_codes"]["items"][0]["public_token"] == q.public_token
    assert d["notifications"]["count"] == 1 and d["domain_lookups"]["count"] == 1
    assert d["payments"]["items"][0]["provider_reference"] == "ref-keep-1"
    assert d["credits"]["balance"] == 9 and d["credits"]["ledger"]["items"][0]["reason"] == "welcome"
    assert d["abuse_reports_submitted"]["count"] == 1 and d["advertising_preferences"]["items"][0]["personalized_ads"] is False
    assert d["export"]["format_version"] == 1 and "excludes secrets" in d["export"]["about"]


def test_export_never_includes_secrets_or_staff_notes(person):
    u, c, tokens, _ = person
    from apps.credits.models import RewardedAdSession
    text = json.dumps(export_json(c).data, default=str)
    for secret in (u.password, "STAFF-ONLY NOTE", "STAFF OVERRIDE NOTE", "HASHVALUE123", tokens["refresh"], tokens["access"], "idempotency"):
        assert secret not in text, secret
    assert "password" not in text.lower().replace("passwords", "")


def test_export_never_includes_another_persons_data(person, other_user, other_client):
    from apps.notifications.models import Notification
    _, c, *_ = person
    make_qr(other_client, name="Someone Else's Secret Menu")
    Notification.objects.create(user=other_user, kind="qr.disabled", severity="info", title="THEIR NOTIFICATION", body="x")
    service.grant(other_user, 77, UsageCreditLedger.Type.ADMIN_GRANT, idempotency_key="theirs", reason="THEIR GRANT")
    text = json.dumps(export_json(c).data, default=str)
    for theirs in (other_user.email, "Someone Else", "THEIR NOTIFICATION", "THEIR GRANT"):
        assert theirs not in text


def test_export_download_headers_and_audit(person):
    u, c, *_ = person
    r = export_json(c)
    assert r["Content-Disposition"].startswith("attachment") and r["Cache-Control"] == "no-store"
    assert AuditLog.objects.filter(action="account.data_exported", actor=u).count() == 1


def test_a_failed_password_is_not_audited_as_an_export(person):
    u, c, *_ = person
    export_json(c, "wrong")
    assert not AuditLog.objects.filter(action="account.data_exported").exists()


def test_large_exports_are_marked_truncated(person, monkeypatch):
    from apps.notifications.models import Notification
    u, c, *_ = person
    for i in range(3):
        Notification.objects.create(user=u, kind="qr.disabled", severity="info", title=f"n{i}", body="b")
    monkeypatch.setattr(export, "MAX_ROWS", 2)
    n = export_json(c).data["notifications"]
    assert n["truncated"] is True and n["count"] == 2


def test_export_is_throttled_by_default():
    from config.settings import base
    assert "data_export" in base.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]


def test_new_fields_are_exported_but_secret_looking_ones_never_are():
    assert not export._skip("title") and export._skip("password") and export._skip("api_secret") and export._skip("reporter_hash")
    assert not export._skip("public_token") and export._skip("unique_session_token") and export._skip("refresh_token")
