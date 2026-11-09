from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework.test import APIClient

from apps.audit.models import AuditLog
from apps.notifications import service as N
from apps.notifications.models import Notification, NotificationPreference
from apps.qr_codes import services as qr_services
from apps.qr_codes.models import QRCode
from apps.security_engine import service as sec
from tests.conftest import enable_provider, make_qr

pytestmark = pytest.mark.django_db
BAD = "ss-malware-test.example.com"


@pytest.fixture
def verified(user):
    user.email_verified = True
    user.save()
    return user


@pytest.fixture
def world(senv):
    senv.publish(BAD)
    enable_provider("test_fixture")
    return senv


def notes(user, **f):
    return list(Notification.objects.filter(user=user, **f))


# ---- security alerts -------------------------------------------------------------------------------------------------------------
def test_owner_is_alerted_when_their_destination_is_flagged_with_host_only_details(verified, auth_client, world):
    qr = make_qr(auth_client, name="Menu", data={"url": f"https://{BAD}/landing/pay?token=SECRET77"}).data
    sec.analyze(f"https://{BAD}/landing/pay?token=SECRET77", source="recheck")
    [n] = notes(verified)
    assert n.kind == "security.destination_flagged" and n.severity == "critical" and "Menu" in n.title
    assert BAD in n.body and "Known malicious" in n.body and "will not forward" in n.body
    assert "SECRET77" not in n.body + str(n.data) and "/landing" not in n.body + str(n.data)
    assert n.data == {"qr_id": qr["id"], "check_id": n.data["check_id"], "classification": "known_malicious", "host": BAD}
    assert len(mail.outbox) == 1 and mail.outbox[0].to == [verified.email] and "SECRET77" not in mail.outbox[0].body


def test_every_owner_of_the_flagged_destination_is_notified_but_not_paused_codes(verified, auth_client, other_client, other_user, world):
    other_user.email_verified = True
    other_user.save()
    make_qr(auth_client, name="A", data={"url": f"https://{BAD}/x"})
    paused = make_qr(auth_client, name="B", data={"url": f"https://{BAD}/x"}).data
    auth_client.post(f"/api/v1/qr/{paused['id']}/pause/")
    make_qr(other_client, name="C", data={"url": f"https://{BAD}/x"})
    make_qr(other_client, name="D", data={"url": f"https://{BAD}/other"})            # different destination
    sec.analyze(f"https://{BAD}/x", source="recheck")
    assert [n.title for n in notes(verified)] == ["Security alert: the destination of “A” was flagged"]
    assert len(notes(other_user)) == 1 and "“C”" in notes(other_user)[0].title


def test_high_risk_alerts_but_suspicious_does_not(verified, auth_client, senv):
    make_qr(auth_client, name="Look", data={"url": "https://аpple.com/x"})            # homograph of apple.com: high risk
    make_qr(auth_client, name="Meh", data={"url": "http://paypal-secure-login.com/y"})  # suspicious only
    senv.publish("xn--pple-43d.com")
    assert sec.analyze("https://аpple.com/x", source="recheck")[0].risk_classification == "high_risk"
    assert sec.analyze("http://paypal-secure-login.com/y", source="recheck")[0].risk_classification == "suspicious"
    assert [n.title for n in notes(verified)] == ["Security alert: the destination of “Look” was flagged"]


def test_repeated_assessments_do_not_spam_the_owner(verified, auth_client, world):
    make_qr(auth_client, data={"url": f"https://{BAD}/x"})
    for _ in range(3):
        sec.analyze(f"https://{BAD}/x", source="recheck")
        SecurityCheckExpire()
    assert len(notes(verified)) == 1 and len(mail.outbox) == 1


def SecurityCheckExpire():
    from apps.security_engine.models import SecurityCheck
    SecurityCheck.objects.update(cache_expires_at=timezone.now() - timedelta(minutes=1))


# ---- email policy ---------------------------------------------------------------------------------------------------------------
def test_email_respects_verification_and_preferences_but_the_in_app_alert_always_exists(user, auth_client, world):
    make_qr(auth_client, data={"url": f"https://{BAD}/x"})
    sec.analyze(f"https://{BAD}/x", source="recheck")                                  # unverified email: no mail
    assert len(notes(user)) == 1 and mail.outbox == [] and notes(user)[0].emailed_at is None
    user.email_verified = True
    user.save()
    NotificationPreference.objects.update_or_create(user=user, defaults={"email_security_alerts": False})
    N.notify(user, "security.destination_flagged", title="t2", body="b", severity="critical")
    assert mail.outbox == [] and len(notes(user)) == 2                                  # preference off: no mail, still in-app
    NotificationPreference.objects.filter(user=user).update(email_security_alerts=True)
    N.notify(user, "security.destination_flagged", title="t3", body="b", severity="critical")
    assert len(mail.outbox) == 1 and notes(user, title="t3")[0].emailed_at is not None


def test_a_mail_failure_never_loses_the_notification(verified, monkeypatch):
    monkeypatch.setattr(N, "send_mail", lambda *a, **k: (_ for _ in ()).throw(OSError("smtp down")))
    n = N.notify(verified, "security.destination_flagged", title="x", body="y", severity="critical")
    assert n is not None and n.emailed_at is None and Notification.objects.count() == 1


def test_info_notifications_are_never_emailed(verified):
    N.notify(verified, "qr.restored", title="x", body="y", severity="info")
    assert mail.outbox == []


# ---- QR status events ----------------------------------------------------------------------------------------------------------------
def test_staff_disable_and_restore_notify_the_owner(verified, auth_client):
    qr = QRCode.objects.get(pk=make_qr(auth_client, name="Promo").data["id"])
    staff = get_user_model().objects.create_user("mod@example.com", "Str0ng-Passphrase-42", is_staff=True)
    qr_services.disable_qr(qr, user=staff, reason="Reported as impersonation", by_staff=True)
    [n] = notes(verified, kind="qr.disabled")
    assert n.severity == "critical" and "staff disabled" in n.body and "impersonation" in n.body and n.data["automated"] is False
    assert len(mail.outbox) == 1
    qr_services.staff_restore_qr(QRCode.objects.get(pk=qr.pk), user=staff)
    assert notes(verified, kind="qr.restored") and len(mail.outbox) == 1                 # restore is in-app only
    assert "mod@example.com" not in n.body                                              # staff identity never exposed


def test_owner_initiated_disable_does_not_notify_the_owner(verified, auth_client):
    qr = make_qr(auth_client).data
    auth_client.post(f"/api/v1/qr/{qr['id']}/disable/")
    assert notes(verified) == []


def test_automatic_policy_disable_explains_it_was_malicious_and_automated(verified, auth_client, world):
    from apps.core.models import AppConfiguration
    AppConfiguration.objects.create(key="security.auto_disable_malicious", value=True)
    qr = make_qr(auth_client, name="Pay", data={"url": f"https://{BAD}/x"}).data
    APIClient().get(f"/api/v1/scanner/verify/{qr['public_token']}/", {"assess": "1"})
    n = notes(verified, kind="qr.disabled")[0]
    assert n.data["automated"] is True and "automatically" in n.body and "malicious" in n.body and BAD in n.body


def test_destination_change_is_recorded_in_app_only_and_shows_hosts_not_urls(verified, auth_client):
    qr = make_qr(auth_client, name="Menu", data={"url": "https://old.example.com/a?s=1"}).data
    auth_client.patch(f"/api/v1/qr/{qr['id']}/", {"current_destination": "https://new.example.org/b?token=Z9"}, format="json")
    [n] = notes(verified, kind="qr.destination_changed")
    assert n.data["from_host"] == "old.example.com" and n.data["to_host"] == "new.example.org" and mail.outbox == []
    assert "Z9" not in n.body and "/b" not in n.body


def test_abuse_reports_notify_the_owner_without_revealing_the_reporter(verified, auth_client, api):
    qr = make_qr(auth_client, name="Menu").data
    body = {"qr_token": qr["public_token"], "category": "impersonation", "description": "This looks like a fake page."}
    api.post("/api/v1/scanner/report/", body, format="json", REMOTE_ADDR="198.51.100.5")
    other = APIClient()
    other.post("/api/v1/scanner/report/", body, format="json", REMOTE_ADDR="198.51.100.6")      # a second reporter, same day
    [n] = notes(verified, kind="abuse.report_received")                                          # deduplicated
    assert n.severity == "warning" and "impersonation" in n.body and "do not change your code" in n.body
    assert set(n.data) == {"qr_id", "category"} and "198.51" not in str(n.data) and "fake page" not in n.body
    assert QRCode.objects.get(pk=qr["id"]).status == "active"


def test_url_only_reports_notify_nobody(verified, api):
    api.post("/api/v1/scanner/report/", {"url": "https://evil.example.org/", "category": "other", "description": "Looks wrong to me."}, format="json")
    assert notes(verified) == []


def test_expiry_reminders(verified, auth_client, capsys):
    from django.core.management import call_command
    soon = make_qr(auth_client, name="Soon", expires_at=(timezone.now() + timedelta(days=2)).isoformat()).data
    make_qr(auth_client, name="Later", expires_at=(timezone.now() + timedelta(days=30)).isoformat())
    make_qr(auth_client, name="Never")
    paused = make_qr(auth_client, name="Paused", expires_at=(timezone.now() + timedelta(days=1)).isoformat()).data
    auth_client.post(f"/api/v1/qr/{paused['id']}/pause/")
    call_command("send_expiry_reminders")
    assert "Sent 1 reminder(s)." in capsys.readouterr().out
    [n] = notes(verified, kind="qr.expiring_soon")
    assert "Soon" in n.title and n.data["qr_id"] == soon["id"] and len(mail.outbox) == 1
    call_command("send_expiry_reminders")
    assert "Sent 0 reminder(s)." in capsys.readouterr().out                              # no duplicate


# ---- API ---------------------------------------------------------------------------------------------------------------------------------
def test_list_filter_read_and_isolation(auth_client, other_client, user, other_user):
    a = N.notify(user, "qr.restored", title="one", body="b")
    b = N.notify(user, "security.destination_flagged", title="two", body="b", severity="critical", email=False)
    theirs = N.notify(other_user, "qr.restored", title="theirs", body="b")
    r = auth_client.get("/api/v1/notifications/")
    assert [x["title"] for x in r.data["results"]] == ["two", "one"] and r.data["count"] == 2
    assert auth_client.get("/api/v1/notifications/?kind=qr.restored").data["count"] == 1
    assert auth_client.get("/api/v1/notifications/?severity=critical").data["count"] == 1
    assert auth_client.get("/api/v1/notifications/unread-count/").data == {"unread": 2, "critical_unread": 1}
    assert auth_client.post(f"/api/v1/notifications/{a.id}/read/").data["read"] is True
    assert auth_client.get("/api/v1/notifications/?unread=true").data["count"] == 1
    assert auth_client.post(f"/api/v1/notifications/{theirs.id}/read/").status_code == 404
    assert other_client.post(f"/api/v1/notifications/{b.id}/read/").status_code == 404
    assert Notification.objects.get(pk=theirs.id).read_at is None
    assert auth_client.post("/api/v1/notifications/read-all/").data == {"marked_read": 1}
    assert auth_client.get("/api/v1/notifications/unread-count/").data == {"unread": 0, "critical_unread": 0}
    assert other_client.get("/api/v1/notifications/unread-count/").data["unread"] == 1


def test_preferences_default_on_and_can_be_changed(auth_client, user):
    assert auth_client.get("/api/v1/notifications/preferences/").data == {
        "email_security_alerts": True, "email_qr_status": True, "email_abuse_reports": True,
        "updated_at": auth_client.get("/api/v1/notifications/preferences/").data["updated_at"]}
    r = auth_client.patch("/api/v1/notifications/preferences/", {"email_qr_status": False, "user": 999}, format="json")
    assert r.status_code == 200 and r.data["email_qr_status"] is False and r.data["email_security_alerts"] is True
    assert NotificationPreference.objects.get(user=user).email_qr_status is False
    assert auth_client.put("/api/v1/notifications/preferences/", {}, format="json").status_code == 405


def test_notification_endpoints_require_authentication(api):
    for path in ("", "unread-count/", "preferences/"):
        assert api.get(f"/api/v1/notifications/{path}").status_code == 401
    assert api.post("/api/v1/notifications/read-all/").status_code == 401


# ---- activity history ------------------------------------------------------------------------------------------------------------------------
def test_qr_activity_history_includes_staff_and_system_actions_without_identities(auth_client, user):
    qr = make_qr(auth_client, name="Menu").data
    auth_client.patch(f"/api/v1/qr/{qr['id']}/", {"current_destination": "https://new.example.org/"}, format="json")
    auth_client.post(f"/api/v1/qr/{qr['id']}/pause/")
    row = QRCode.objects.get(pk=qr["id"])
    staff = get_user_model().objects.create_user("mod@example.com", "Str0ng-Passphrase-42", is_staff=True)
    qr_services.disable_qr(row, user=staff, reason="abuse", by_staff=True)
    qr_services.staff_restore_qr(QRCode.objects.get(pk=qr["id"]), user=None)
    r = auth_client.get(f"/api/v1/qr/{qr['id']}/activity/")
    assert r.status_code == 200
    got = [(e["label"], e["actor"]) for e in reversed(r.data["results"])]
    assert got == [("Created", "you"), ("Destination changed", "you"), ("Paused", "you"),
                   ("Disabled", "scansentry_staff"), ("Reactivated", "system")]
    flat = str(r.data)
    assert "mod@example.com" not in flat and "ip_address" not in flat
    change = next(e for e in r.data["results"] if e["action"] == "qr.destination_changed")
    assert change["after_state"] == {"destination": "https://new.example.org/"}


def test_qr_activity_is_owner_only(auth_client, other_client):
    qr = make_qr(auth_client).data
    assert other_client.get(f"/api/v1/qr/{qr['id']}/activity/").status_code == 404


def test_account_activity_is_the_users_own_actions_and_is_read_only(auth_client, other_client, user):
    make_qr(auth_client)
    make_qr(other_client)
    r = auth_client.get("/api/v1/activity/")
    assert r.status_code == 200 and r.data["count"] >= 1
    assert all(e["actor"] == "you" for e in r.data["results"])
    assert AuditLog.objects.filter(action="qr.created").count() == 2 and r.data["count"] == AuditLog.objects.filter(actor=user).count()
    assert auth_client.get("/api/v1/activity/?action=qr.").data["count"] == 1
    assert auth_client.get("/api/v1/activity/?action=nothing").data["count"] == 0
    for method in (auth_client.post, auth_client.patch, auth_client.delete):
        assert method("/api/v1/activity/", {}, format="json").status_code == 405


def test_activity_requires_authentication(api, auth_client):
    qr = make_qr(auth_client).data
    assert api.get("/api/v1/activity/").status_code == 401
    assert api.get(f"/api/v1/qr/{qr['id']}/activity/").status_code == 401
