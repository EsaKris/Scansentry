from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.analytics.models import ScanEvent, UsageCounter
from apps.core.models import AppConfiguration
from apps.domain_intel.models import DomainAssessment
from apps.notifications.models import Notification
from apps.security_engine.models import SecurityCheck
from tests.conftest import make_qr

pytestmark = pytest.mark.django_db


def ago(days):
    return timezone.now() - timedelta(days=days)


def seed(user, qr_id):
    ScanEvent.objects.create(qr_code_id=qr_id, scanned_at=ago(400), outcome="delivered", visitor_hash="old")
    ScanEvent.objects.create(qr_code_id=qr_id, scanned_at=ago(10), outcome="delivered", visitor_hash="new")
    old_read = Notification.objects.create(user=user, kind="qr.restored", title="o", body="b", read_at=ago(190))
    Notification.objects.filter(pk=old_read.pk).update(created_at=ago(200))
    old_unread = Notification.objects.create(user=user, kind="qr.restored", title="u", body="b")
    Notification.objects.filter(pk=old_unread.pk).update(created_at=ago(200))
    new_read = Notification.objects.create(user=user, kind="qr.restored", title="n", body="b", read_at=ago(1))
    for d, tag in ((100, "old"), (5, "new")):
        SecurityCheck.objects.create(submitted_url=f"https://{tag}.com", risk_classification="suspicious", engine_version="x",
                                     checked_at=ago(d), cache_expires_at=ago(d))
    for d, tag in ((400, "old.com"), (5, "new.com")):
        DomainAssessment.objects.create(domain=tag, registrable_domain=tag, engine_version="x", checked_at=ago(d), cache_expires_at=ago(d))
    for d in (500, 3):
        UsageCounter.objects.create(user=user, feature_key="f", window="day", period_start=ago(d), period_end=ago(d) + timedelta(days=1))
    return old_read, old_unread, new_read


def test_purge_deletes_only_data_past_retention(user, auth_client, capsys):
    qr = make_qr(auth_client).data["id"]
    old_read, old_unread, new_read = seed(user, qr)
    call_command("purge_old_data")
    out = capsys.readouterr().out
    assert "Deleted 1 scan events" in out and "Deleted 1 read notifications" in out and "Deleted 1 security checks" in out
    assert list(ScanEvent.objects.values_list("visitor_hash", flat=True)) == ["new"]
    assert set(Notification.objects.values_list("title", flat=True)) == {"u", "n"}      # unread are kept
    assert SecurityCheck.objects.get().submitted_url == "https://new.com"
    assert DomainAssessment.objects.get().domain == "new.com"
    assert UsageCounter.objects.count() == 1


def test_dry_run_deletes_nothing(user, auth_client, capsys):
    qr = make_qr(auth_client).data["id"]
    seed(user, qr)
    before = (ScanEvent.objects.count(), Notification.objects.count(), SecurityCheck.objects.count(), DomainAssessment.objects.count())
    call_command("purge_old_data", "--dry-run")
    assert "Would delete 1 scan events" in capsys.readouterr().out
    assert before == (ScanEvent.objects.count(), Notification.objects.count(), SecurityCheck.objects.count(), DomainAssessment.objects.count())


def test_retention_periods_are_admin_configurable(user, auth_client):
    qr = make_qr(auth_client).data["id"]
    seed(user, qr)
    AppConfiguration.objects.create(key="retention.scan_events_days", value=5)
    AppConfiguration.objects.create(key="retention.security_checks_days", value=2)
    call_command("purge_old_data")
    assert ScanEvent.objects.count() == 0 and SecurityCheck.objects.count() == 0       # both rows are older than the new limits


def test_nonsense_retention_values_fall_back_to_safe_defaults_and_zero_never_wipes_todays_data(user, auth_client):
    qr = make_qr(auth_client).data["id"]
    seed(user, qr)
    SecurityCheck.objects.create(submitted_url="https://today.com", risk_classification="suspicious", engine_version="x",
                                 checked_at=timezone.now(), cache_expires_at=timezone.now())
    AppConfiguration.objects.create(key="retention.scan_events_days", value="abc")       # unparsable -> default 395 days
    AppConfiguration.objects.create(key="retention.security_checks_days", value=0)       # 0 is clamped to 1 day, not "delete all"
    call_command("purge_old_data")
    assert list(ScanEvent.objects.values_list("visitor_hash", flat=True)) == ["new"]
    assert list(SecurityCheck.objects.values_list("submitted_url", flat=True)) == ["https://today.com"]
