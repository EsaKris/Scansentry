"""Enforce data-retention limits. Schedule daily:  python manage.py purge_old_data

Retention periods (days) are admin-configurable via AppConfiguration:
  retention.scan_events_days (395) · retention.notifications_days (180, read notifications)
  retention.security_checks_days (90) · retention.domain_assessments_days (365) · retention.usage_counters_days (400)
Use --dry-run to see what would be deleted.
"""
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.analytics.models import ScanEvent, UsageCounter
from apps.core.config import get_config
from apps.domain_intel.models import DomainAssessment
from apps.notifications.models import Notification
from apps.security_engine.models import SecurityCheck

DEFAULTS = {"scan_events": 395, "notifications": 180, "security_checks": 90, "domain_assessments": 365,
            "usage_counters": 400}


def days(name: str) -> int:
    try:
        return max(1, int(get_config(f"retention.{name}_days", DEFAULTS[name])))
    except (TypeError, ValueError):
        return DEFAULTS[name]


class Command(BaseCommand):
    help = "Delete data older than the configured retention periods."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **opts):
        now = timezone.now()
        cut = lambda name: now - timedelta(days=days(name))
        targets = {
            "scan events": ScanEvent.objects.filter(scanned_at__lt=cut("scan_events")),
            "read notifications": Notification.objects.filter(read_at__isnull=False, created_at__lt=cut("notifications")),
            "security checks": SecurityCheck.objects.filter(checked_at__lt=cut("security_checks")),
            "domain assessments": DomainAssessment.objects.filter(checked_at__lt=cut("domain_assessments")),
            "usage counters": UsageCounter.objects.filter(period_end__lt=cut("usage_counters")),
        }
        for label, qs in targets.items():
            n = qs.count()
            if not opts["dry_run"] and n:
                qs.delete()
            self.stdout.write(f"{'Would delete' if opts['dry_run'] else 'Deleted'} {n} {label}")
