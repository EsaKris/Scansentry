"""Move subscriptions through trial end, grace period and expiry. Schedule hourly:  python manage.py process_subscriptions

Access itself is time-based, so a late or missed run never grants or removes access wrongly: this job keeps
statuses, history and notifications accurate."""
from django.core.management.base import BaseCommand

from apps.billing.service import process_due_subscriptions


class Command(BaseCommand):
    help = "Process trial endings, grace periods and expiries."

    def handle(self, *args, **opts):
        c = process_due_subscriptions()
        self.stdout.write(f"Moved {c['grace_period']} subscription(s) to grace period and expired {c['expired']}.")
