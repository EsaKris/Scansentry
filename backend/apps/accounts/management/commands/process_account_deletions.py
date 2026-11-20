"""Erase accounts whose deletion request is past its grace period. Schedule daily:  python manage.py process_account_deletions

Grace period: config `account.deletion_grace_days` (default 14); users can cancel until then. A paid period still running is honoured (renewal is cancelled,
the account is erased afterwards). Staff accounts and organisation owners with other members are never erased automatically: they are reported here instead.
"""
from django.core.management.base import BaseCommand

from apps.accounts import deletion


class Command(BaseCommand):
    help = "Anonymise accounts whose deletion grace period has passed."

    def handle(self, *args, **opts):
        s = deletion.process_due()
        self.stdout.write(f"Anonymised {s['anonymized']} account(s); deferred {len(s['deferred'])}.")
        for d in s["deferred"]:
            self.stdout.write(f"  deferred {d['user']}: {'; '.join(d['reasons'])}")
