"""Re-assess the destinations of active dynamic QR codes and apply the malicious-destination policy.

Run on a schedule (e.g. hourly via cron/Celery beat):  python manage.py recheck_destinations --limit 200
A destination can turn malicious after the code was created, so this closes the gap between scans.
"""
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from apps.qr_codes.models import QRCode
from apps.security_engine import service
from apps.security_engine.policy import apply_malicious_policy


class Command(BaseCommand):
    help = "Re-assess active dynamic QR destinations and apply the malicious-destination policy."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100, help="Maximum destinations to check")

    def handle(self, *args, **opts):
        now = timezone.now()
        qs = (QRCode.objects.filter(code_mode=QRCode.Mode.DYNAMIC, status=QRCode.Status.ACTIVE)
              .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
              .order_by("-last_scanned_at", "-created_at"))
        seen, checked, flagged = set(), 0, 0
        for qr in qs.iterator():
            dest = qr.current_destination
            if dest in seen:
                continue
            seen.add(dest)
            if checked >= opts["limit"]:
                break
            try:
                check, _ = service.analyze(dest, source="recheck", trace=True)
            except service.NotApplicable:
                continue
            except Exception as exc:    # one bad destination must not stop the run
                self.stderr.write(f"FAILED {dest}: {exc.__class__.__name__}")
                continue
            checked += 1
            if check.risk_classification == "known_malicious":
                flagged += 1
                for affected in QRCode.objects.filter(current_destination=dest, status=QRCode.Status.ACTIVE,
                                                      code_mode=QRCode.Mode.DYNAMIC):
                    apply_malicious_policy(affected, check)
                self.stdout.write(f"MALICIOUS {dest}")
        self.stdout.write(f"Checked {checked} destination(s); {flagged} known malicious.")
