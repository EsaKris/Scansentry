"""Notify owners of active QR codes that expire soon.  Schedule daily:  python manage.py send_expiry_reminders --days 3"""
from django.core.management.base import BaseCommand

from apps.notifications.service import send_expiry_reminders


class Command(BaseCommand):
    help = "Send expiry reminders for QR codes expiring within N days."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=3)

    def handle(self, *args, **opts):
        self.stdout.write(f"Sent {send_expiry_reminders(opts['days'])} reminder(s).")
