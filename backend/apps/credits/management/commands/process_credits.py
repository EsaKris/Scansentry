"""Housekeeping for credits and rewarded ads. Schedule hourly:  python manage.py process_credits

  * expires credits whose expiry date has passed (writes CREDIT_EXPIRY ledger entries)
  * closes rewarded-ad sessions nobody finished (they can no longer be completed)
Spending and balance reads also expire credits on demand, so a late run never lets expired credits be spent.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.credits import service
from apps.credits.models import CreditLot, RewardedAdSession


class Command(BaseCommand):
    help = "Expire due credits and close stale rewarded-ad sessions."

    def handle(self, *args, **opts):
        now = timezone.now()
        wallets = (CreditLot.objects.filter(remaining__gt=0, expires_at__lte=now).values_list("wallet__user_id", flat=True).distinct())
        from django.contrib.auth import get_user_model
        users = get_user_model().objects.filter(pk__in=list(wallets))
        expired = sum(service.expire_due(u, now) for u in users)
        S = RewardedAdSession.Status
        closed = RewardedAdSession.objects.filter(status__in=(S.CREATED, S.AD_AVAILABLE, S.STARTED), expires_at__lte=now).update(status=S.EXPIRED)
        self.stdout.write(f"Expired {expired} credits for {users.count()} users; closed {closed} stale ad sessions.")
