"""Create an EXAMPLE rewarded-ad offer and credit price for development and demos. Illustrative values only: the product owner sets
the real ones in the admin. The offer is created DISABLED, and the rewarded-ad switches stay as they are.

    python manage.py seed_example_rewards
"""
from django.core.management.base import BaseCommand

from apps.advertising.models import AdProvider
from apps.core.models import AppConfiguration
from apps.credits.models import RewardedAdOffer


class Command(BaseCommand):
    help = "Create an example (disabled) rewarded-ad offer for Android and a sample credit price for domain lookups."

    def handle(self, *args, **opts):
        provider = AdProvider.objects.get(key="admob")
        offer, created = RewardedAdOffer.objects.get_or_create(
            name="EXAMPLE: Watch an ad for extra domain lookups", platform="android", provider=provider,
            defaults=dict(description="Illustrative example. Edit or replace it in the admin.", reward_amount=2, cooldown_seconds=120,
                          maximum_claims_per_day=5, eligible_categories=["free", "trial"], eligible_features=["domain.lookups"],
                          credit_expiry_days=30, enabled=False))
        row, _ = AppConfiguration.objects.get_or_create(key="credits.feature_costs", defaults=dict(value={}))
        if not row.value:
            row.value = {"domain.lookups": 1}
            row.save()
        self.stdout.write(f"{'Created' if created else 'Found'} the example offer (disabled). Domain lookups now cost 1 credit.")
