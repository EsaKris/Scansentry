"""Create EXAMPLE plans for development and demos. These numbers are illustrative only: real prices, limits and
entitlements are set by the product owner in the admin. Idempotent; never overwrites existing plans.

    python manage.py seed_example_plans
"""
from django.core.management.base import BaseCommand

from apps.billing.models import FeatureDefinition, Plan, PlanFeature, PlanPrice

EXAMPLES = [
    # slug, name, order, prices {currency: amount}, interval, trial, grace, {feature: (enabled, limit)}
    ("free", "Free", 0, {}, "month", 0, 0, {"qr.dynamic.active_limit": (True, 5), "domain.lookups.daily_limit": (True, 5),
                                            "qr.analytics.advanced": (False, None), "qr.pdf_export": (False, None),
                                            "ads.remove": (False, None)}),
    ("starter", "Starter", 1, {"NGN": "2000.00", "USD": "2.00"}, "month", 7, 3,
     {"qr.dynamic.active_limit": (True, 25), "domain.lookups.daily_limit": (True, 25), "ads.remove": (True, None)}),
    ("pro", "Pro", 2, {"NGN": "5000.00", "USD": "5.00"}, "month", 7, 3,
     {"qr.dynamic.active_limit": (True, 100), "domain.lookups.daily_limit": (True, 100), "ads.remove": (True, None),
      "qr.analytics.advanced": (True, None), "qr.pdf_export": (True, None)}),
    ("business", "Business", 3, {"NGN": "20000.00", "USD": "20.00"}, "month", 0, 7,
     {"qr.dynamic.active_limit": (True, None), "domain.lookups.daily_limit": (True, None), "ads.remove": (True, None),
      "qr.analytics.advanced": (True, None), "qr.pdf_export": (True, None), "api.access": (True, None)}),
]


class Command(BaseCommand):
    help = "Create example plans (illustrative values only)."

    def handle(self, *args, **opts):
        created = 0
        for slug, name, order, prices, interval, trial, grace, feats in EXAMPLES:
            plan, new = Plan.objects.get_or_create(slug=slug, defaults=dict(
                name=name, display_order=order, is_free=not prices, billing_interval=interval, trial_days=trial,
                grace_period_days=grace, description="EXAMPLE plan: edit or replace in the admin."))
            if not new:
                continue
            created += 1
            for cur, amount in prices.items():
                PlanPrice.objects.create(plan=plan, currency=cur, amount=amount)
            for key, (enabled, limit) in feats.items():
                f = FeatureDefinition.objects.filter(key=key).first()
                if f:
                    PlanFeature.objects.create(plan=plan, feature=f, enabled=enabled, limit_value=limit)
        self.stdout.write(f"Created {created} example plan(s). Pricing stays OFF until you enable it (pricing_enabled).")
