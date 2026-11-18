from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _seed(sender, **kwargs):
    from .seed import seed_defaults
    seed_defaults()


class BillingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.billing"

    def ready(self):
        post_migrate.connect(_seed, sender=self)
