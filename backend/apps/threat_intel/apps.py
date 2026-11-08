from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _sync(sender, **kwargs):
    from .service import sync_providers
    sync_providers()


class ThreatIntelConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.threat_intel"

    def ready(self):
        post_migrate.connect(_sync, sender=self)
