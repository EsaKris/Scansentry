from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _sync(sender, **kwargs):
    from .rules import sync_rules
    sync_rules()


class SecurityEngineConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.security_engine"

    def ready(self):
        post_migrate.connect(_sync, sender=self)
