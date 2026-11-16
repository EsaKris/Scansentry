"""Idempotent defaults on migrate. Nothing is overwritten once an administrator has changed it."""
from apps.core.models import AppConfiguration

from .config import DEFAULTS


def seed_defaults() -> None:
    for key, value in DEFAULTS.items():
        AppConfiguration.objects.get_or_create(key=key, defaults=dict(
            value=value, is_public=False, description="Rewarded ads / ScanSentry Credits setting (see README). Edit in the admin."))
