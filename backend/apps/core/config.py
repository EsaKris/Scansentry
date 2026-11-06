"""Read helpers for AppConfiguration (e.g. pricing_enabled, ads_enabled)."""
from typing import Any

from .models import AppConfiguration


def get_config(key: str, default: Any = None) -> Any:
    row = AppConfiguration.objects.filter(key=key).only("value").first()
    if row is None:
        return default
    value = row.value
    # Values are stored as JSON; allow {"value": X} or a bare JSON scalar.
    if isinstance(value, dict) and set(value.keys()) == {"value"}:
        return value["value"]
    return value
