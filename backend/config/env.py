"""Tiny helpers for reading environment variables."""
import os


def env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


def env_bool(key: str, default: bool = False) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(key: str, default: int) -> int:
    value = os.environ.get(key)
    return int(value) if value not in (None, "") else default


def env_list(key: str, default: str = "") -> list[str]:
    value = os.environ.get(key, default)
    return [item.strip() for item in value.split(",") if item.strip()]
