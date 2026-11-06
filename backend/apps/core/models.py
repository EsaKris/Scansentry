import uuid

from django.conf import settings
from django.db import models


class UUIDModel(models.Model):
    """UUID primary key for entities that are exposed through the API."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class AppConfiguration(models.Model):
    """Database-backed settings so commercial/feature rules are never hardcoded.

    Only rows with is_public=True are ever exposed to clients. Never store
    secrets here.
    """

    key = models.CharField(max_length=120, unique=True)
    value = models.JSONField(default=dict, blank=True)
    description = models.TextField(blank=True)
    is_public = models.BooleanField(default=False)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name="+",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return self.key
