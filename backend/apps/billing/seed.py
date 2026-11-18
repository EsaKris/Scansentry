"""Idempotent defaults created on migrate. Seeding never overwrites anything an administrator changed.

No commercial values are seeded: the Free plan has no limits (so behaviour is unchanged until an
administrator configures it), and pricing starts switched OFF.
"""
from apps.core.models import AppConfiguration

B, I, J = "boolean", "integer", "json"
CATALOGUE = [
    # key, name, type, default, measurable
    ("qr.static.create", "Create static QR codes", B, True, False),
    ("qr.dynamic.create", "Create dynamic QR codes", B, True, False),
    ("qr.dynamic.active_limit", "Active dynamic QR codes", I, None, True),
    ("qr.scans.monthly_limit", "Tracked scans per month", I, None, True),
    ("qr.custom_branding", "Custom QR branding", B, True, False),
    ("qr.logo_upload", "Logo in QR codes", B, True, False),
    ("qr.svg_export", "SVG export", B, True, False),
    ("qr.pdf_export", "PDF export", B, True, False),
    ("qr.bulk_generation", "Bulk QR generation", B, False, False),
    ("qr.analytics.basic", "Basic scan analytics", B, True, False),
    ("qr.analytics.advanced", "Advanced scan analytics and export", B, True, False),
    ("domain.lookups.daily_limit", "Domain lookups per day", I, None, True),
    ("domain.lookups.weekly_limit", "Domain lookups per week", I, None, True),
    ("domain.lookups.monthly_limit", "Domain lookups per month", I, None, True),
    ("credits.earn.daily_limit", "Credits earnable per day", I, None, True),
    ("credits.earn.weekly_limit", "Credits earnable per week", I, None, True),
    ("credits.earn.monthly_limit", "Credits earnable per month", I, None, True),
    ("credits.spend.feature_cost", "Credit cost per feature", J, None, False),
    ("domain.reports.export", "Domain report export", B, True, False),
    ("security.advanced_checks", "Advanced security checks", B, True, False),
    ("security.history", "Security history", B, True, False),
    ("ai.explanations", "AI security explanations", B, True, False),
    ("qr.custom_domains", "Custom QR domains", B, False, False),
    ("api.access", "API access", B, False, False),
    ("api.monthly_requests", "API requests per month", I, None, True),
    ("organization.team_members", "Organisation team members", I, None, True),
    ("ads.remove", "Ad-free experience", B, False, False),
    ("ads.rewarded_credits", "Rewarded-ad credits", B, True, False),
]


def seed_defaults() -> None:
    from .models import FeatureDefinition, Plan
    for key, name, dtype, default, measurable in CATALOGUE:
        FeatureDefinition.objects.get_or_create(key=key, defaults=dict(
            name=name, data_type=dtype, default_value=default, measurable=measurable))
    Plan.objects.get_or_create(slug="free", defaults=dict(
        name="Free", description="The base tier.", is_free=True, is_public=True, display_order=0))
    AppConfiguration.objects.get_or_create(key="pricing_enabled", defaults=dict(
        value=False, is_public=True, description="Master switch for pricing, checkout and plan enforcement of purchases."))
