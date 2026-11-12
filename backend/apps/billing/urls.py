from django.urls import path

from . import views as v

urlpatterns = [
    path("plans/", v.PlansView.as_view(), name="plans"),
    path("billing/subscription/", v.SubscriptionView.as_view(), name="billing-subscription"),
    path("billing/entitlements/", v.EntitlementsView.as_view(), name="billing-entitlements"),
    path("billing/checkout/", v.CheckoutView.as_view(), name="billing-checkout"),
    path("billing/checkout/verify/", v.CheckoutVerifyView.as_view(), name="billing-checkout-verify"),
    path("billing/cancel/", v.CancelView.as_view(), name="billing-cancel"),
    path("billing/resume/", v.ResumeView.as_view(), name="billing-resume"),
    path("billing/transactions/", v.TransactionsView.as_view(), name="billing-transactions"),
    path("billing/webhooks/<str:provider>/", v.WebhookView.as_view(), name="billing-webhook"),
    path("admin/billing/overview/", v.AdminOverviewView.as_view(), name="admin-billing-overview"),
    path("admin/billing/webhook-events/", v.AdminWebhookEventsView.as_view(), name="admin-billing-webhooks"),
    path("admin/billing/overrides/", v.AdminOverrideCreateView.as_view(), name="admin-billing-override"),
    path("admin/billing/overrides/<int:pk>/revoke/", v.AdminOverrideRevokeView.as_view(), name="admin-billing-revoke"),
    path("admin/billing/subscriptions/extend/", v.AdminSubscriptionActionView.as_view(action="extend"), name="admin-sub-extend"),
    path("admin/billing/subscriptions/suspend/", v.AdminSubscriptionActionView.as_view(action="suspend"), name="admin-sub-suspend"),
    path("admin/billing/subscriptions/restore/", v.AdminSubscriptionActionView.as_view(action="restore"), name="admin-sub-restore"),
]
