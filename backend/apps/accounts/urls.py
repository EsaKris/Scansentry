from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="auth-register"),
    path("login/", views.LoginView.as_view(), name="auth-login"),
    path("logout/", views.LogoutView.as_view(), name="auth-logout"),
    path("token/refresh/", views.RefreshView.as_view(), name="auth-refresh"),
    path("verify-email/", views.VerifyEmailView.as_view(), name="auth-verify-email"),
    path("password-reset/", views.PasswordResetRequestView.as_view(), name="auth-password-reset"),
    path("password-reset/confirm/", views.PasswordResetConfirmView.as_view(),
         name="auth-password-reset-confirm"),
    path("me/", views.MeView.as_view(), name="auth-me"),
    path("me/deletion-request/", views.DeletionRequestView.as_view(), name="auth-deletion-request"),
]
