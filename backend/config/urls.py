from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

api_v1 = [
    path("auth/", include("apps.accounts.urls")),
    path("", include("apps.core.urls")),
    path("", include("apps.qr_codes.urls")),
    path("", include("apps.scanner.urls")),
    path("", include("apps.domain_intel.urls")),
    path("", include("apps.security_engine.urls")),
    path("", include("apps.analytics.urls")),
    path("", include("apps.notifications.urls")),
    path("", include("apps.audit.urls")),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include(api_v1)),
]
