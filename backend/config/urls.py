from django.conf import settings
from django.http import HttpResponse
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
    path("", include("apps.billing.urls")),
    path("", include("apps.advertising.urls")),
    path("", include("apps.credits.urls")),
    path("", include("apps.audit.urls")),
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
]

def robots_txt(request):
    """The API host is never to be indexed. (The website has its own robots.txt: see docs/seo/robots.txt.)"""
    return HttpResponse("User-agent: *\nDisallow: /\n", content_type="text/plain")


urlpatterns = [
    path("robots.txt", robots_txt, name="robots-txt"),
    path(settings.ADMIN_URL.strip("/") + "/", admin.site.urls),
    path("api/v1/", include(api_v1)),
]
