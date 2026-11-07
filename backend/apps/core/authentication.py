from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class OptionalJWTAuthentication(JWTAuthentication):
    """Authenticate when a valid token is sent, otherwise treat the caller as anonymous.

    For public endpoints that behave slightly better for signed-in users (e.g. abuse reports)
    but must never fail because of a stale token.
    """

    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except (InvalidToken, AuthenticationFailed):
            return None
