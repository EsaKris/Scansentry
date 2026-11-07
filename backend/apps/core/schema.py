from drf_spectacular.extensions import OpenApiAuthenticationExtension


class OptionalJWTScheme(OpenApiAuthenticationExtension):
    target_class = "apps.core.authentication.OptionalJWTAuthentication"
    name = "jwtAuthOptional"

    def get_security_definition(self, auto_schema):
        return {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
