"""Structured API errors: {"error": {"code", "message", "details"}}."""
from rest_framework.exceptions import ValidationError
from rest_framework.views import exception_handler


def api_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return None

    code = getattr(exc, "default_code", "error")
    try:                                    # prefer the specific code the exception was raised with
        specific = exc.get_codes()
        if isinstance(specific, str):
            code = specific
    except Exception:
        pass
    details = None
    if isinstance(exc, ValidationError):
        code = "validation_error"
        message = "The request could not be validated."
        details = response.data
    else:
        data = response.data
        message = data.get("detail", "Request failed.") if isinstance(data, dict) else str(data)
        message = str(message)

    response.data = {"error": {"code": code, "message": message, "details": details}}
    return response
