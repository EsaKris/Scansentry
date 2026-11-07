import re

from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.qr_codes.services import resolve_token

from . import decoding
from .analysis import SECURITY_NOT_ASSESSED, _obs, analyze_content, analyze_url, managed_token_from_url
from .serializers import AnalyzeRequestSerializer, DecodeRequestSerializer
from .verification import build_verification

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")


def _not_found():
    return Response({"error": {"code": "not_found", "message": "This QR code was not found.",
                               "details": None}}, status=404)


class PublicScannerView(APIView):
    """Base for anonymous scanner endpoints: no auth, no cookies, never cached."""

    authentication_classes: list = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["Cache-Control"] = "no-store"
        return response


def full_analysis(content: str) -> dict:
    """analyze_content plus ScanSentry-managed link resolution. Performs no network access."""
    result = analyze_content(content)
    result["scansentry"] = None
    result["destination_analysis"] = None
    actions = result["actions"]
    actions["open_target"] = None

    if result["kind"] != "url" or actions["blocked"]:
        return result

    url = result["url"]["normalized"]
    token = managed_token_from_url(url)
    if token is None:
        actions["open_target"] = url
        return result

    qr = resolve_token(token)
    if qr is None:
        result["scansentry"] = {"managed": True, "state": "not_found"}
        result["observations"].append(_obs(
            "unregistered_scansentry_link",
            "This looks like a ScanSentry link but no matching QR code is registered."))
        actions.update(can_open=False, action=None, blocked=True,
                       block_reason="This looks like a ScanSentry link, but it is not a registered QR code.")
        return result

    verification = build_verification(qr)
    result["scansentry"] = {"managed": True, **verification}
    if verification["state"] != "active":
        actions.update(can_open=False, action=None, block_reason=verification["message"])
        return result

    dest = analyze_url(verification["destination"])
    result["destination_analysis"] = {"url": dest["url"], "observations": dest["observations"]}
    result["observations"].extend(dest["observations"])
    if dest["blocked"]:
        actions.update(can_open=False, action=None, blocked=True, block_reason=dest["reason"])
    else:
        actions["open_target"] = dest["url"]["normalized"]
    return result


class DecodeView(PublicScannerView):
    parser_classes = [MultiPartParser, FormParser]
    throttle_scope = "scanner_decode"

    @extend_schema(request={"multipart/form-data": DecodeRequestSerializer},
                   responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = DecodeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        contents = decoding.decode_upload(ser.validated_data["image"])  # in memory only
        results = [{"content": c[:4096], "analysis": full_analysis(c[:4096])} for c in contents]
        return Response({"found": bool(results), "count": len(results), "results": results})


class AnalyzeView(PublicScannerView):
    parser_classes = [JSONParser]
    throttle_scope = "scanner_analyze"

    @extend_schema(request=AnalyzeRequestSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = AnalyzeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        return Response(full_analysis(ser.validated_data["content"]))


class VerifyTokenView(PublicScannerView):
    """Public resolver for dynamic QR tokens. Never redirects; always needs user confirmation."""

    throttle_scope = "qr_resolve"

    @extend_schema(responses={200: OpenApiTypes.OBJECT, 404: OpenApiTypes.OBJECT})
    def get(self, request, token):
        qr = resolve_token(token) if TOKEN_RE.fullmatch(token) else None
        if qr is None:
            return _not_found()
        return Response(build_verification(qr))
