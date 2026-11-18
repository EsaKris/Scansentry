import re

from drf_spectacular.utils import OpenApiTypes, extend_schema
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.analytics.service import record_scan
from apps.qr_codes.services import resolve_token

from . import decoding
from .analysis import SECURITY_NOT_ASSESSED, _obs, analyze_content, analyze_url, managed_token_from_url
from .serializers import AnalyzeRequestSerializer, DecodeRequestSerializer
from .verification import build_verification, security_for

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


def _block(actions: dict, reason: str) -> None:
    actions.update(can_open=False, action=None, blocked=True, block_reason=reason, open_target=None)


_OUTCOME = {"active": "delivered", "paused": "paused", "disabled": "disabled", "expired": "expired", "blocked": "blocked"}


def _sec_status(sec: dict | None) -> str:
    status = (sec or {}).get("status", "")
    return "" if status == "assessment_not_available" else status


def full_analysis(content: str, *, assess: bool = False, request=None, scanner_type: str = "camera") -> dict:
    """Analyse content and (when a request is supplied) record a privacy-conscious scan event."""
    result = _full_analysis(content, assess=assess)
    qr = result.pop("_qr", None)
    if request is not None:
        sc = result.get("scansentry") or {}
        if qr is not None:
            record_scan(request, qr=qr, outcome=_OUTCOME.get(sc.get("state"), "delivered"), scanner_type=scanner_type,
                        security_status=_sec_status(result.get("security")))
        elif not sc:     # an external code: counted for platform statistics only, no content kept
            record_scan(request, qr=None, outcome="analyzed", scanner_type=scanner_type,
                        security_status=_sec_status(result.get("security")), content_kind=result["kind"])
    return result


def _full_analysis(content: str, *, assess: bool = False) -> dict:
    """analyze_content plus ScanSentry-managed link resolution.

    Default: no network access (cached security results only). assess=True also runs the full security
    assessment (domain intelligence + threat intelligence) on the destination.
    """
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
        security, check = security_for(url, assess=assess)
        result["security"] = security
        if check is not None and check.risk_classification == "known_malicious":
            from apps.security_engine.policy import MALICIOUS_MESSAGE
            _block(actions, MALICIOUS_MESSAGE)
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

    verification = build_verification(qr, assess=assess)
    result["_qr"] = qr
    result["scansentry"] = {"managed": True, **verification}
    result["security"] = verification["security"]
    if verification["state"] == "blocked":          # redirect policy: confirmed malicious destination
        _block(actions, verification["message"])
        return result
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
        assess = ser.validated_data.get("assess", False)
        results = [{"content": c[:4096], "analysis": full_analysis(c[:4096], assess=assess, request=request,
                                                                    scanner_type="upload")} for c in contents]
        return Response({"found": bool(results), "count": len(results), "results": results})


class AnalyzeView(PublicScannerView):
    parser_classes = [JSONParser]
    throttle_scope = "scanner_analyze"

    @extend_schema(request=AnalyzeRequestSerializer, responses={200: OpenApiTypes.OBJECT})
    def post(self, request):
        ser = AnalyzeRequestSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        return Response(full_analysis(ser.validated_data["content"], assess=ser.validated_data["assess"],
                                      request=request, scanner_type=ser.validated_data["scanner_type"]))


class VerifyTokenView(PublicScannerView):
    """Public resolver for dynamic QR tokens. Never redirects; always needs user confirmation."""

    throttle_scope = "qr_resolve"

    @extend_schema(responses={200: OpenApiTypes.OBJECT, 404: OpenApiTypes.OBJECT})
    def get(self, request, token):
        qr = resolve_token(token) if TOKEN_RE.fullmatch(token) else None
        if qr is None:
            return _not_found()
        assess = request.query_params.get("assess", "").lower() in ("1", "true", "yes")
        body = build_verification(qr, assess=assess)
        record_scan(request, qr=qr, outcome=_OUTCOME.get(body["state"], "delivered"),
                    scanner_type=request.query_params.get("via", "link"), security_status=_sec_status(body.get("security")))
        return Response(body)
