"""QR content types. Each type validates its own input and builds the encoded payload.

Add a new QR type by adding a TextChoices value, an input serializer and one registry entry.
"""
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.core.urlsafety import validate_http_url

from .models import QRCode

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class SafeText(serializers.CharField):
    """Single-line text: rejects control characters (blocks vCard/Wi-Fi field injection)."""

    def to_internal_value(self, data):
        value = super().to_internal_value(data)
        if _CONTROL.search(value):
            raise serializers.ValidationError("Control characters are not allowed.")
        return value


class HttpUrlField(serializers.CharField):
    def to_internal_value(self, data):
        value = super().to_internal_value(data)
        try:
            return validate_http_url(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)


def _phone(value: str) -> str:
    cleaned = re.sub(r"[\s().-]", "", value)
    if not re.fullmatch(r"\+?\d{6,15}", cleaned):
        raise serializers.ValidationError("Enter a valid phone number (6-15 digits, optional +).")
    return cleaned


class PhoneField(serializers.CharField):
    def to_internal_value(self, data):
        return _phone(super().to_internal_value(data))


# ---- input serializers -------------------------------------------------------------
class UrlData(serializers.Serializer):
    url = HttpUrlField(max_length=2048)


class WhatsAppData(serializers.Serializer):
    phone = PhoneField(max_length=30)
    message = serializers.CharField(max_length=500, required=False, allow_blank=True, default="")


class PhoneData(serializers.Serializer):
    phone = PhoneField(max_length=30)


class EmailData(serializers.Serializer):
    address = serializers.EmailField(max_length=254)
    subject = SafeText(max_length=200, required=False, allow_blank=True, default="")
    body = serializers.CharField(max_length=1000, required=False, allow_blank=True, default="")


class WifiData(serializers.Serializer):
    ssid = SafeText(max_length=32)
    password = SafeText(max_length=63, required=False, allow_blank=True, default="")
    security = serializers.ChoiceField(choices=["WPA", "WEP", "nopass"], default="WPA")
    hidden = serializers.BooleanField(default=False)

    def validate(self, attrs):
        if attrs["security"] != "nopass" and not attrs["password"]:
            raise serializers.ValidationError({"password": "A password is required for this security type."})
        return attrs


class VCardData(serializers.Serializer):
    first_name = SafeText(max_length=60, required=False, allow_blank=True, default="")
    last_name = SafeText(max_length=60, required=False, allow_blank=True, default="")
    organization = SafeText(max_length=120, required=False, allow_blank=True, default="")
    title = SafeText(max_length=120, required=False, allow_blank=True, default="")
    phone = PhoneField(max_length=30, required=False, allow_blank=True, default="")
    email = serializers.EmailField(max_length=254, required=False, allow_blank=True, default="")
    url = HttpUrlField(max_length=2048, required=False, allow_blank=True, default="")

    def validate(self, attrs):
        if not (attrs["first_name"] or attrs["last_name"] or attrs["organization"]):
            raise serializers.ValidationError("Provide at least a name or an organization.")
        return attrs


SOCIAL_PLATFORMS = {
    "instagram": "https://www.instagram.com/{h}",
    "x": "https://x.com/{h}",
    "facebook": "https://www.facebook.com/{h}",
    "tiktok": "https://www.tiktok.com/@{h}",
    "youtube": "https://www.youtube.com/@{h}",
    "linkedin": "https://www.linkedin.com/in/{h}",
    "github": "https://github.com/{h}",
}


class SocialData(serializers.Serializer):
    platform = serializers.ChoiceField(choices=sorted(SOCIAL_PLATFORMS))
    handle = serializers.RegexField(r"^[A-Za-z0-9._-]{1,60}$", max_length=60)


class TextData(serializers.Serializer):
    text = serializers.CharField(max_length=1000)


# ---- payload builders -----------------------------------------------------------------
@dataclass
class Built:
    payload: str
    destination: str = ""  # https URL a dynamic code may point to; empty if not URL-like


def _esc_wifi(v: str) -> str:
    return re.sub(r'([\\;,:"])', r"\\\1", v)


def _esc_vcard(v: str) -> str:
    return v.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _build_url(d):
    return Built(d["url"], d["url"])


def _build_whatsapp(d):
    digits = d["phone"].lstrip("+")
    url = f"https://wa.me/{digits}"
    if d["message"]:
        url += f"?text={quote(d['message'], safe='')}"
    return Built(url, url)


def _build_phone(d):
    return Built(f"tel:{d['phone']}")


def _build_email(d):
    q = []
    if d["subject"]:
        q.append(f"subject={quote(d['subject'], safe='')}")
    if d["body"]:
        q.append(f"body={quote(d['body'], safe='')}")
    return Built(f"mailto:{d['address']}" + (f"?{'&'.join(q)}" if q else ""))


def _build_wifi(d):
    pw = "" if d["security"] == "nopass" else _esc_wifi(d["password"])
    return Built(f"WIFI:T:{d['security']};S:{_esc_wifi(d['ssid'])};P:{pw};H:{'true' if d['hidden'] else 'false'};;")


def _build_vcard(d):
    fn = " ".join(p for p in (d["first_name"], d["last_name"]) if p) or d["organization"]
    lines = ["BEGIN:VCARD", "VERSION:3.0",
             f"N:{_esc_vcard(d['last_name'])};{_esc_vcard(d['first_name'])};;;",
             f"FN:{_esc_vcard(fn)}"]
    if d["organization"]:
        lines.append(f"ORG:{_esc_vcard(d['organization'])}")
    if d["title"]:
        lines.append(f"TITLE:{_esc_vcard(d['title'])}")
    if d["phone"]:
        lines.append(f"TEL:{d['phone']}")
    if d["email"]:
        lines.append(f"EMAIL:{d['email']}")
    if d["url"]:
        lines.append(f"URL:{d['url']}")
    lines.append("END:VCARD")
    return Built("\n".join(lines))


def _build_social(d):
    url = SOCIAL_PLATFORMS[d["platform"]].format(h=d["handle"])
    return Built(url, url)


def _build_text(d):
    return Built(d["text"])


@dataclass(frozen=True)
class QRTypeSpec:
    serializer: type
    build: Callable[[dict], Built]
    dynamic_capable: bool


REGISTRY: dict[str, QRTypeSpec] = {
    QRCode.Type.URL: QRTypeSpec(UrlData, _build_url, True),
    QRCode.Type.WHATSAPP: QRTypeSpec(WhatsAppData, _build_whatsapp, True),
    QRCode.Type.PHONE: QRTypeSpec(PhoneData, _build_phone, False),
    QRCode.Type.EMAIL: QRTypeSpec(EmailData, _build_email, False),
    QRCode.Type.WIFI: QRTypeSpec(WifiData, _build_wifi, False),
    QRCode.Type.VCARD: QRTypeSpec(VCardData, _build_vcard, False),
    QRCode.Type.SOCIAL: QRTypeSpec(SocialData, _build_social, True),
    QRCode.Type.FILE: QRTypeSpec(UrlData, _build_url, True),
    # Custom landing pages: for now a link to a page the owner hosts. A hosted landing-page
    # builder is a later feature; the type exists so the API does not change then.
    QRCode.Type.LANDING: QRTypeSpec(UrlData, _build_url, True),
    QRCode.Type.TEXT: QRTypeSpec(TextData, _build_text, False),
}
