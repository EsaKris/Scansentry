"""Coarse User-Agent classification. The raw string is never stored."""
import re

_BOT = re.compile(
    r"bot\b|bot/|crawl|spider|slurp|facebookexternalhit|^whatsapp/|telegrambot|slackbot|discord|linkedinbot|"
    r"twitterbot|embedly|curl/|wget/|python-requests|go-http-client|headless|uptime|monitor|preview", re.I)
_TABLET = re.compile(r"ipad|tablet|kindle|silk/|(android(?!.*mobile))", re.I)
_MOBILE = re.compile(r"mobi|iphone|ipod|android|windows phone", re.I)


def classify(user_agent: str) -> dict:
    ua = (user_agent or "").strip()[:512]
    if not ua:
        return {"device": "unknown", "browser": "other", "is_bot": False}
    if _BOT.search(ua):
        return {"device": "unknown", "browser": "other", "is_bot": True}
    device = "tablet" if _TABLET.search(ua) else "mobile" if _MOBILE.search(ua) else "desktop"
    low = ua.lower()
    if "edg/" in low or "edga/" in low or "edgios/" in low:
        browser = "edge"
    elif "opr/" in low or "opera" in low:
        browser = "opera"
    elif "samsungbrowser" in low:
        browser = "samsung"
    elif "firefox" in low or "fxios" in low:
        browser = "firefox"
    elif "chrome" in low or "crios" in low:
        browser = "chrome"
    elif "safari" in low:
        browser = "safari"
    else:
        browser = "other"
    return {"device": device, "browser": browser, "is_bot": False}
