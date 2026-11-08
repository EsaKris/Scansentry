"""Redirect policy for confirmed-malicious destinations (documented in README/SECURITY).

  * ScanSentry never forwards a user to a destination with a confirmed malicious finding
    (threat-intelligence match for malware/phishing). The verification page shows the policy message.
  * Weaker classifications (suspicious / high risk) are shown as warnings; the user decides.
  * Optionally (AppConfiguration `security.auto_disable_malicious`, default false) the QR code is also disabled
    by staff-level policy so it stays blocked after the cache expires. Owner/staff review follows.
"""
from apps.core.config import get_config

MALICIOUS_MESSAGE = ("This destination is listed by a threat-intelligence source as harmful. "
                     "ScanSentry will not forward you to it.")


def apply_malicious_policy(qr, check) -> None:
    if check.risk_classification != "known_malicious":
        return
    if get_config("security.auto_disable_malicious", False):
        from apps.qr_codes import services as qr_services
        from apps.qr_codes.models import QRCode
        if qr.status == QRCode.Status.ACTIVE:
            qr_services.disable_qr(qr, user=None, by_staff=True,
                                   reason="Disabled automatically: confirmed malicious destination")
