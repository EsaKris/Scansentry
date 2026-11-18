# ScanSentry user guide

*Every scan deserves protection.* ScanSentry helps you create QR codes you can manage, and understand where any QR code leads **before** you go there.
This guide describes how the product behaves. Screen names and layout come from the web and Android apps and may differ slightly.

## If you scan QR codes
**Scanning needs no account.** Open the scanner, point the camera at a code (or upload a picture of one). ScanSentry reads it and shows you what is inside.
- **Nothing opens by itself.** For a website link you see the full address, the website name, and any warnings. You choose whether to continue. Plain text, contacts, Wi-Fi details, phone numbers and email addresses are shown first and need your tap to act.
- **Dangerous codes are blocked.** Links that could run code or open local files (for example `javascript:` or `file:` links) are never opened.
- **ScanSentry QR codes** (made with ScanSentry's own links) show a verification page first: who published it, the destination, when it was last checked and what was found.

**How to read a result.** ScanSentry never says a website is "safe", because no tool can promise that. You will see one of:
| Label | Meaning |
|---|---|
| Known malicious | A trusted source reports it is dangerous. ScanSentry-managed redirects to it are blocked. Do not continue. |
| High risk | Several serious warning signs. Strongly avoid. |
| Suspicious | Some warning signs (for example a look-alike of a known brand). Be careful; never enter passwords or payment details unless you are certain. |
| Needs further verification | Not enough information to judge. Check with the organisation another way. |
| No known threat detected | Nothing bad was found by the checks that ran. This is **not** a guarantee: check the date and the list of checks. |
| Assessment unavailable | The checks could not run (for example a service was down). This is never treated as good news. |
A padlock or "https" does not prove a site is genuine, and a new website is not automatically bad. The report explains each finding in plain language and lists any check that could not be completed.

**Report a suspicious code.** Use "Report" on the result (no account needed): choose a reason (fake payment page, impersonation, a sticker placed over a real code, unexpected destination change...) and add a note. A person reviews reports; one report never marks a site malicious on its own.

**Checking a website directly.** The domain checker accepts a link or a name and shows registration details (when the registry shares them), the domain's age, its DNS and certificate health, whether the site responds, and any threat findings. "Not disclosed" and "unknown" are honest answers, not errors.

## If you create QR codes (free account)
1. **Choose a type:** website, WhatsApp, phone, email, Wi-Fi, contact card, social profile, file link, landing page, or text.
2. **Static or dynamic?** A *static* code contains its content forever and cannot be changed. A *dynamic* code contains a ScanSentry link, so you can **change where it points later without reprinting**, pause it, set an expiry, and see scans.
3. **Style it:** colours, a logo, a frame and call-to-action. ScanSentry checks contrast and spacing so the code still scans; if a design is risky you are told why. Download as PNG, SVG or PDF.
4. **Manage:** edit the destination (the change history is kept), pause or reactivate, disable, expire. A paused or disabled code never silently sends people to its old address. If ScanSentry finds that your code's destination has become dangerous, you are alerted and, depending on settings, the code may be disabled. If a staff member disables a code for abuse you cannot re-enable it.
5. **Analytics:** total scans, trends, device and browser type, broad region where available, and how many warnings were shown. ScanSentry does **not** store scanners' IP addresses or identify individuals.

## Plans, limits, credits and ads
- Free accounts have **usage limits** (for example domain checks per day) and may see **clearly labelled advertisements** on non-critical pages (dashboard, library). Paid plans can remove ads. Prices and limits are shown on the pricing page; if pricing is switched off you will not see purchase options.
- **Ads never appear** while scanning, on results or warnings, on verification pages, while creating or downloading a QR, or on security alerts.
- **Limit reached?** You see which limit, how much you used, **exactly when it resets**, your credit balance, and your choices: wait, upgrade (when available), or **optionally** watch a rewarded video for ScanSentry Credits.
- **ScanSentry Credits** are usage units, not money: no cash value, they cannot be withdrawn, transferred, sold or used to pay for a plan, and they may expire. You are told the exact reward before any video starts, and nothing plays unless you choose it. Credits are added only after the ad provider confirms you completed the video; closing it early or a failed ad costs you nothing.
- **Scanning, decoding and every security warning are always free**, with no ad and no credits needed.

## Your account and privacy
You can edit your profile, verify your email, reset your password, change notification preferences, and request account deletion. See the privacy policy for what is collected and how long it is kept.
