# Data inventory (input for your privacy policy and the Google Play Data safety form)

**This is engineering documentation, not legal advice.** A privacy policy, terms of service and the store disclosures must be written or reviewed by someone qualified for the regions you serve. Use this to make them accurate.

## What the backend stores
| Data | Why | Retention (default, admin-configurable) |
|---|---|---|
| Account: email, display name, password hash, verified flag | sign-in, alerts | until deletion (see gap below) |
| QR codes: name, description, type, destination/payload, generated image, owner | the service | until the owner deletes them |
| Destination-change history | accountability for dynamic codes | with the QR code |
| Scan events (time, device/browser *category*, approximate country/region if a CDN header is configured, security status) | owner analytics | 395 days |
| Visitor "uniqueness" hash | unique-scan estimates | rotates daily; the raw IP, user agent and URL are **never** stored |
| Security checks and domain assessments (host, evidence) | reports and history | 90 / 365 days. Query strings and fragments are stripped before storage |
| Abuse reports (category, text, optional image evidence) | moderation | until review plus your policy; reporter IP kept only as a keyed hash |
| Notifications and preferences | alerts | 180 days |
| Subscriptions, payments (provider references, amounts) | billing, accounting | as required by law/accounting: keep; card numbers are never stored (the provider holds them) |
| Usage counters | enforce limits | 400 days |
| ScanSentry Credits ledger | the wallet record | kept (it is the balance record) |
| Rewarded-ad sessions / provider callback records | reward verification, abuse review | unrewarded sessions 90 days; callback records 30 days (no IP, no signature); rewarded sessions kept |
| Audit log of administrative changes | accountability | kept |
| Application logs (JSON) | operations | set by your log host; paths only, no query strings, tokens or IPs from the app/gunicorn |

## Who receives data
| Recipient | What they get | Notes |
|---|---|---|
| Supabase / your database host | everything above | processor; choose the region deliberately |
| Container host, Redis, object storage | request traffic, counters, uploaded images | processors |
| Google Web Risk (if enabled) | the URL without query string/fragment | commercial licence required |
| AI provider (if enabled) | a structured evidence summary, no query strings or personal data | optional; the product works without it |
| Paystack / Flutterwave | payment details you enter on **their** page; amounts and references | processors; webhooks verified |
| Google AdMob / Ad Manager / AdSense (if enabled) | device advertising identifiers and ad interaction data, subject to consent | needs consent management (UMP on Android); declare in Data safety |
| Sentry (if enabled) | error traces scrubbed of query strings, bodies, cookies, headers, identity | optional |
| Email provider | recipient address and message | verification, reset, alerts |
| Your CDN/proxy | may log full URLs including query strings | configure retention; see `DEPLOYMENT.md` |

## Facts worth stating plainly in the policy
- Scanning works without an account; the content you scan is analysed to check it, and query strings are removed before storage or before anything is sent to a third party.
- No selling of personal data is built into the product. Advertising, where enabled, is run by the ad provider under their policies and your consent choices.
- Credits have no cash value. Rewarded ads are optional.
- Analytics never store IP addresses, user agents or URLs, and do not identify individuals.

## Known gaps to close before launch (legal exposure)
- **Account-deletion requests are recorded but not processed automatically, and there is no data-export endpoint.** Handle manually and document it, or build it (see `MVP_SCOPE.md`).
- Email change and session/device management are not implemented.
- The Data safety form must reflect ads (identifiers, interaction data) if ads are enabled, payments, and account data.
- Confirm your obligations for ad consent (e.g. GDPR/ePrivacy in the EU/UK, other regions) and payments in your launch countries.
