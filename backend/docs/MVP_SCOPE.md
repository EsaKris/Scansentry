# What is outside the MVP, and what remains

The PRD asks for a list of features that remain intentionally outside the MVP. This is it, with the reason, so nothing is silently dropped.

## Not built yet (the big items)
| Item | Status | Notes |
|---|---|---|
| **Web application** (React) | not started | assigned to the web teammate; the API and `openapi.yaml` are ready |
| **Android application** (React Native/Expo) | not started | needs a development build for Google Mobile Ads; UMP consent flow |
| **Live integration testing** | not done | `SANDBOX_TESTING.md` |
| **Real deployment** | not done | `DEPLOYMENT.md` was exercised in a sandbox only; the Docker image was not built |

## Backend features deferred
| Item | Why deferred / impact |
|---|---|
| Domain-report PDF/CSV export | the `domain.reports.export` entitlement exists but there is no endpoint; **first gap to fix** |
| Account-deletion processing and user data export | requests are recorded only; a legal exposure in many regions (`PRIVACY_AND_DATA.md`) |
| Email change, session/device management | not needed for a first launch; add before wide release |
| Google Play Billing and Stripe adapters | **Play Billing is required to sell subscriptions inside the Android app**; Paystack/Flutterwave cover web payments |
| Proration for plan changes | downgrades to Free are "cancel at period end" |
| Catalogue entitlements with no enforcement yet | `qr.scans.monthly_limit`, `qr.custom_branding`, `qr.bulk_generation` (and no bulk endpoint), `qr.custom_domains`, `api.access`/`api.monthly_requests` (no API keys), `organization.team_members`, `security.advanced_checks`, `security.history`. Do not sell these as plan features until enforced |
| Organisations/teams | modelled, not enforced: no invitations, shared libraries or organisation billing |
| Credits beyond domain lookups | only `domain.lookups` is credit-funded; AI explanations and report export need usage counters first |
| Web rewarded ads with provider verification | impossible with Google today (server-side verification is app-only); client-attested mode exists, off by default |
| Live ad-provider reporting (AdMob/Ad Manager APIs) | only imported/entered figures are supported; the admin never invents numbers |
| WHOIS fallback | RDAP only |
| Hosted landing-page builder; PDF/file hosting; logo in previews/SVG | the landing QR type points at a URL you host |
| Celery workers | domain/security checks, emails and notifications run inside requests; move to Celery + Redis at scale |
| Analytics roll-ups | computed live from events; add roll-ups if volume grows; "unique" figures are daily estimates |
| Automatic reward-abuse suspension, device attestation (Play Integrity) | there is a threshold flag and a manual suspension switch |
| Penetration test / independent security review | strongly recommended before real money or users (`SECURITY.md`) |
| CI pipeline | a workflow file is provided in `ci/` but was never run |

## Decisions that only the product owner can make
Plans, prices, limits, trial lengths; whether to enable client-attested web rewards; the brand list for look-alike detection; `security.auto_disable_malicious`; staff roles; the privacy policy and terms; target regions.
