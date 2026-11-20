# ScanSentry — Backend (Milestones 1–9: …, Advertising, Rewarded ads & Credits, Release hardening)

Django 5.2 + Django REST Framework API shared by the web and Android clients.

## What works now
- Custom user model (UUID id, email login, case-insensitive unique email)
- JWT auth: register, login, refresh (rotating + blacklist), logout
- Email verification, password reset (no account enumeration), account deletion request
- Rate limiting on auth endpoints, structured JSON errors
- Organizations + memberships (data model only), `AppConfiguration` (DB-backed settings), read-only `AuditLog`
- `/api/v1/health/`, `/api/v1/config/` (public settings only)
- OpenAPI schema + Swagger UI + Redoc
- **QR engine (Milestone 2):** 10 QR types, static + dynamic codes, secure random tokens,
  destination editing with append-only history, pause / activate / disable / expiry,
  campaigns, logo upload, PNG / SVG / PDF export, live preview, scannability checks
- **Scanner (Milestone 3):** server-side image decoding, content analysis for every QR payload type,
  dangerous-scheme blocking, ScanSentry link resolution, public abuse reporting with moderator review
- **Domain intelligence (Milestone 4, part A):** SSRF-safe network layer, RDAP registration data, DNS /
  TLS / website checks, registration-status and hosting-status classification, versioned Domain Health
  score, cached assessments with history
- **Security engine (Milestone 4, part B):** 22 admin-tunable rules, weighted risk score with a weak-indicator cap,
  threat-intelligence provider adapters, redirect tracing for shortened links, AI-assisted explanations with strict
  validation, a block-on-malicious redirect policy, scheduled re-checks
- **Analytics & notifications (Milestone 5):** privacy-conscious scan analytics, atomic usage counters, owner security
  alerts, in-app notifications with email preferences, activity history, data-retention enforcement
- **Pricing & subscriptions (Milestone 6):** database-driven plans, prices and feature entitlements, a global pricing switch,
  subscription lifecycle, Paystack and Flutterwave adapters with signed, idempotent, re-verified webhooks, admin overrides,
  role-based administration
- **Advertising (Milestone 7):** one server-side ad-eligibility decision for web and Android, admin-controlled switches and
  placements, ad-free plans, trial rules, consent hints, and ad-free security screens enforced by the backend
- **Rewarded ads & ScanSentry Credits (Milestone 8):** append-only credit ledger and wallet, admin-configured rewarded offers, single-use
  server-created ad sessions, AdMob server-side-verified rewards (ECDSA), caps/cooldowns, credit-funded extra usage, limit-screen data,
  audited admin adjustments and reporting
- **Release hardening (Milestone 9):** production settings that fail closed, shared Redis rate limits, structured JSON logs with request ids, privacy-scrubbed Sentry,
  private object storage, admin sign-in throttle, non-root container, smoke test, backup/restore scripts, RLS script, deployment/operations docs, PostgreSQL + concurrency testing
- 1194 automated tests (1188 on SQLite + 6 PostgreSQL-only concurrency tests), run on both databases (generated codes are decoded back; the SSRF guard, security, privacy, isolation, billing and advertising
  rules are tested against a fake internet with real TLS handshakes and simulated payment providers, and mutation-checked)

## Quick start (local, SQLite)
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements/dev.txt
cp .env.example .env            # then edit DJANGO_SECRET_KEY
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
pytest
```
Docs: http://localhost:8000/api/v1/docs/ · Admin: http://localhost:8000/admin/

## Using Supabase as the database
1. In Supabase: Project Settings → Database → copy the connection string.
2. Put it in `.env` as `DATABASE_URL` and set `DB_SSL_REQUIRE=true`.
3. Run `python manage.py migrate` using the direct or session-pooler string (port 5432).
4. If you run the app through the transaction pooler (port 6543), also set
   `DB_DISABLE_SERVER_SIDE_CURSORS=true`.
5. **Important:** Django owns these tables. In the Supabase SQL editor, enable Row Level
   Security on every table (with no public policies), or turn off the Data API, so the
   Supabase REST API cannot be used to bypass Django's permission checks.
6. Do not use Supabase Auth; Django is the only auth system.

## Postman
1. Export the schema: `python manage.py spectacular --file openapi.yaml` (a copy is included).
2. In Postman: Import → select `openapi.yaml`. You get a full collection.
3. Share the workspace with the web developer. They can use a Postman mock server to build
   against endpoints before they exist. Re-export and re-import when endpoints change.

## Endpoints (v1)
| Method | Path | Notes |
|---|---|---|
| POST | /api/v1/auth/register/ | Same response whether or not the email exists |
| POST | /api/v1/auth/login/ | email + password → access/refresh |
| POST | /api/v1/auth/logout/ | blacklists the refresh token |
| POST | /api/v1/auth/token/refresh/ | rotates refresh token |
| POST | /api/v1/auth/verify-email/ | token from email |
| POST | /api/v1/auth/password-reset/ | always 200 |
| POST | /api/v1/auth/password-reset/confirm/ | uid + token + new_password |
| GET/PATCH | /api/v1/auth/me/ | PATCH only changes display_name |
| POST | /api/v1/auth/me/deletion-request/ | recorded + audited |
| GET | /api/v1/health/ | DB check, 503 if degraded |
| GET | /api/v1/config/ | only `is_public` settings |

## QR endpoints (Milestone 2)
| Method | Path | Notes |
|---|---|---|
| POST | /api/v1/qr/ | Create. Body: `name`, `qr_type`, `code_mode`, `data{}`, optional `style`, `expires_at`, `campaign` |
| GET | /api/v1/qr/ | List own codes. Filters: `status`, `qr_type`, `code_mode`, `campaign`; `search`; `ordering` |
| GET/PATCH/DELETE | /api/v1/qr/{id}/ | PATCH: name, description, style, expires_at, campaign, and `current_destination` (dynamic only) |
| POST | /api/v1/qr/{id}/pause/ · activate/ · disable/ | Lifecycle. Disabled is final for the owner |
| GET | /api/v1/qr/{id}/history/ | Destination-change history |
| POST/DELETE | /api/v1/qr/{id}/logo/ | multipart `logo`; re-encoded to PNG, metadata stripped |
| GET | /api/v1/qr/{id}/image/{png\|svg\|pdf}/ | add `?download=1` for an attachment |
| POST | /api/v1/qr/preview/ | PNG preview without saving |
| GET/POST/... | /api/v1/campaigns/ | Owner-scoped folders/campaigns |

`data` per type: `url{url}` · `whatsapp{phone,message}` · `phone{phone}` · `email{address,subject,body}`
· `wifi{ssid,password,security,hidden}` · `vcard{first_name,last_name,organization,title,phone,email,url}`
· `social{platform,handle}` · `file{url}` · `landing{url}` · `text{text}`.
Only url, whatsapp, social, file and landing can be dynamic.

Set `REDIRECT_BASE_URL` to the public domain that will serve `/r/<token>` (the web app).

### Design decisions to know about
- **No auto-redirect.** `/scanner/verify/{token}/` returns state + destination (only while active
  and unexpired) with `requires_user_confirmation: true`. The web/mobile verification page decides
  what to show; the security block says `assessment_not_available` until Milestone 4.
- **Entitlements are a stub.** Limits/feature flags are read from an `AppConfiguration` row named
  `default_entitlements`, e.g. `{"qr.dynamic.active_limit": 5, "qr.svg_export": false}`. Missing keys mean
  allowed/unlimited. Milestone 6 swaps in plan-based lookups without changing feature code.
- **Images render on demand** (deterministic from stored payload + style), so there is no
  `generated_image` file to keep in sync.
- **Staff-disabled codes** cannot be re-enabled or edited by the owner; use the admin actions.
- Logo is not included in `preview/` or SVG export (PNG/PDF only).

## Scanner endpoints (Milestone 3) — all public, no account needed
| Method | Path | Notes |
|---|---|---|
| POST | /api/v1/scanner/decode/ | multipart `image` (PNG/JPEG/WebP, ≤5 MB). Returns each decoded code **with its analysis**. Nothing is stored |
| POST | /api/v1/scanner/analyze/ | JSON `{"content": "..."}` — use this when the web/mobile client decodes the camera frame itself |
| GET | /api/v1/scanner/verify/{token}/ | Verification data for a ScanSentry dynamic token |
| POST | /api/v1/scanner/report/ | Abuse report: `qr_token` or `url`, `category`, `description`, optional `evidence` image |

**Analysis response** (`analyze` and each `decode` result):
- `kind`: `url` · `phone` · `email` · `wifi` · `vcard` · `text` · `blocked_scheme` · `unsupported_scheme`
- `preview`: human-readable content (Wi-Fi never echoes the password, only `password_present`)
- `url`: host, punycode + display host, `is_idn`, `mixed_scripts`, `is_ip_address`, `uses_https` …
- `observations`: neutral facts such as `mixed_scripts`, `redirect_parameter`, `embedded_credentials`.
  These are **not verdicts**; the security engine (Milestone 4) turns facts into risk findings
- `scansentry`: for ScanSentry links — `state`, publisher, and destination (only while active)
- `actions`: `can_open`, `open_target`, `blocked`, `block_reason`, and `requires_user_confirmation: true`
- `security.status` is `assessment_not_available` until Milestone 4

The client must show the analysis and only open `actions.open_target` after the user taps a confirm button.
Analysis performs **no network access** (a test enforces this).

**Abuse reports**: stored for moderators in the admin. Reports never change a QR code or mark a
domain malicious by themselves. The same reporter repeating the same report within
`ABUSE_DEDUPE_HOURS` is stored once; different reporters are linked as duplicates. The
reporter's IP is kept only as a keyed hash.

### Deployment note: `NUM_PROXIES`
Rate limits use the client address. Behind a reverse proxy/load balancer set `NUM_PROXIES` to the
number of trusted proxies; with the default `0`, `X-Forwarded-For` is ignored so it cannot be spoofed.

## Domain intelligence endpoints (Milestone 4A)
| Method | Path | Notes |
|---|---|---|
| POST | /api/v1/domains/analyze/ | **Public** (rate-limited). `{"value": "<url or domain>", "refresh": false}`. Signed-in users also get history and may `refresh` |
| GET | /api/v1/domains/assessments/{id}/ | A stored assessment by its unguessable id |
| GET | /api/v1/domains/history/ | The signed-in user's lookups (`?domain=` filter) |

**What an assessment contains:** `registration` (RDAP: created / expires / updated, `age_days`, `age_group`,
registrar, nameservers, `raw_status_flags`, normalised `status` + explanation, `not_disclosed` fields),
`dns`, `tls`, `website` (`hosting_status`, HTTP status, redirects, evidence, confidence),
`scores.domain_health`, `missing_checks`, `provider_errors`, `completion_status`
(`complete`/`partial`/`failed`), `confidence`, `limitations`. `scores.security_risk` is `null` until Part B.

**Registration statuses:** `REGISTERED_ACTIVE` · `REGISTRY_HOLD` · `REGISTRAR_HOLD` · `REDEMPTION_PERIOD` ·
`PENDING_DELETION` · `INACTIVE_OR_UNDELEGATED` · `EXPIRED_OR_NOT_RENEWED` (only when the expiry date is evidence) ·
`NOT_FOUND` · `UNKNOWN` · `LOOKUP_UNAVAILABLE`. Transfer/delete/update locks are *not* suspensions.
**Website statuses:** `WEBSITE_RESPONDING` · `WEBSITE_UNAVAILABLE` · `DNS_FAILURE` ·
`HOSTING_SUSPENSION_SUSPECTED` (low confidence) · `HOSTING_SUSPENSION_INDICATOR_DETECTED` (medium, heuristic) · `UNKNOWN`.
An HTTP 403/404/5xx, a timeout or a DNS error alone never produces a suspension status, and nothing is ever
called "confirmed".

**Configurable without a deploy** (rows in `AppConfiguration`, via the admin):
| Key | Meaning | Default |
|---|---|---|
| `domain.cache_hours` | how long a complete assessment is reused | 24 |
| `domain.error_cache_minutes` | cache for partial/failed assessments | 15 |
| `domain.rdap_cache_hours` | how long registry answers are reused | 24 |
| `domain.age_thresholds_days` | `{"newly_registered":30,"recently_registered":180,"established":1825}` | as shown |
| `domain.health_weights` | `{"registration":30,"dns":25,"tls":20,"website":20,"configuration":5}` | as shown |
| `default_entitlements` | e.g. `{"domain.lookups.daily_limit": 10, "domain.lookups.weekly_limit": ..., "domain.lookups.monthly_limit": ...}` | unlimited |

**Live smoke test (run this from the server's network before launch):**
```bash
python manage.py assess_domain example.com          # readable summary
python manage.py assess_domain example.com --json   # full result
```
Every line should show a real status; any `MISSING CHECK` or `PROVIDER ERROR` tells you which outbound dependency
(RDAP bootstrap, DNS resolver, port 443/80 egress) is blocked.

**Design rules to keep when extending**
- Only `/` of a host is ever requested. A submitted URL's path/query is never sent anywhere (it may hold secrets
  or trigger actions).
- **All outbound HTTP goes through `NetGuard`** (`apps/domain_intel/netsafe.py`): see SECURITY.md.
- Check functions run in worker threads and must not touch the database.
- Missing data is `null` / `not_disclosed` and listed in `missing_checks`. Never a default "clean" value.
- WHOIS fallback is **not** implemented (port-43 egress and per-registry terms); RDAP only.
- Security checks run synchronously (domain checks run in parallel; worst case about 30 s). Move to Celery if needed.

## Security engine endpoints (Milestone 4B)
| Method | Path | Notes |
|---|---|---|
| POST | /api/v1/security/analyze/ | **Public** (rate-limited). `{"url": "...", "trace": true, "ai": false}` |
| GET | /api/v1/security/checks/{id}/ | A stored check by its unguessable id |
| GET | /api/v1/security/providers/ | **Admins only.** Provider status, usage and health. Never returns credentials |
| POST | /api/v1/scanner/analyze/ | now accepts `"assess": true` (also on `decode/`) to include the security assessment |
| GET | /api/v1/scanner/verify/{token}/?assess=1 | verification with a fresh security assessment of the destination |

**Classifications** (`classification`, with a human `classification_label`):
`known_malicious` · `high_risk` · `suspicious` · `needs_further_verification` · `no_known_threat_detected` ·
`assessment_unavailable`. There is deliberately no "safe".
- `known_malicious` comes **only** from a threat-intelligence match for malware/phishing, never from a score
- `no_known_threat_detected` is only returned when an *external* threat-intelligence source answered successfully,
  the real destination was reached (redirect trace OK), and no rule crashed. Otherwise the result is
  `needs_further_verification` (or `assessment_unavailable` if nothing external could run)
- weak indicators (domain age, URL shortener, no HTTPS, unusual TLD, international host name) can add up to
  `suspicious` but are capped below `high_risk`; `high_risk` needs one strong indicator or two moderate ones

**Response highlights:** `findings` (rule key, `reason_code`, severity, strength, weight, evidence, recommended action,
rule version), `risk_score`, `confidence`, `missing_checks`, `provider_errors`, `threat_intelligence.providers`
(per-provider status), `domain` summary, `redirect_trace`, `explanation`, `scoring` (versions, ruleset hash, thresholds),
`limitations`.

**Rules** are defined in `apps/security_engine/rules.py` (detection logic) and tuned in the admin (**Security rules**:
enable/disable, weight, severity, thresholds). Categories: URL structure (malformed, dangerous/unsupported scheme,
credentials, encoded host, IP / obfuscated IP, IDN, mixed alphabets, excessive sub-domains, unusual encoding, redirect
parameter, shortener, unusual TLD), impersonation (brand look-alike, brand + sensitive keyword), redirect chain, TLS
(no HTTPS, invalid certificate), domain (registry hold, recently registered, resolves to private address) and threat
intelligence (malware, phishing, unwanted software, suspicious listing). Every change is audited.

**Configurable without a deploy** (`AppConfiguration` rows):
| Key | Meaning | Default |
|---|---|---|
| `security.risk_thresholds` | `{"suspicious":35,"high_risk":65,"weak_only_cap":49}` | as shown |
| `security.cache_minutes` | reuse of complete checks (incomplete: 5 min) | 30 |
| `security.malicious_cache_hours` | how long a malicious finding keeps blocking | 24 |
| `security.brand_domains` | brands protected from look-alikes (starter list is built in; extend for your market) | built-in list |
| `security.url_shorteners` / `security.unusual_tlds` | lists used by the shortener / TLD rules | built-in lists |
| `security.trace_shorteners` | follow redirects of known shorteners | true |
| `security.auto_disable_malicious` | also disable the QR code on a confirmed malicious destination | false |
| `default_entitlements` → `ai.explanations` | allow AI-worded explanations | allowed |

### Threat-intelligence providers
Managed in the admin (**Threat providers**): enable, timeout, retries, rate limit, `config` (e.g. `{"cache_ttl_seconds": 0}`),
and the *name* of the environment variable that holds the key (secrets are never stored in the database). Usage metrics
count every API call, including retries. Seeded on migrate:
| Provider | Default | Notes |
|---|---|---|
| `local_blocklist` | on | Staff-managed entries (admin → Threat indicators, provider `local_blocklist`). Not an external source, so it can block but cannot by itself justify "no known threat" |
| `google_web_risk` | off | **Commercially licensed** Google Cloud service (paid). To activate: create a Google Cloud project with billing, enable the Web Risk API, create an API key, set `THREAT_INTEL_API_KEY`, then enable it in the admin |
| `test_fixture` | off | Controlled test data under `example.com`. **Keep disabled in production** |

VirusTotal's public API and the free Google Safe Browsing API are non-commercial and are intentionally not included.
A provider that fails (timeout, rejected key, rate limit, outage, unparsable answer) is reported in `provider_errors` and
`missing_checks`; it is never turned into a clean result. Findings are saved (provider, reference, timestamps) as
`ThreatIndicator` evidence; saved external findings are *not* re-served as a blocklist.

### Redirect policy for confirmed-malicious destinations
ScanSentry **never forwards a user** to a destination with a confirmed malicious finding. The verification response then
has `state: "blocked"`, no `destination`, and the policy message; the scanner marks the action `blocked`. Suspicious and
high-risk results are warnings; the user decides. The finding is cached per destination URL (query ignored) and kept for
`security.malicious_cache_hours`. To keep codes blocked after that, schedule:
```bash
python manage.py recheck_destinations --limit 200   # e.g. hourly (cron / Celery beat)
```
and optionally set `security.auto_disable_malicious` so the code is disabled at staff level (the owner cannot undo it).

### Redirect tracing
Only for known URL shorteners (list above). The trace follows redirects through the same SSRF guard, flags loops, forbidden
destinations and many unrelated domains, and the **final destination** is then assessed. Stored traces contain
query-stripped URLs only.

### AI explanations (optional)
A deterministic, rule-based explanation always exists. If `AI_PROVIDER=anthropic` and `AI_API_KEY` are set, signed-in users
can request `"ai": true`. The model receives only a small whitelisted evidence object: host, rule keys and their static
meaning, severities, counts, statuses. **No paths, query strings or user data.** Its reply must pass strict validation
(known finding keys only, same classification, no safety claims, length limits); otherwise the rule-based text is returned
with an `ai_error` note. The AI can never change a classification. Set `AI_MODEL` (default `claude-sonnet-5-5`; verify the
current name in Anthropic's docs). Anonymous requests never call the AI.

### Privacy
Query strings and fragments are removed before storage and before anything goes to a threat provider or the AI.

## Analytics, usage, notifications & activity (Milestone 5)
| Method | Path | Notes |
|---|---|---|
| GET | /api/v1/analytics/overview/ | Totals, change vs previous period, code counts, top codes, devices |
| GET | /api/v1/analytics/scans/ | Time series + breakdowns. `days` or `from`/`to`, `granularity=day\|week\|month`, `tz=Africa/Lagos`, `qr=<id>`, `export=csv` |
| GET | /api/v1/analytics/qr-performance/ | Per-code table + campaign comparison (`export=csv`) |
| GET | /api/v1/qr/{id}/analytics/ | One code (owner only) |
| GET | /api/v1/usage/overview/ · /usage/limits/ | Used / limit / remaining and the exact reset time (UTC) per window |
| GET | /api/v1/notifications/ | `?unread=true&kind=&severity=` |
| POST | /api/v1/notifications/{id}/read/ · /notifications/read-all/ | |
| GET | /api/v1/notifications/unread-count/ | `unread`, `critical_unread` |
| GET/PATCH | /api/v1/notifications/preferences/ | Email preferences only (see below) |
| GET | /api/v1/qr/{id}/activity/ · /api/v1/activity/ | Audit trail of one code / of the signed-in user |

**What is recorded per scan** (`ScanEvent`): time, outcome (delivered / paused / disabled / expired / blocked / analysed),
device category, browser family, scanner type (camera / upload / link), security status at scan, optional country/region,
and a daily-rotating visitor hash. **Never stored:** IP address, user agent, URL or any scanned content.
- *Unique estimates* use `HMAC(secret, date|IP|UA)` truncated to 16 hex characters. It is keyed, rotates every UTC day and
  cannot be linked across days or reversed, so it estimates "unique scans per day" without identifying anyone.
  Multi-day uniques are the sum of daily uniques (documented in every response's `privacy_note`)
- *Country/region* are recorded only when your CDN/proxy supplies them: set `GEO_COUNTRY_HEADER` (e.g. `CF-IPCountry`) and
  optionally `GEO_REGION_HEADER`. The proxy must strip these headers from client requests. Off by default; nothing is
  derived from the IP address
- Link-preview and crawler traffic (WhatsApp, Slack, Facebook, Googlebot, curl ...) is stored flagged `is_bot` and
  excluded from all analytics. The same device scanning the same code within `ANALYTICS_DEDUPE_SECONDS` (30) counts once
- Recording can never break a scan: failures are logged and swallowed
- Scans of non-ScanSentry codes through the public scanner are stored without an owner (platform statistics only)
- Entitlements: `qr.analytics.basic` (totals, trend, device / scanner / outcome) and `qr.analytics.advanced` (browser,
  country, region, security status, campaign comparison, CSV export) are enforced on the backend; locked sections are listed in `locked`
- CSV exports neutralise spreadsheet formula injection

**Usage counters** (`UsageCounter`) are atomic per user / feature / window (UTC day, Monday-week, month). `consume()` locks
the rows, checks every limit and only then increments, so concurrent requests cannot jointly exceed a limit; a refused call
changes nothing and the error states the exact reset time. Domain lookups use it today; the entitlement keys
(`domain.lookups.daily_limit` ...) live in `default_entitlements` until Milestone 6 adds plans. Bad input and anonymous checks
never use an allowance.

**Notifications**: in-app notifications are always created (they are safety information); preferences control **email only**
(`email_security_alerts`, `email_qr_status`, `email_abuse_reports`), and email is sent only to verified addresses.
Events: destination flagged (high risk / known malicious, to every owner of an active code pointing there), code disabled
by staff or by the malicious-destination policy, code restored, destination changed (in-app only), abuse report received
(category only, never the reporter), code expiring soon. Messages and payloads contain host names only, never full URLs.
Duplicates within 24 hours are suppressed. Mail failures never lose the notification.

**Activity history** shows what happened to a code, including staff and system actions. Staff are shown as
`scansentry_staff`, never by name; IP addresses are never exposed; the API is read-only.

**Retention** is enforced, not just stated. Schedule daily (and `send_expiry_reminders` daily):
```bash
python manage.py purge_old_data            # add --dry-run to preview
python manage.py send_expiry_reminders --days 3
```
Configurable via `AppConfiguration`: `retention.scan_events_days` (395), `retention.notifications_days` (180, read only),
`retention.security_checks_days` (90), `retention.domain_assessments_days` (365), `retention.usage_counters_days` (400).
A value of 0 is clamped to 1 day; unparsable values fall back to the default. Disclose analytics and retention in your privacy policy.

## Pricing, plans, entitlements & subscriptions (Milestone 6)
**Nothing commercial is hardcoded.** Pricing starts **OFF**; the Free plan has **no limits** until you configure it, so a fresh
install behaves exactly as before. Everything below is configured in the Django admin without a deployment.

| Method | Path | Notes |
|---|---|---|
| GET | /api/v1/plans/ | Public pricing data. Empty while pricing is off. `?currency=NGN` |
| GET | /api/v1/billing/subscription/ | Effective plan, status, period, `access_until`, `has_access` |
| GET | /api/v1/billing/entitlements/ | **The** decision web and Android use: every feature with `enabled`, `limit`, `source` |
| POST | /api/v1/billing/checkout/ | `{"plan","currency","provider"?,"start_trial"?}`. The client never sends a price |
| POST | /api/v1/billing/checkout/verify/ | `{"reference"}` — call after the provider redirects back |
| POST | /api/v1/billing/cancel/ · /resume/ | Cancel keeps access to the period end; `{"immediately": true}` ends it now |
| GET | /api/v1/billing/transactions/ | The user's own payments |
| POST | /api/v1/billing/webhooks/{provider}/ | Provider callbacks (signature-protected) |
| GET/POST | /api/v1/admin/billing/… | overview, webhook-events, overrides (+revoke), subscriptions extend / suspend / restore. Role-protected |

**Admin: where to configure what** — *Billing → Plans* (inline prices per currency and plan features), *Feature definitions*
(the catalogue: defaults, data types), *Core → App configuration* (`pricing_enabled`, `billing.*` keys). Keys:
| Key | Meaning | Default |
|---|---|---|
| `pricing_enabled` | master switch for purchasing | false |
| `billing.free_plan_slug` | the base tier | `free` |
| `billing.pricing_disabled_plan_slug` | entitlements for users **without paid access** while pricing is off (e.g. a promotional plan) | the free plan |
| `billing.enabled_providers` | e.g. `["paystack","flutterwave"]` | `["paystack"]` |
| `billing.trials_enabled` | allow trials | true |
| `billing.refund_revokes_access` | a refund ends access | true |

**How entitlements resolve** (lowest to highest priority): feature default → global baseline (`default_entitlements`, kept for
compatibility) → the user's effective plan → administrative overrides (temporary premium plan, then specific grants/revokes).
Numeric features: empty limit = unlimited, disabled = 0. Access is **time-based**, so a late job never wrongly grants or removes it:
active/past-due/grace → until period end + the plan's grace days · cancelled → until the period end · trial → trial end ·
pending/expired/suspended → none. Cancelling, a failed renewal, or switching pricing off **never** cuts short paid access;
switching pricing off leaves existing subscribers on their plans and gives everyone else the configured fallback plan.

**Payments (safety rules, all tested)**
- The amount is calculated from the **database price**; the client chooses a plan and currency only
- A payment is credited only after the provider's **API confirms success with the exact amount and currency**; a signed webhook alone is never believed
- Crediting is **idempotent** (verification, webhooks and retries together grant access once); duplicate and replayed webhooks are deduplicated
- Webhooks: bad/missing signature → 401 and nothing stored; transient trouble → 503 so the provider retries; permanent mismatches → 200 + audited; payloads stored whitelisted (no email, card data)
- Provider credentials come only from the environment; secrets are never returned or logged

**Providers**
| Provider | Status | Setup |
|---|---|---|
| Paystack | implemented | `PAYSTACK_SECRET_KEY`; webhook URL `/api/v1/billing/webhooks/paystack/`; for **automatic renewals** create a Paystack plan and store its code on the plan as `provider_refs.paystack_plan_code`. Without it, each period is one payment and the user renews by paying again |
| Flutterwave | implemented | `FLUTTERWAVE_SECRET_KEY` + `FLUTTERWAVE_WEBHOOK_HASH`; one payment per period |
| Stripe | **not implemented** | listed so the roadmap is visible |
| Google Play Billing | **not implemented** | Google's policy requires Play Billing for digital subscriptions sold inside the Android app; it needs the Google Play Developer API |

The Paystack and Flutterwave adapters were written from public documentation and tested against simulated providers:
**test them in each provider's sandbox before going live.**

**Lifecycle jobs — schedule hourly:** `python manage.py process_subscriptions` (trial end → grace → expiry, notifications).
**Demo data:** `python manage.py seed_example_plans` creates EXAMPLE plans (illustrative values only; pricing stays off).

**Admin roles** (assign in Django admin → Users → permissions). Not every staff member can touch money:
`billing.manage_pricing` (plans, features, pricing switches) · `billing.manage_subscriptions` (extend, suspend, restore) ·
`billing.grant_entitlements` (feature grants, promotions, temporary premium access) · `billing.view_payments` (payments, revenue,
webhook events). Every administrative change needs an **internal note** (≥5 characters), is written to the audit log and to the
subscription history (`SubscriptionEvent`). Pricing/billing/entitlement settings in *App configuration* are protected by
`manage_pricing`, and every config change is audited.

**Known limitations (v1):** no proration (switching plans takes effect on payment; remaining time on the old plan is not credited);
downgrading to Free is "cancel at period end"; a cancelled Paystack-managed subscription needs the provider-side cancellation to succeed
(the API reports `provider_cancellation: "failed"` and logs it if not); one currency per payment; organisation-level subscriptions are modelled but not yet enforced.

## Advertising (Milestone 7)
Advertising is a **configurable revenue stream, not part of the UI code**. The backend makes the *only* eligibility decision, so
web and Android cannot disagree, and ad-free plans and ad-free screens are enforced on the server.

| Method | Path | Notes |
|---|---|---|
| GET | /api/v1/advertising/config/ | Public, secret-free settings: switches, enabled providers' **public** ids, label, forbidden screens |
| GET | /api/v1/advertising/eligible-placements/?platform=web\|android&surface=dashboard | **The decision.** Anonymous or signed-in. Returns `eligible`, `reason`, `user_category`, `placements[]` |
| GET/PATCH | /api/v1/advertising/preferences/ | `{"personalized_ads": true\|false\|null}` (can only make ads *less* personalised) |
| GET | /api/v1/admin/advertising/overview/ · /simulate/?user=&platform=&surface= | Admins with `manage_ads`: warnings, misconfigurations, provider-reported figures; "what would this user see?" |

**Reasons** (`reason`): `ok` · `ads_disabled` · `platform_disabled` · `category_disabled` · `ad_free_entitlement` · `surface_restricted` ·
`unknown_surface` · `unknown_platform` · `no_placements`.

**Switches** (Core → App configuration; no deployment needed): `ads_enabled` (**master, OFF by default**), `ads_web_enabled`,
`ads_android_enabled`, `ads_enabled_for_free_users` / `_trial_users` / `_paid_users` / `_enterprise_users`, `ads_non_personalized_default`,
`ads_test_mode`, `ads_frequency_limits`, `ads_remove_with_premium`, `ads_enterprise_plan_slugs`. Recommended defaults are seeded
(free + trial on, paid + enterprise off). Ad networks live under *Advertising → Ad providers* and placements under *Ad placements*
(8 placements are pre-created **disabled with no ad unit ids**; fill in your real ids, then enable). Needs the `advertising.manage_ads`
permission, separate from the billing roles; changes are audited.

**Who sees ads.** Categories are `anonymous`, `free`, `trial`, `paid`, `enterprise`. A user sees ads only if the master, platform and
category switches allow it **and** their effective `ads.remove` entitlement does not remove them:
- **trials never lose ads just because the trial plan includes `ads.remove`** (trials unlock premium features but may keep showing ads
  when `ads_enabled_for_trial_users` is on). Only an explicit, individual admin grant of `ads.remove` removes ads for a trial user.
  Temporary premium access granted by an admin counts as a trial
- plan-derived ad removal follows `ads_remove_with_premium`; explicit admin grants always count
- anonymous visitors see only placements marked `allow_anonymous`
- per-placement `eligible_plan_rules`: `{"categories": [...], "include_plans": [...], "exclude_plans": [...]}`

**Screens that never show ads — enforced by the backend, not configurable.** `scanner`, `scan_result`, `verification`, `security_warning`,
`threat_result`, `security_confirmation`, `qr_generation`, `qr_download`, `redirect`, `emergency_alert`, `domain_report`. A request for any
of them returns `eligible: false, reason: surface_restricted` on both platforms, no setting can override it, a placement on such a screen
**cannot be saved**, and even a row forced into the database is never served. Only `dashboard`, `qr_library`, `analytics`, `resources`
and `account` can carry ads. No security, scanner or domain API response ever contains ad data.

**Test vs production.** In `ads_test_mode` (default ON) the API returns Google's *official test ad units* (AdMob banner/native, Ad Manager
sample path; AdSense has none, so `adtest: true` tells the client to add `data-adtest="on"`) and **never** your stored production ids. In
production mode only real ids are served: a placement with no id, or with a Google test id, is skipped and flagged in the admin overview.
Google test ids cannot be stored as production ids. Ad unit ids are public client-side values; no provider secret is stored anywhere.

**Reporting.** Provider-reported figures (`AdProviderReport`: requests, impressions, fill rate, estimated revenue) can be entered or
imported by an administrator. The overview shows them exactly as reported, or says reporting is **unavailable**. ScanSentry never
estimates or invents impression or revenue numbers, and it does not track ad impressions or clicks itself. Live provider reporting
APIs (AdMob / Ad Manager) are **not** integrated yet.

**Consent and personalisation.** Consent itself is collected by the provider's consent platform on the client: **Google UMP on Android**,
a certified CMP on web. The API returns `request_non_personalized_ads` (privacy-first default: true) and the user's own choice can only
reduce personalisation. Clients must also request non-personalised ads whenever consent is missing or refused. Disclose advertising data
processing in your privacy policy and in Google Play's Data safety form.

### Client integration (web and React Native)
1. On each screen, call `GET /advertising/eligible-placements/?platform=…&surface=<screen>` (send the bearer token when signed in).
   **Never decide eligibility on the client.** If `eligible` is false, render nothing and reserve no space
2. For each placement: load the provider SDK with `ad_unit_id` and `provider_config`, honour `frequency`, and always show the `label`
   ("Advertisement") visibly. Never style an ad like a ScanSentry warning or recommendation; reserve its height to avoid layout shift
3. Ad loading failures must never block or delay a screen: show nothing and carry on
4. Android: the Google Mobile Ads SDK **does not run in Expo Go**; use an Expo **development build** (config plugin) with the test app id
   from `provider_config.app_id`. Run the UMP consent flow before requesting ads
5. Never place ads during scanning, results, verification, warnings, QR creation/download or redirects, even if the API were asked

## Rewarded ads & ScanSentry Credits (Milestone 8)
**Credits are internal usage units: no cash value, not transferable, not withdrawable, cannot buy subscriptions.** Nothing earns or
spends credits until an administrator configures it: every switch is OFF and the credit price table is empty by default.
Scanning, decoding, public verification and security warnings **never** need credits or an ad (tested, including with a zero balance).

| Method | Path | Notes |
|---|---|---|
| GET | /api/v1/credits/balance/ | `available_balance`, lifetime totals, expiring credits, earning limits (day/week/month), `earning_suspended` |
| GET | /api/v1/credits/history/ | Own ledger, paginated, `?type=`. Read-only |
| GET | /api/v1/credits/limit-screen/?feature=domain.lookups&platform=android | Everything for a "limit reached" screen (below) |
| GET | /api/v1/credits/rewarded-offers/?platform=web\|android | Offers with `available`/`reason`, exact reward, claims left, cooldown, terms |
| POST | /api/v1/credits/rewarded-sessions/ | `{"offer","platform"}` → short-lived single-use session + client instructions. The user must opt in |
| GET | /api/v1/credits/rewarded-sessions/{id}/ | Poll after the ad: status, `credits_granted`, balance |
| POST | /api/v1/credits/rewarded-sessions/{id}/events/ | Client progress: `ad_available`, `started`, `closed_early`, `cancelled`, `no_fill`, `load_failed`, `timeout`, `client_reward_reported`. **Never grants anything** |
| POST | /api/v1/credits/rewarded-sessions/{id}/complete/ | **Web only, disabled by default** (see "Web rewards") |
| GET/POST | /api/v1/advertising/reward-callbacks/{provider}/ | Provider callback. Today `admob` (AdMob server-side verification, a GET). Signature-protected, no login |
| GET | /api/v1/admin/credits/overview/ | `view_credit_reports`: issued / spent / expired / outstanding, reconciliation, sessions and callbacks by outcome, unusual patterns, warnings |
| POST | /api/v1/admin/credits/adjust/ | `manage_credits`: `{"user","kind":"grant\|promotional\|reversal","amount","reason","expires_in_days?","request_id?"}`. Reason required, audited, idempotent by `request_id` |

**Switches** (Core → App configuration; need `advertising.manage_ads`; no deployment): `rewarded_ads_enabled` (master), `rewarded_ads_web_enabled`,
`rewarded_ads_android_enabled`, `rewarded_ads_test_mode` (default ON), `rewarded_web_client_attested_enabled` (default OFF),
`rewarded_session_ttl_seconds` (900), `rewarded_ssv_max_delay_seconds` (86400), `rewarded_attested_min_watch_seconds` (5),
`rewarded_abuse_daily_threshold` (10), `credits.feature_costs` (`{"domain.lookups": 2}`; empty = nothing is credit-funded).
**Offers** (Credits → Rewarded ad offers; changes audited): reward amount, platform, provider, eligible plans / account categories / features,
daily / weekly / monthly claim caps, cooldown, credit expiry (empty = never), schedule, production ad unit, optional country allow/block lists
(need `GEO_COUNTRY_HEADER`; an unknown country with a country rule is *not* eligible). **Credits earned per day/week/month** are capped by the
existing `credits.earn.*_limit` entitlements, **per-plan credit prices** by `credits.spend.feature_cost` (its plan-feature `configuration`,
e.g. `{"domain.lookups": 1}`; it wins over the global table) and who may earn at all by `ads.rewarded_credits`.
AdSense, banner and native providers are rejected as offer providers: ordinary ads are never a reward mechanism.

**How a reward is granted (Android, AdMob SSV).** 1) `POST rewarded-sessions/` (backend checks switches, plan, caps, cooldown; returns a token and the
`ssv` values). 2) The app sets `userIdentifier = ssv.user_id` and `customData = ssv.custom_data` on the rewarded ad, loads the unit from
`client.ad_unit_id`, and reports `ad_available` / `started`. 3) The user completes the ad. 4) Google calls `/advertising/reward-callbacks/admob/`;
the backend verifies the ECDSA signature over the raw query string with Google's rotating public keys (fetched through the SSRF guard, cached 6 h),
then checks the session, user, ad unit, timing, replay, caps and cooldown again, and writes **exactly one** ledger entry. 5) The app polls the session
until `rewarded`. Credits come from *our* offer (snapshotted at session creation), never from Google's `reward_amount`.
Callback rules: forged / tampered / unknown key → 403 and nothing changes; malformed or extra unsigned parameters → 400; key server down → 503 (Google retries);
every handled outcome incl. refusals → 200. Delayed delivery is fine: the user's reward moment must fall inside the session's life, and the callback may arrive up
to `rewarded_ssv_max_delay_seconds` later. Closing an ad early does not block a genuine completion (the provider's definition is authoritative).

**Web rewards: decision needed.** Google's Ad Manager documentation states that server-side verification *"is an app only feature and it is unavailable for web use"*.
A web completion can therefore only be **client-attested**, i.e. a determined user could fake it. So web offers are `verification_unavailable` until an
administrator turns on `rewarded_web_client_attested_enabled`; even then it needs your own started session, a plausible watch time, an unexpired session, caps and
cooldown, is labelled `client_attested` in the ledger/admin, and the admin overview shows a warning. Recommended: keep it off for launch (credits from Android only),
or keep earning caps small if you enable it. In test mode Ad Manager web needs `configuration.test_ad_unit_identifier` on the offer (paste a sample unit from Google's docs).

**Limit screen and credit-funded use.** When a metered allowance (today: domain lookups) is exhausted, the `403 limit_reached` error's `details` (and
`GET /credits/limit-screen/`) contain: per-window `used` / `limit` / `remaining` / exact `resets_at` (UTC), `blocking` windows, the latest reset, `credits`
(balance, cost per use, `can_cover`, reason), `rewarded_ad` (eligible offers), `upgrade` (only when pricing is on) and `wait`. Credits are **never spent silently**:
the client resends the request with `"use_credits": true` (domain analyze also accepts `"platform"`). Only features priced in credits can be funded, never ones
switched off for the plan; a lookup that then fails refunds the credits (once).

**Ledger rules.** Entries are append-only (`REWARDED_AD_EARNED`, `PROMOTIONAL_CREDIT`, `ADMIN_GRANT`, `USAGE_REFUND` positive; `FEATURE_USAGE`, `CREDIT_EXPIRY`,
`ADMIN_REVERSAL` negative; sign enforced by a database constraint). Spending is a conditional atomic update, so it cannot overdraw or double-spend; keys make every
movement idempotent; the soonest-expiring credits are spent first and expired credits are never spendable (balance reads and spends expire them on demand).
`wallet == sum(ledger) == sum(unspent lots)` is checked in the admin overview. Jobs — schedule hourly: `python manage.py process_credits`.
Demo data: `python manage.py seed_example_rewards` (a DISABLED example offer and a sample credit price). Retention (`purge_old_data`): callback records 30 days,
unrewarded sessions 90 days; rewarded sessions and the ledger are kept. Admin roles: `credits.manage_credits` (adjustments, earning suspension),
`credits.view_credit_reports` (overview, read-only records); offers and switches need `advertising.manage_ads`.

**Live setup you still need:** AdMob app + a rewarded ad unit with *server-side verification enabled* and the callback URL
`https://<your-api>/api/v1/advertising/reward-callbacks/admob/` (AdMob has a test tool for it); put the real unit on the offer, enable the `admob` provider,
switch `rewarded_ads_test_mode` off. The callback URL must be reachable by Google (HTTPS). Android SSV also needs UMP consent in the app before requests.

## Documentation (Milestone 9)
| Document | For |
|---|---|
| `docs/DEPLOYMENT.md` | step-by-step production deployment (Supabase, Redis, object storage, API, scheduler), updating and rollback |
| `docs/OPERATIONS.md` | scheduled jobs, monitoring, backups and restore drills, secret rotation, incident playbooks |
| `docs/SANDBOX_TESTING.md` | what must be tested live (domains, Web Risk, Paystack, AdMob, email, devices) and what "pass" means |
| `docs/ACCEPTANCE.md` | the PRD's 23 scenarios mapped to tests, with honest status (21 backend-verified, 1 partial, 1 unproven) |
| `docs/PRIVACY_AND_DATA.md` | data inventory and retention for the privacy policy and Play Data safety form (not legal advice) |
| `docs/USER_GUIDE.md` | end-user guide |
| `docs/MVP_SCOPE.md` | what is outside the MVP and what remains |
| `docs/DEMO_AND_SUBMISSION.md` | what can be demonstrated today, and the submission checklist |
| `docs/TESTING.md` | how to run the tests (SQLite and PostgreSQL), static checks, mutation checking |
| `docs/SEO_AND_ANALYTICS.md` + `docs/seo/` | getting found on Google: rendering decision, pages and keywords, Search Console, analytics/consent, starter files (robots, sitemap, head template, consent snippet, ads.txt) |
Scripts: `scripts/seo_check.py <site url>` (audits the public WEBSITE), `scripts/smoke_test.py <url>` (post-deploy checks), `scripts/backup_db.sh`, `scripts/restore_drill.sh`, `scripts/enable_rls.sql`; `deploy/scheduler.sh`; `docker-compose.prod.yml`; `ci/github-actions-backend.yml`.

## Account data rights and exports
| Method | Path | Notes |
|---|---|---|
| GET / POST / DELETE | /api/v1/auth/me/deletion-request/ | status, request, cancel. Erasure after a grace period (`account.deletion_grace_days`, default 14) by `process_account_deletions` (daily) |
| POST | /api/v1/auth/me/export/ | `{"password"}` -> the user's own data as a JSON download; 5/day; audited |
| GET | /api/v1/domains/assessments/{id}/export/?type=csv\|pdf | signed-in, needs the `domain.reports.export` entitlement (enforced on the backend); CSV cells are protected against spreadsheet formula injection |
Erasure anonymises the account (a tombstone keeps payment/audit records without personal data), deletes the person's QR codes, files and records, never cuts short a paid period, and never erases staff or organisation owners with members automatically.

## Settings modules
`config.settings.local` (dev), `.test` (pytest, forced by pytest.ini), `.production`
(HTTPS, HSTS, secure cookies; refuses to start with the default secret key).

## Deliberately not built yet
Session/device management, email change, QR codes, scanner, domain intelligence,
Celery/Redis, Google Play Billing / Stripe, domain-report export. See SECURITY.md known gaps.

## What is next: the web and Android apps, live testing, and the remaining backend gaps (see docs/MVP_SCOPE.md)
