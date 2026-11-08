# ScanSentry — Backend (Milestones 1–4A: Foundation + QR engine + Scanner + Domain intelligence)

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
- 358 automated tests (generated codes are decoded back; the SSRF guard is tested against a fake internet
  with real TLS handshakes, and mutation-checked)

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

## Settings modules
`config.settings.local` (dev), `.test` (pytest, forced by pytest.ini), `.production`
(HTTPS, HSTS, secure cookies; refuses to start with the default secret key).

## Deliberately not built yet
Session/device management, email change, QR codes, scanner, domain intelligence,
security engine, billing, ads, credits, Celery/Redis. See the milestone plan.

## Next: Milestone 4B — rule engine, threat-intelligence adapter, security risk score, AI explanations
