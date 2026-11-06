# ScanSentry — Backend (Milestones 1–2: Foundation + QR engine)

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
- 81 automated tests (generated codes are decoded back in tests to prove they scan)

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
| GET | /api/v1/scanner/verify/{token}/ | **Public.** Resolves a dynamic token; never redirects |

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

## Settings modules
`config.settings.local` (dev), `.test` (pytest, forced by pytest.ini), `.production`
(HTTPS, HSTS, secure cookies; refuses to start with the default secret key).

## Deliberately not built yet
Session/device management, email change, QR codes, scanner, domain intelligence,
security engine, billing, ads, credits, Celery/Redis. See the milestone plan.

## Next: Milestone 3 — public scanner & verification (decode, explicit navigation consent, abuse reports)
