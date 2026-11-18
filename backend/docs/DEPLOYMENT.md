# Deployment guide

Target: the API on a container host (Railway, Render, Fly.io or similar), the database on Supabase (or any PostgreSQL 14+), Redis for rate limits,
private object storage for uploaded files. Supabase does **not** host Django. The web and Android clients are deployed separately and talk to this API.

**What has and has not been verified.** The production settings, image build steps (static files, gunicorn), Redis sharing, the smoke test, backups and the RLS script were
run for real in a Linux sandbox. The Docker image itself was **not built** (no Docker available) and nothing was deployed to a real host: expect to adjust host-specific details.

## 0. Before you start
Accounts to create early (approvals take days): Supabase, a container host, Redis (host add-on or Upstash), an SMTP provider, a domain name. Optional/later: Google Web Risk,
AdMob, Ad Manager/AdSense, Paystack, Sentry. See `SANDBOX_TESTING.md` for what each needs.

## 1. Database (Supabase)
1. Create a project. Copy the connection string. Prefer the **session pooler** string if your host has no IPv6 (Supabase's direct host may be IPv6-only; check their current docs).
   If you use the *transaction* pooler also set `DB_DISABLE_SERVER_SIDE_CURSORS=true`.
2. `DATABASE_URL=postgresql://postgres.<ref>:<password>@<host>:5432/postgres` and `DB_SSL_REQUIRE=true`.
3. After the first migration, run `scripts/enable_rls.sql` (SQL editor). **Re-run it after any deploy that adds tables.**
4. Backups: check what your Supabase plan includes (daily backups and point-in-time recovery are plan-dependent). Independently run `scripts/backup_db.sh` on a schedule (see `OPERATIONS.md`).

## 2. Redis
Provision any Redis 6+ and set `REDIS_URL` (`rediss://` for TLS). Production **refuses to start without it**: rate limits (login, scanning, callbacks, admin sign-in) must be shared by every worker.
Without Redis each worker counts separately, so every limit is multiplied by the worker count (measured: three processes counted 1,1,1 instead of 1,2,3).
Redis holds only cache/counters: it needs no persistence, and losing it only resets rate-limit windows.

## 3. File storage (QR logos, abuse evidence: private)
A container disk is wiped on every deploy, so use object storage:
- Create a **private** bucket. For Supabase Storage use its S3 endpoint `https://<project>.supabase.co/storage/v1/s3` and S3 access keys from the dashboard.
- `FILE_STORAGE_PROVIDER=s3`, `S3_BUCKET_NAME`, `S3_ENDPOINT_URL`, `S3_REGION`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`.
- Files are never served publicly; the app stores them with a private ACL and any URL it generates is signed and expires in 5 minutes. Never make the bucket public.
- Not tested against a real bucket: upload a QR logo and an abuse-report evidence image after deploy and confirm both are stored and not publicly reachable.

## 4. The API service
Build from `backend/Dockerfile` (non-root user, static files collected with production settings, gunicorn). Settings to provide (see `.env.example`):

| Variable | Notes |
|---|---|
| `DJANGO_SETTINGS_MODULE` | `config.settings.production` (the image sets it) |
| `DJANGO_SECRET_KEY` | 32+ random characters; the app refuses weak/default values |
| `DJANGO_ALLOWED_HOSTS` | your API host(s); the app refuses the defaults |
| `CORS_ALLOWED_ORIGINS` | your web app origin(s), `https://` only |
| `DATABASE_URL`, `DB_SSL_REQUIRE` | step 1 |
| `REDIS_URL` | step 2 |
| `FRONTEND_URL`, `REDIRECT_BASE_URL` | the web app, and the public domain serving `/r/<token>` |
| `NUM_PROXIES` | how many trusted proxies sit in front (1 on most hosts). Wrong values let clients spoof their IP or collapse everyone into one rate-limit bucket |
| `EMAIL_BACKEND` + SMTP settings, `DEFAULT_FROM_EMAIL` | verification, reset and alert emails |
| `DJANGO_ADMIN_URL` | move the admin away from `/admin/`; also restrict it by IP/VPN if you can |
| `SENTRY_DSN` | optional |
| Provider keys | `THREAT_INTEL_API_KEY`, `PAYSTACK_SECRET_KEY`, `FLUTTERWAVE_*`, `AI_*`: only for what you enable |

Host settings: start command = image default (`gunicorn config.wsgi:application -c gunicorn.conf.py`); **release/pre-deploy command** = `python manage.py migrate --noinput`;
health check path = `/api/v1/health/` (plain HTTP is exempt from the HTTPS redirect for probes); `WEB_CONCURRENCY` = 2-4 depending on memory (a domain assessment can take ~20 s, so keep `GUNICORN_TIMEOUT` at 60).
Behind a TLS-terminating proxy, the proxy must send `X-Forwarded-Proto`. If it cannot, set `SECURE_SSL_REDIRECT=false` (and accept that Django cannot force HTTPS).

## 5. The scheduler (one instance only)
Run `sh deploy/scheduler.sh` as a **separate always-on service** from the same image, or recreate its schedule with your host's cron:
hourly `process_subscriptions`, `recheck_destinations --limit 200`, `process_credits`; daily `purge_old_data`, `send_expiry_reminders --days 3`.
Never run two schedulers. Without it: trials and grace periods do not end, expired credits are only removed when touched, retention is not enforced and malicious-destination re-checks stop.

## 6. First-time setup
```
python manage.py createsuperuser
python manage.py seed_example_plans        # optional demo plans; replace with real values in the admin
python manage.py assess_domain example.com # live smoke test of RDAP/DNS/TLS/website from THIS network
```
In the admin: leave `pricing_enabled` and the ad switches OFF until accounts are approved; set the brand list (`security.brand_domains`), `security.auto_disable_malicious`, and staff roles
(`manage_pricing`, `manage_subscriptions`, `grant_entitlements`, `view_payments`, `manage_ads`, `credits.manage_credits`, `credits.view_credit_reports`).

## 7. Verify the deployment
```
python scripts/smoke_test.py https://api.yourdomain.com --web-origin https://app.yourdomain.com
```
All checks must pass (it is read-only and safe on production). Then: sign in to the admin, create a user, create a QR, open `/r/<token>`, confirm an email arrives, check Sentry received a test event
(`python manage.py shell -c "import sentry_sdk; sentry_sdk.capture_message('ScanSentry test')"`).

## 8. Network and logging notes
- **Outbound filtering.** The app blocks private/internal addresses itself (SSRF guard), but also restrict egress at the platform level where you can (deny RFC1918, link-local and the cloud metadata address).
- **Proxy logs.** gunicorn logs paths only and the app logs paths only, but your host's router/CDN may log full URLs *including query strings* (which carry scanned content and tokens). Turn that off or shorten its retention.
- **Docs endpoints.** `/api/v1/docs/` and `/api/v1/schema/` are public. That is fine for an API consumed by apps; remove them if you prefer.

## 9. Updating and rolling back
1. Take a backup (`scripts/backup_db.sh`). 2. Deploy: the release command runs migrations. 3. Re-run `scripts/enable_rls.sql` if tables were added. 4. Run the smoke test.
**Rollback:** redeploy the previous image. Migrations only move forward: only run `migrate <app> <previous>` if you have read that migration and it is reversible; otherwise restore the backup.
Deploy additive migrations first and code second when a change is risky (e.g. new column, then code that uses it).
