# Operations runbook

## Scheduled jobs (run exactly one scheduler: `deploy/scheduler.sh`)
| Job | Cadence | What it does | If it stops |
|---|---|---|---|
| `process_subscriptions` | hourly | ends trials and grace periods, expires subscriptions, sends notices | paid/trial access never ends on time |
| `recheck_destinations --limit 200` | hourly | re-assesses live QR destinations; applies the malicious-destination policy | a destination that turns malicious later is not caught |
| `process_credits` | hourly | expires due credits, closes abandoned ad sessions | little: spending and balance reads also expire credits on demand |
| `purge_old_data` | daily | enforces retention (see `PRIVACY_AND_DATA.md`) | data is kept longer than the privacy policy says |
| `send_expiry_reminders --days 3` | daily | QR expiry reminders | owners are not warned |
| `process_account_deletions` | daily | erases accounts whose deletion grace period (default 14 days) has passed; honours a paid period still running; reports accounts it cannot erase (staff, organisation owners with members) | deletion requests are never carried out: a legal exposure |
Every job is idempotent: running one twice is safe. A failing job is logged as `JOB FAILED: ...` and does not stop the others.

## What to watch
Alert on these (logs are JSON with a `request_id`; Sentry holds exceptions):
- **Health:** `GET /api/v1/health/` not `{"status":"ok","database":"ok"}` for 2+ minutes.
- **5xx rate** above ~1% of requests, or any burst of Sentry errors after a deploy.
- **Scheduler silent:** no `process_subscriptions` line in the last 2 hours.
- **Reward callbacks:** a spike in `invalid_signature` (probing) or any `key_unavailable` (Google's key server unreachable from your network). Review in the admin: Credits > Reward callback events.
- **Credit consistency:** the admin overview `GET /api/v1/admin/credits/overview/` must report `reconciliation.consistent: true`. If not, stop issuing credits and investigate before anything else.
- **Webhooks:** payment webhook events stuck in a non-processed state (Billing > Payment webhook events).
- **Threat provider:** repeated provider errors in assessments mean results degrade to "needs further verification". They never become "no known threat".
To trace one user report: ask for the `X-Request-ID` response header, then search the logs for it.

## Backups (the part people skip)
- Schedule `scripts/backup_db.sh` daily (cron on a small VM/job runner with `pg_dump` >= your server version): `DATABASE_URL=... BACKUP_DIR=... KEEP_DAYS=14`.
  **Copy dumps off the provider** (a different account/bucket, encrypted). Dumps contain personal data and payment references.
- **Restore drill at least monthly:** `SCRATCH_DATABASE_URL=<throwaway db> sh scripts/restore_drill.sh <dump>`. It checks the checksum, restores, prints row counts and that the credit ledger total equals the wallet total.
  A backup you have never restored is not a backup. (The scripts were exercised against a real PostgreSQL 16 for this milestone, not against Supabase.)
- Restoring production: stop the API and scheduler, restore into a **new** database, point `DATABASE_URL` at it, run `python manage.py migrate`, re-run `scripts/enable_rls.sql`, start services, run the smoke test.
- Accepting data loss: anything after the last backup (new users, scans, payments). Payments can be re-verified by reference with the provider; see the incident below.

## Secrets and rotation
| Secret | Rotate when | Effect |
|---|---|---|
| `DJANGO_SECRET_KEY` | suspected leak | all sessions and signed tokens (JWT, password-reset, verification links) become invalid; users sign in again |
| Paystack/Flutterwave keys | leak, staff change | update env, redeploy; webhook signatures are checked with the new key |
| `THREAT_INTEL_API_KEY`, `AI_API_KEY` | leak | update env; calls fail honestly until then (reports say assessment unavailable) |
| S3 keys | leak | rotate in the provider, update env, redeploy |
| `DATABASE_URL` password | leak, staff change | rotate in Supabase, update env, redeploy |
Never put a secret in the repository, the admin, or a client app. Ad unit ids are public by design; provider secrets are not.

## Incident playbooks
**A QR code or domain is reported malicious.** Admin > Abuse reports: review. User reports never mark a domain malicious on their own. Pause or disable the QR (staff-disable cannot be undone by the owner).
Add a local blocklist entry if confirmed. Recheck with `manage.py recheck_destinations`.
**A payment succeeded at the provider but the user has no access.** Find the transaction (Billing > Payment transactions). Access is granted only after the provider confirms exact amount and currency; check the webhook
events for errors. Re-run verification for that reference; if still failing, grant a temporary entitlement with a required note (audited) while you investigate.
**Reward abuse suspected.** Admin overview > `unusual_reward_patterns`. Suspend earning for the wallet (Credits > Wallets > `earning_suspended`), review sessions and callbacks, reverse credits with `POST /api/v1/admin/credits/adjust/` (kind `reversal`, reason required).
Tighten `maximum_claims_per_*`, cooldown and the `credits.earn.*_limit` entitlements. If web rewards are enabled and being farmed, turn off `rewarded_web_client_attested_enabled`.
**Threat provider or RDAP outage.** Nothing to do: assessments report the missing checks. Tell users only if it lasts hours; never present degraded results as clean.
**Credits do not reconcile.** Stop issuing (switch `rewarded_ads_enabled` off). Compare the ledger with wallets: `reconcile()` in `apps/credits/service.py`. The ledger is authoritative. Restore from backup if corruption is proven.
**Leaked secret.** Rotate it (table above), redeploy, review audit logs and Sentry for misuse, and notify affected users if personal data may have been exposed (this may be a legal duty in your region).
**Bad deploy.** Redeploy the previous image; see "Updating and rolling back" in `DEPLOYMENT.md`.

## User data requests
- **Export:** users download their own data themselves (`POST /api/v1/auth/me/export/`, password required, 5 per day, audited). For a request that arrives by email, ask them to use the app, or run the same export from the Django shell: `from apps.accounts.export import export_user_data`.
- **Deletion:** users request it in the app (`POST /api/v1/auth/me/deletion-request/`), can cancel during the grace period (`DELETE`), and `process_account_deletions` erases the account afterwards: personal data is deleted and the account row becomes an anonymous tombstone (payment records and audit entries are kept without personal details).
  Read the job's output each day: it lists **deferred** accounts and why (staff accounts, organisation owners with other members: resolve manually; a running paid period: erased automatically when it ends).
- Deletion is **irreversible** and removes the user's QR codes: printed dynamic codes stop working. Backups taken before the erasure still contain the data until they expire, which your privacy policy should state (see `PRIVACY_AND_DATA.md`).
- Staff accounts are never erased automatically (so administration cannot be locked out): demote first, then request deletion.