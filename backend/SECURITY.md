# Security notes (backend)

## Implemented in Milestone 1
- Django password hashing; 10-character minimum + common/numeric/similarity validators
- Short-lived access tokens (15 min), rotating refresh tokens with blacklist
- Rate limiting on login, registration, verification and password reset
- No account enumeration on register or password reset
- Password-reset and email-verification tokens expire; reset tokens are single-use
- `PATCH /auth/me/` cannot change email, staff flags or verification state
- Audit log is created only server-side and is read-only in admin
- Production settings: HTTPS redirect, HSTS, secure cookies, nosniff, X-Frame-Options DENY
- Secrets only from environment variables; `.env` is git-ignored

## Added in Milestone 2
- Every QR queryset is scoped to the owner; other users' IDs return 404 on all endpoints
- Dynamic tokens: 144-bit `secrets` tokens, never database IDs; public resolver is rate-limited
  and rejects malformed tokens before touching the database
- Destination URLs: http/https only; `javascript:`, `data:`, `file:` and custom schemes rejected;
  embedded credentials rejected; hostnames converted to punycode
- vCard / Wi-Fi inputs reject control characters and are escaped (no field injection)
- Paused, disabled and expired codes never reveal their destination
- Logo uploads are validated by content, size/pixel-limited, and re-encoded (EXIF stripped); SVG uploads rejected
- Contrast and quiet-zone rules enforced; generated images are decoded back in tests
- Destination history is append-only; status/destination/logo changes are audited

## Added in Milestone 3
- Scanned content is treated as untrusted: analysed and neutralised (control characters stripped),
  never executed, never fetched. A test fails if analysis opens a socket
- `javascript:`, `data:`, `file:`, `vbscript:`, `intent:` and other dangerous schemes are always blocked;
  unknown custom schemes are unsupported; embedded-credential and percent-encoded-host links are blocked
- Every result requires explicit user confirmation before navigation; paused/disabled/expired
  ScanSentry codes never reveal a destination; unregistered look-alike ScanSentry links are blocked
- Image uploads: validated by content, size- and pixel-limited (decompression-bomb safe), decoded in memory only
- Abuse reports: rate-limited, deduplicated, reporter IP stored only as a keyed hash, evidence images
  re-encoded; reports never auto-block anything
- Rate limits trust `X-Forwarded-For` only when `NUM_PROXIES` is configured

## Added in Milestone 4A: outbound network safety (SSRF)
Every outbound request (website checks, TLS inspection, RDAP, the IANA bootstrap) goes through `NetGuard`:
- http/https only; ports 80/443 only; no credentials in URLs; IP literals validated directly
- the host is resolved by us and **every** address must be globally routable. Loopback, private, link-local
  (including 169.254.169.254 cloud metadata), CGNAT, ULA, multicast and reserved ranges are refused, and
  IPv4-in-IPv6 encodings (mapped, 6to4, Teredo, NAT64) are unwrapped before checking. One bad record blocks the host
- the connection is **pinned to the validated IP** (no second lookup), defeating DNS rebinding; Host/SNI use the original name
- redirects are followed manually (max 5), loops detected, and **every hop is re-validated**
- connect/total timeouts, response-size cap, no cookies, no body decoding, no script execution or rendering
- input is rejected before any lookup if it is an IP, a numeric host, a single label, or a non-public name
  (`localhost`, `.local`, `.internal`, `.test`, ...)
Tests run against a fake internet and assert not just the refusal but that **no connection was attempted**; the
guard's tests were mutation-checked (removing the address check, hop re-validation, pinning or the port rule each
makes tests fail).

**Deploy with network-level egress controls as well.** Application checks are the first line, not the only one:
run the API where outbound traffic to private ranges and cloud metadata endpoints is blocked by the platform, and
point `DNS_NAMESERVERS` at a trusted resolver.

## Added in Milestone 4B: security engine
- Classification honesty: no "safe" label anywhere; `known_malicious` only from a threat-intel match; a clean verdict
  needs an answering external source, a reached destination and no crashed rule; missing checks are listed, never assumed clean
- Weak indicators are capped below `high_risk`; scoring and rule configuration are versioned (ruleset hash stored per check)
- Threat providers: credentials only from environment variables, sent in headers (not URLs), never returned by any API or
  error message; commercial-licence notes shown to admins; failures reported, never converted to clean results
- Privacy: query strings/fragments stripped before storage, provider calls and AI calls; stored redirect traces redacted
- AI: whitelisted evidence only, strict output validation, cannot change a verdict or claim safety, falls back to rule-based text
- Redirect policy blocks confirmed-malicious destinations (optionally disables the code at staff level)
- Rule, provider and indicator changes made in the admin are audited
Mutation-checked guarantees (each breaks a test if removed): weak-indicator cap, clean verdict requires an answering
provider, provider failure is not an answer, redirect policy, AI cannot change the verdict, AI safety claims rejected,
query strings never stored or sent.

## Added in Milestone 5: analytics, notifications, usage
- Data minimisation: no IP address, user agent or URL in analytics; the visitor hash is keyed, daily-rotating and not reversible;
  country/region only from an operator-controlled header, validated (2 letters / control characters stripped)
- Strict isolation: every analytics, notification and activity query is scoped to the owner; other users' IDs return 404
- Bot/preview traffic excluded; scans de-duplicated; recording failures never affect scanning
- Notifications and alerts carry host names only; reporter identity never shared; staff identity never exposed in activity
- Email only to verified addresses and only per preference; usage limits enforced atomically on the backend
- CSV export neutralises formula injection; retention is enforced by a scheduled command
Mutation-checked: owner scoping, bot exclusion, hash keying and daily rotation, scan de-duplication, usage limits,
notification de-duplication, email-to-unverified, URL-in-notification and CSV injection.

## Added in Milestone 6: billing
- Prices are read from the database; the client cannot influence the amount charged
- Payments are credited only after provider API verification (exact amount + currency); a signed webhook alone is never trusted
- Idempotent crediting and webhook de-duplication; failed/refused payments are recorded outside the rolled-back transaction
- Webhook signatures verified in constant time; unconfigured providers refuse everything; payloads stored whitelisted
- Provider credentials only from the environment; provider calls go through the SSRF-guarded client
- Paid access is never cut short by cancelling, failed renewals or switching pricing off
- Role-based administration with specific permissions; every administrative change needs a note and is audited
Mutation-checked: client-controlled price, unsigned webhooks, crediting without provider verification, double credit,
amount/currency mismatch, cancel cutting access, checkout while pricing is off, expired overrides, missing admin note,
missing role check, duplicate webhooks, pricing-off revoking access, renewal amount/plan mismatches, email stored from webhooks.

## Added in Milestone 7: advertising
- One server-side eligibility decision; web and Android cannot disagree and clients cannot override it
- Security-critical screens are refused by the backend regardless of any setting; placements on them cannot be saved, and a forced row is still never served
- Ad-free plans are enforced on the server; trial and explicit-grant rules are tested
- Test ad units only in test mode; Google test ids can never be stored or served in production; stored production ids never leak in test mode
- No provider secret is stored; only whitelisted public identifiers are exposed; advertising settings need a dedicated permission and are audited
- Reporting figures are provider-reported or reported unavailable, never invented
Mutation-checked: forbidden-screen refusal (and its defence in depth), ad-free enforcement, trial rule, master/platform/category
switches, test-id handling in both modes, placement validation, public-config secret filtering, privacy-first personalisation default,
rewarded format exclusion, ad-admin role check, disabled-provider and anonymous-visitor handling.

## Added in Milestone 8: rewarded ads and credits
- Credits are granted in exactly one function (`settle`), reachable only from a signature-verified provider callback or the explicitly enabled web attestation.
  Requesting, loading, opening, clicking or closing an ad never reaches it; client progress events cannot grant
- AdMob SSV: ECDSA/SHA-256 over the raw query string, keys from Google's key server through the SSRF guard, cached ≤6 h with a bounded refresh; nothing may follow
  `signature` except `key_id`, repeated parameters are refused (parameter pollution), a down key server answers 503 and never "verified"
- Session, user, ad unit, reward timing, transaction id and replay are all checked; the reward amount is our snapshot, never the provider's number; sessions are single-use,
  short-lived and unguessable (256-bit); an invalid signature cannot alter any session; Google test ads cannot pay in production
- Caps, cooldown, switches and the earning entitlements are enforced when the session is created AND again when credits are granted
- The ledger is append-only with a database sign constraint; debits are conditional atomic updates (no overdraw / double spend even without row locks); every movement
  is idempotent; wallet, ledger and lots are reconciled; admin adjustments need a reason, a permission and are audited
- Credits are never spent without an explicit `use_credits` request, only on admin-priced, plan-enabled, metered features, and are refunded if the use fails
- Essential security access (decode, verify, warnings) has no credit or ad dependency, tested with a zero balance; security screens remain ad-free
- Callback records hold no IP address and no signature; sessions' tokens are hidden from the admin and from every read endpoint after creation
Mutation-checked: signature verification, overdraw guard, idempotency (both layers), duplicate/replayed callbacks, expired and early reward moments, client events granting,
unsigned appended parameters, silent spending, spending expired credits, web attestation switch and post-expiry completion, test ads in production, user mismatch,
grant-time cap, transaction-id replay, repeatable refunds, rewarded-provider capability, ledger edits, admin permission, key-server outage handling.

## Milestone 9: security review
Scope: this was a review by the engineer who built the system plus tooling. It is **not** an independent penetration test: commission one before real money or real users.
**Tooling:** `bandit -ll` reports no medium/high findings (the 9 low findings are false positives on strings such as rate names); `pip-audit` reports no known vulnerable dependencies;
`manage.py check --deploy` is clean with the production settings.
**Defects found and fixed during the review** (each now has a regression test):
1. *Per-process rate limits.* With no shared cache, every limit (login, scanning, callbacks) was multiplied by the worker count. Production now refuses to start without `REDIS_URL` (explicit single-worker opt-out available); verified with real Redis across separate processes.
2. *Container would have broken the admin.* Static files were collected with the local settings while production uses a manifest storage: `/admin/` raised a 500. The image now collects with production settings (verified).
3. *Admin sign-in had no brute-force protection.* Added a per-client throttle (client address taken from `NUM_PROXIES`, a forged `X-Forwarded-For` is ignored) and a configurable admin path.
4. *Payment-verification lock error on PostgreSQL.* `select_for_update` across a nullable join is rejected by PostgreSQL, which would have made payment verification fail with a 500 in production (SQLite hid it). Fixed in three places.
5. *Over-long column in the reward code* (outcome text longer than its column on PostgreSQL). Widened by a migration; every outcome code is now tested against the column limits; over-long provider transaction ids are refused.
6. *Reward-cap race.* A cap check was protected only by an accident of unrelated row locking. Settlement now locks the session and then the user's wallet row before any cap, cooldown or earning-limit check; a parallel test (12 simultaneous callbacks, cap 2) fails without it and passes with it.
7. *Local file storage on ephemeral disks.* Uploaded logos/evidence would vanish on redeploy. Added private, signed-URL-only S3-compatible storage; filesystem remains available for persistent volumes.
8. *Logs and error reports could contain secrets.* gunicorn access logs are off by default and, when on, record paths only; application logs strip query strings and bearer tokens; Sentry (optional) is scrubbed of query strings, bodies, cookies, sensitive headers and user identity.
**Verified live in the sandbox:** production gunicorn (2 workers) + Redis + migrated PostgreSQL pass the 18-check smoke test; the access log contained no query string; a backup restored into a scratch database with its data and credit-ledger total intact; the RLS script locked all 50 tables, Django (owner role) kept working and a non-owner role with a `SELECT` grant read 0 rows.
**Not verified:** the Docker image build, any real host, Supabase specifics (pooler/IPv6, Storage S3 endpoint, backup plans), real object storage, Google/Paystack/AdMob behaviour, real devices, load/performance, and the CI workflow.

## Added after Milestone 9: data rights, exports, search-engine exposure
- Account erasure anonymises (payments are `PROTECT`ed and audit entries point at their actor, so the row stays as a tombstone); a policy table decides every relation to a user and a test fails if a new model is not decided; another test scans every column of every table for the erased person's email and name
- Erasure is delayed by a grace period, cancellable, never cuts a paid period short, and never runs automatically on staff accounts or organisation owners with members
- Data export needs the password again (a stolen session is not enough), is rate-limited and audited, and excludes secrets by name AND by pattern, other people's data and staff-internal notes
- Domain-report CSV neutralises formula-injection cells (a hostile site controls registrar/DNS text); PDF text is escaped; download filenames cannot inject headers; the export is gated by the entitlement on the backend
- The API host sends `X-Robots-Tag: noindex` and `Disallow: /`; the website must do the same for scan results and `/r/` pages (`docs/SEO_AND_ANALYTICS.md`)

## Known gaps (tracked for later milestones)
- **Web rewarded ads cannot be server-verified** (Google: Ad Manager SSV is app-only). They are off by default; if enabled they are client-attested and farmable by a determined user
- The SSV adapter was written from Google's public documentation and tested against a simulated signer: verify it with AdMob's SSV test tool and a real device before enabling rewards
- Only `domain.lookups` is credit-funded so far; other metered features (AI explanations, report export, `qr.scans.monthly_limit`) still need counters before they can be priced in credits
- Reward-abuse detection is a threshold flag plus `earning_suspended`; there is no automatic suspension. No device attestation (Play Integrity) is used
- Callback records are not rate-limited per source beyond the global throttle (Google's IPs are shared); the throttle counters need Redis with several workers
- `select_for_update` is a no-op on SQLite; on PostgreSQL it serialises per-user credit changes. Concurrency safety does not rely on it (conditional updates, unique keys) but was
  not stress-tested under real parallel load
- Image decoding uses OpenCV, which misses a few percent of hard photos; the client camera decoder is the primary path
- The built-in brand list and abuse-heavy-TLD list are starter data; tune them for your market. Look-alike detection will have false negatives and some false positives
- Redirect-policy blocks rely on a cached finding per destination URL; run `recheck_destinations` on a schedule
- The risk score is a transparent weighted sum, not a validated model
- Analytics aggregates run live over the events table; add pre-aggregated rollups if volumes become large
- 'Unique' scan figures are daily estimates summed across days, not distinct people
- Notifications and email are sent synchronously; move to a queue (Celery) at scale
- Payment adapters are tested against simulated providers only; verify in each provider's sandbox before launch
- No proration; organisation-level billing is modelled but not enforced
- Consent collection (Google UMP / web CMP) and ad rendering are client-side; verify them in the apps. Provider reporting APIs are not integrated
- Login throttling is per-IP; add per-account lockout/backoff
- Throttle counters need Redis (not per-process memory) when running multiple workers
- No device/session management yet
- Destination safety (reputation, lookalike detection) arrives in Milestone 4; Milestone 2 only validates syntax
- Network checks have been tested against a simulated internet, not live RDAP/DNS/TLS (the build sandbox has no general internet access): run the live smoke test in the README before launch
- Domain checks run synchronously in the request (parallel, 20 s cap). Move to Celery if latency becomes a problem
- Structured error monitoring (e.g. Sentry) not configured

## Reporting
Email the project owner with details. Do not open public issues for vulnerabilities.
