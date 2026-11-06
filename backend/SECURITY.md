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

## Known gaps (tracked for later milestones)
- Login throttling is per-IP; add per-account lockout/backoff
- Throttle counters need Redis (not per-process memory) when running multiple workers
- No device/session management yet
- Destination safety (reputation, lookalike detection) arrives in Milestone 4; Milestone 2 only validates syntax
- SSRF protections arrive with the domain-intelligence milestone
- Structured error monitoring (e.g. Sentry) not configured

## Reporting
Email the project owner with details. Do not open public issues for vulnerabilities.
