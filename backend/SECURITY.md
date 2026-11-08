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

## Known gaps (tracked for later milestones)
- Image decoding uses OpenCV, which misses a few percent of hard photos; the client camera decoder is the primary path
- Login throttling is per-IP; add per-account lockout/backoff
- Throttle counters need Redis (not per-process memory) when running multiple workers
- No device/session management yet
- Destination safety (reputation, lookalike detection) arrives in Milestone 4; Milestone 2 only validates syntax
- Network checks have been tested against a simulated internet, not live RDAP/DNS/TLS (the build sandbox has no general internet access): run the live smoke test in the README before launch
- Domain checks run synchronously in the request (parallel, 20 s cap). Move to Celery if latency becomes a problem
- Structured error monitoring (e.g. Sentry) not configured

## Reporting
Email the project owner with details. Do not open public issues for vulnerabilities.
