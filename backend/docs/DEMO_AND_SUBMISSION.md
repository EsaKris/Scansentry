# Demonstration and submission

## The honest state
The backend is complete through Milestone 9 **as software**: 1,100+ automated tests pass on SQLite and PostgreSQL, security tooling is clean, backups and the production configuration were exercised.
The **web and Android apps are not built**, nothing is deployed, and no live provider (RDAP from the real host, Web Risk, Paystack, AdMob) has been exercised. A video of "the product" therefore cannot be recorded yet:
what can be shown today is the **API**, which is a legitimate technical demo but not a user-facing one. Do not present simulated results as live ones.

## Demo that works today (backend only, ~10 minutes)
Use Swagger UI at `/api/v1/docs/` or the Postman collection imported from `openapi.yaml`. Everything below is covered by automated tests (see `ACCEPTANCE.md`).
1. **Public scan, no account.** `POST /scanner/analyze/` with a normal link: read the result, the explicit-confirmation flag, and that no "safe" label appears. Then `javascript:alert(1)`: blocked.
2. **Create and manage a dynamic QR.** Register, log in, `POST /qr/` (dynamic website), download the PNG; decode it: it contains a ScanSentry link, **not** the destination.
3. **Change the destination.** `PATCH /qr/{id}/`; the image is unchanged, `GET /scanner/verify/{token}/` now shows the new destination; `GET /qr/{id}/history/` shows the change. Pause it: it no longer redirects.
4. **Domain intelligence.** `POST /domains/analyze/` (simulated RDAP unless run on a real network): registration date, age, registrar, raw statuses, hold vs transfer lock, DNS/TLS/website, health and risk scores kept separate, missing checks listed.
5. **Honest failure.** Show a report with a provider unavailable: "needs further verification", never "no known threat".
6. **Pricing without a deployment.** In the admin: enable `pricing_enabled`, create a plan with an NGN price and entitlements; `GET /plans/` reflects it; switch off and the purchase controls disappear while history remains.
7. **Ads and limits.** `GET /advertising/eligible-placements/` for a free vs an ad-free user; for scanner/verification surfaces the answer is "never". Hit a usage limit: the `limit_reached` error shows reset time, credit balance and options.
8. **Rewarded credits.** Create a session; show that `started`/`closed` events grant nothing; replay a signed callback (use the test simulator) and show exactly one ledger entry, then a forged one refused.
9. **Admin controls.** Audit log, credit overview with reconciliation, staff permissions.
10. **Operations.** `python scripts/smoke_test.py <url>` against a running instance; show `X-Request-ID`; show the restore drill output.

## Submission checklist
- [ ] Web app and Android app built and pointed at the same deployed API (scenario 14)
- [ ] Deployed backend passes `scripts/smoke_test.py` over HTTPS
- [ ] Every scenario in `ACCEPTANCE.md` re-checked end to end on a device (not just the API)
- [ ] `SANDBOX_TESTING.md` completed, or each skipped item listed as a known limitation
- [ ] Privacy policy, terms of service, Play Data safety form, ad-consent flow
- [ ] Android release build; Google Play developer account
- [ ] Demonstration video (real clients), README with setup, `SECURITY.md`, `MVP_SCOPE.md` (what is intentionally out)
- [ ] No real secrets in the repository; `.env.example` complete; demo accounts use throwaway data
- [ ] Pricing/ads/rewards switches set deliberately for the demo (all default to OFF)
