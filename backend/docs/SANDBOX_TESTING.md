# Live and sandbox testing checklist

Everything below could **not** be tested in the build environment (no real accounts, devices or deployed host). Each item says what to do and what "pass" means.
Do them in this order. Use test/sandbox modes only; never real money and never a real malicious site.

## 1. Network and domain checks (from the real server)
`python manage.py assess_domain example.com` run on the deployed server.
Pass: the report shows RDAP registration data, DNS records, TLS and website results. Any `MISSING CHECK` means a blocked outbound port (80/443), DNS, or an egress rule: fix the network, not the code.
Also try a domain with a ccTLD you care about (e.g. a `.ng` name): registration data is not identical everywhere, and "not disclosed" is a correct answer.

## 2. Threat intelligence (Google Web Risk)
Create a Google Cloud project with billing, enable the Web Risk API, create an API key restricted to that API. Set `THREAT_INTEL_API_KEY`, enable the provider in the admin.
Pass: assessing a normal site shows "no known threat detected" with the provider named; with the key removed or invalid it shows "needs further verification" / provider error and **never** "no known threat".
Use only Google's published test URLs and confirm in the Web Risk documentation that they apply to that API. Assessment makes the server fetch the page (with the SSRF guard, no script execution): do not point it at real malware.
Check licensing terms for commercial use before launch.

## 3. Email
Configure SMTP. Register a user: the verification email arrives, the link works, password reset works, a QR expiry reminder and an owner security alert send.
Pass: links point at `FRONTEND_URL`; nothing sensitive is in the subject lines.

## 4. Payments (Paystack test mode)
Set test keys, create a plan with an NGN price, enable pricing, then: checkout -> pay with a Paystack test card -> return -> subscription active; confirm the webhook arrived (Billing > Webhook events) and was processed once;
replay the same webhook (must be ignored); try a tampered amount (must not credit); cancel (access continues to period end); renewal with a Paystack plan code.
Pass: every state matches `README.md` (billing section). The adapters were written from public docs and tested only against simulations. Repeat the key flow for Flutterwave if you enable it.
Google Play Billing and Stripe adapters do not exist yet; Play Billing is required to sell subscriptions inside the Android app.

## 5. Rewarded ads (AdMob server-side verification)
1. AdMob: create the app and a **rewarded** ad unit; in the unit's settings enable server-side verification and set the callback URL to `https://<api>/api/v1/advertising/reward-callbacks/admob/`. Use AdMob's SSV test tool to send a test callback.
   Pass: the response is **not** a `403 invalid_callback` or `503`. A test callback has no real session, so expect `200` with code `session_not_found`, or `400 malformed_callback` if the test tool omits `custom_data`/`user_id` (our parser requires them). What matters: a 403 means the signature check or key fetch is broken; the Admin > Reward callback events list shows the outcome. The real proof is step 3.
2. In the admin: enable the `admob` provider, create an Android offer (or `manage.py seed_example_rewards`), switch `rewarded_ads_enabled` and `rewarded_ads_android_enabled` on, keep `rewarded_ads_test_mode` on.
3. On a real Android development build (not Expo Go): create a session, set `userIdentifier = ssv.user_id` and `customData = ssv.custom_data` on the ad, watch a **test** ad.
   Pass: within seconds the session becomes `rewarded`, the balance rises by the offer's amount **once**, and closing the ad early gives nothing.
4. Production: put the real unit id on the offer, switch test mode off. Pass: a test ad no longer pays (`test_ad_in_production`).
5. Consent: implement Google's User Messaging Platform before requesting ads; confirm ads fall back to non-personalised where consent is refused.
Web rewarded ads cannot be verified server-side (Google: app-only). Decide deliberately whether to enable client-attested web rewards; see `SECURITY.md`.

## 6. Ads (standard)
AdSense/Ad Manager (web) and AdMob (Android) need account approval and site/app verification (days to weeks). With test ad units: an eligible free user sees a labelled ad on the dashboard; a paid user with `ads.remove` does not;
the scanner, results, verification, warning and QR creation screens never show one. The backend decision (`GET /api/v1/advertising/eligible-placements/`) is tested; the clients must obey it.

## 7. Redis and workers
With two or more API workers: send 12 wrong-password logins quickly from one client. Pass: the limit trips after the configured count, not after count x workers. Then `docker kill` Redis: the API must keep serving (rate limits degrade; check the logs).

## 8. Storage
Upload a QR logo and an abuse-report evidence image. Pass: both land in the private bucket and the bucket's objects are not reachable without a signed URL.

## 9. Security checks on the live host
`python scripts/smoke_test.py https://<api>`. Then: an `https://` redirect from `http://`; HSTS header present; admin reachable only where you intend; try the SSRF checks (assess `http://169.254.169.254/`, `http://localhost`, `http://10.0.0.1`): all must be refused.
Run `nmap`/a scanner only against your own deployment. Commission a human security review before real money or real user data (this checklist is not a penetration test).

## 10. Cross-device scanning (clients)
Once the clients exist: scan the same printed QR (static and dynamic) on low-end and recent Android phones, in poor light, at an angle, from a screen, and by image upload; test the web scanner in Chrome, Safari and Firefox.
Pass: decoding succeeds and a link is never opened without explicit confirmation. Also print QRs with the generator's colours/logo and confirm real devices read them (contrast/quiet-zone checks are automated, real cameras are not).
