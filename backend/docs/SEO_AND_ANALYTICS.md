# SEO, Google Search Console and analytics

**Read this first.** Search engines rank your *public website*, not this API. The backend's part is small (it already tells search engines to ignore the API host, and it keeps the product honest and fast).
The work that decides whether people find ScanSentry when they search for a QR scanner is done in the **web app and its content**: this guide and the files in `docs/seo/` are for whoever builds it.
Nobody can honestly promise a ranking. A new domain usually takes weeks to be indexed and **months** to earn traffic; "QR code scanner" is one of the most competitive searches there is.
What you *can* do is remove every technical obstacle, publish genuinely useful pages, and target searches you can win. `scripts/seo_check.py` verifies the technical part automatically.

## 1. The biggest decision: how the public pages are rendered
A plain React + Vite app is a *client-rendered SPA*: the server sends an almost empty page and JavaScript builds it. Google can render JavaScript, but later and less reliably, and many other crawlers and every social/messaging preview cannot.
For pages that must rank, the finished HTML must already contain the title, headings and text.

| Option | Effort | SEO | Verdict |
|---|---|---|---|
| A. One Vite SPA for everything | none | weak for marketing pages | not recommended |
| **B. Same Vite app, but **prerender the public routes at build time** (static HTML per page; the app takes over in the browser)** | low-medium | good | **minimum acceptable** |
| **C. A separate static marketing site (Astro/Next/similar) on the main domain; the React app on `app.` or a path** | medium | best (fastest, cleanest) | **recommended if the web developer is comfortable with it** |

The PRD says "React + Vite" for the web app; B keeps that. This is the web developer's call, but **decide before building pages**: retrofitting it later is painful. Verify with `scripts/seo_check.py`: it warns when a page has almost no text in the raw HTML.

## 2. Pages worth building (and the searches they target)
Aim at searches you can realistically win, not just the head term.
| Page (indexable) | Targets | Notes |
|---|---|---|
| `/qr-code-scanner` | "online QR code scanner", "scan QR code from image" | A real, working tool *plus* 400+ words of explanation and an FAQ below it. Tool pages rank when they are fast and useful |
| `/domain-checker` | "domain age checker", "who owns this domain / RDAP lookup", "website registration date" | The domain intelligence engine is a genuine differentiator |
| `/qr-code-generator` | "dynamic QR code generator", "QR code with analytics", "editable QR code" | Very competitive; lead with what is different (destination verification, security) |
| `/learn/what-is-quishing` and similar guides | "QR code phishing", "quishing", "fake QR code stickers", "how to check a QR code before scanning" | Informational pages earn links and trust; the best long-term traffic source for a security brand |
| `/security-methodology`, `/how-it-works`, `/about`, `/contact`, `/privacy`, `/terms` | trust ("E-E-A-T") | Security products are judged on trust. Name real people, a contact, how scores work and their limits |
| `/pricing`, `/features` | brand and comparison searches | |
**Local angle.** If Nigeria/Africa is your first market, say so in the copy ("QR code scanner for Nigeria", local payment methods, NGN prices): that is far easier to win than the global head term.

### The honesty tension
People search "is this QR code safe?" ScanSentry never labels anything "safe" (a core product rule). Do not break that to chase keywords. Write pages that answer the *question* honestly:
"How to check where a QR code leads *before* you open it, and what a clean result does and does not mean." That is truthful, differs from competitors, and matches the intent.

### Do NOT index per-domain report pages at launch
A page for every domain ("Is example.com safe? ScanSentry report") looks like free SEO but: it is thin, duplicate-looking content at scale (a spam signal), it can wrongly accuse real businesses (legal/reputation risk), and it
publishes assessments that the product treats as time-sensitive. Keep result pages `noindex`. Revisit only with strong editorial controls and legal advice.

## 3. Never index these (scan results, QR links, signed-in pages)
`/r/<token>` verification pages, scan results, domain reports, dashboard, account, billing: **`noindex, nofollow` in the HTML head AND an `X-Robots-Tag` header**, plus `Disallow` in robots.txt (`docs/seo/robots.txt`).
Reason: tokens and scanned content are private, and an indexed verification page would make a legitimate QR code look public. Note robots.txt alone does not remove a URL that other sites link to; the noindex header does.
The API host (`api.` or wherever Django runs) already sends `X-Robots-Tag: noindex` and a `Disallow: /` robots.txt, so it will never appear in results.

## 4. Technical checklist (all verified by `scripts/seo_check.py` unless marked manual)
- One unique **title** (30-60 characters) and **meta description** (70-160) per page; one **h1**; real heading hierarchy; descriptive alt text. Template: `docs/seo/head-template.html`.
- **Canonical** URL on every page (absolute, https, no tracking parameters). Redirect `http` -> `https` and `www` <-> apex (pick one) with a 301. (manual)
- **robots.txt** and **sitemap.xml** (`docs/seo/`): only indexable pages in the sitemap, with honest `lastmod`. Reference the sitemap in robots.txt.
- Real **404** for unknown URLs (not a 200 "not found" page: that creates "soft 404" duplicates).
- **Mobile-first**: viewport meta, responsive layout, tap targets. Most scans and searches are on phones.
- **Core Web Vitals** (measure with PageSpeed Insights / Search Console, manual): LCP <= 2.5 s, INP <= 200 ms (INP replaced FID in 2024), CLS <= 0.1. Keep third-party scripts and ads off the critical path, size images, use modern formats, set explicit image dimensions.
- **Structured data** (JSON-LD): Organization + WebSite on the home page, WebApplication on the scanner/generator pages. Validate with Google's Rich Results Test. It helps understanding; it does not guarantee rich results.
  (FAQ rich results are now limited to a small set of authoritative sites, so do not add FAQ markup *expecting* a rich result. Visible FAQs are still good content.)
- **Social previews**: Open Graph / Twitter tags with a 1200x630 image.
- **Internal links**: every page reachable in 2-3 clicks from the home page with descriptive link text. Link guides to the tools they explain.
- **Speed and security**: HTTPS everywhere, HSTS, a CSP that allows only the scripts you use (section 6).
- Multiple languages: use `hreflang` and separate URLs per language; do not auto-redirect by IP. Skip until you actually have translations.

## 5. Google Search Console (do this the day the site goes live)
1. Go to search.google.com/search-console, **Add property -> Domain**, enter `scansentry.example`, and add the **DNS TXT record** Google gives you at your registrar. (A *Domain* property covers http/https and all subdomains.)
2. **Sitemaps** -> submit `https://scansentry.example/sitemap.xml`. It should show "Success" and a discovered-URL count.
3. **URL Inspection**: paste the home page and the scanner page, check "URL is on Google" / "Test live URL" -> view the rendered HTML: **the title, headings and text must be visible there** (this proves prerendering works). Use "Request indexing" for key pages (limited daily).
4. Watch **Pages** (indexing; "Excluded" should contain only what you meant to exclude, e.g. `/r/`), **Core Web Vitals**, **Mobile usability**/page experience, and **Search results** (queries, clicks, position).
5. Check **Security issues / Manual actions** weekly at first: a security brand that is wrongly flagged loses trust fast.
6. Also add the site to **Bing Webmaster Tools** (it can import from Search Console). Optional: IndexNow for faster Bing/Yandex discovery.
7. Create a **Google Business Profile** only if you have a real business address/presence you want shown.

## 6. Analytics, scripts and the privacy promise
ScanSentry's promise: scanning is private, no IP/user-agent/URL analytics on scans. A Google tag on the wrong page would break that promise, so:
- **Never** load analytics, ad or tag-manager scripts on the scanner, scan results, `/r/` verification, domain reports, the signed-in app or any security warning (also the ad rules in the PRD). Marketing pages only.
- Choose the tool deliberately: **Google Analytics 4** (free, powerful, sends data to Google; needs consent in many regions) or a privacy-first tool (Plausible, Umami, self-hosted: no cookies, simpler compliance, fewer features).
  A privacy-focused product has a credible reason to pick the second. If you use GA4, use `docs/seo/consent-mode-snippet.html` (Consent Mode v2: denied until the visitor agrees, anonymised IP, Google signals off) and describe it in the privacy policy.
- **Consent**: use a banner/CMP. Personalised ads in the EEA/UK need a Google-certified CMP. Check Nigeria's Data Protection Act (NDPA 2023) and the rules wherever your users are: get legal advice (see `PRIVACY_AND_DATA.md`).
- **Google Tag Manager** lets whoever has access inject arbitrary scripts into your site. If you use it, restrict who can publish, and still keep it off the sensitive pages.
- **No personal data in events** (emails, scanned content, full URLs with query strings).
- **Content-Security-Policy** on the web host: allow `script-src` only for your own origin and `https://www.googletagmanager.com` / `https://www.google-analytics.com` (and ad domains only if you run ads) on the marketing pages; keep the app and scanner pages on a stricter policy with no third-party scripts.
- **AdSense / Ad Manager (web)**: needs an approved account and an `ads.txt` (`docs/seo/ads.txt.example`); ads only on the allowed non-critical pages (see PRD section 9 and `README.md`). **AdMob (Android)** needs `app-ads.txt` on the developer website named in your Play listing.
- **Search Console is not analytics**: it shows how you appear in Google; analytics shows what visitors do. Use both.

## 7. Content and authority (what actually moves rankings over months)
1. Publish 6-10 genuinely helpful guides (quishing, fake QR stickers on parking meters/restaurants, how to inspect a link, what domain age does and does not tell you) written by a named author with real expertise.
2. Make the free tools excellent and shareable (the scanner and domain checker): useful tools attract links on their own.
3. Earn links honestly: security blogs, local tech press, university/IT-department resources, a "how we assess domains" methodology page others can cite. Do not buy links or use link farms (penalty risk).
4. Keep pages current: dates, accuracy, and a changelog on the methodology page.
5. Expect: indexing in days to weeks, first impressions in weeks, meaningful traffic in 3-6+ months. Track impressions and queries in Search Console and improve the pages that already get impressions but few clicks (titles/descriptions).
**Avoid**: keyword stuffing, doorway/near-duplicate pages, cloaking (showing Google different content), hidden text, scaled AI-written filler, fake reviews or ratings in markup. These cause penalties.

## 8. How to verify (run this before launch and after each release)
```
python scripts/seo_check.py https://scansentry.example --private /r/example-token /app /dashboard /scan/result
```
It fetches robots.txt, the sitemap and each listed page and reports titles, descriptions, h1s, canonicals, JSON-LD validity, noindex on private paths, soft-404 behaviour and client-rendered shells. FAIL = fix before launch.
Then, manually: Search Console URL Inspection (rendered HTML), PageSpeed Insights (mobile), Rich Results Test, and view-source on the home page.

## 9. What is and is not done
Done in the backend: the API host is never indexed (header + robots.txt, tested); the SEO audit script (tested against a good and a bad fake site); the starter files in `docs/seo/`; the smoke test checks the API host's noindex.
**Not done (needs the web app):** any page, prerendering, sitemap generation, the consent banner, analytics, structured data on real pages, Search Console setup (needs your domain's DNS), and content. The script is only as good as the pages it is pointed at.
