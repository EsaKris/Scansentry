#!/usr/bin/env python3
"""Technical SEO audit for the public WEBSITE (not the API). Standard library only; read-only.

    python scripts/seo_check.py https://scansentry.com [--private /r/test /app/dashboard /scan/result] [--max-pages 30]

FAIL = fix before launch. WARN = advice. Exit code 1 if any FAIL.
It checks what a crawler sees in the raw HTML. It cannot judge content quality, rankings or Core Web Vitals (use Search Console and PageSpeed Insights).
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

UA = {"User-Agent": "Mozilla/5.0 (compatible; ScanSentrySEOCheck/1.0)"}
fails, warns, passes = [], [], []


def fetch(url, max_bytes=2_000_000):
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        return 0, {}, "", "only http and https URLs are fetched"      # never file:// or other schemes
    req = urllib.request.Request(url, headers=UA)
    try:
        r = urllib.request.urlopen(req, timeout=20)  # nosec B310 - scheme restricted to http/https above
    except urllib.error.HTTPError as e:
        r = e
    except Exception as e:                      # noqa: BLE001
        return 0, {}, "", str(e)
    body = r.read(max_bytes).decode("utf-8", "replace")
    return r.status, {k.lower(): v for k, v in r.headers.items()}, body, r.geturl()


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title, self.h1, self.meta, self.links = "", False, 0, {}, {}
        self.jsonld, self._in_ld, self.lang, self.imgs, self.imgs_no_alt, self.text = [], False, "", 0, 0, []
        self._skip = 0

    def handle_starttag(self, tag, a):
        a = dict(a)
        if tag == "html":
            self.lang = a.get("lang", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "h1":
            self.h1 += 1
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or "").lower()
            if key:
                self.meta[key] = a.get("content", "")
        elif tag == "link" and a.get("rel"):
            self.links[a["rel"].lower()] = a.get("href", "")
        elif tag == "script":
            if a.get("type", "").lower() == "application/ld+json":
                self._in_ld = True
                self.jsonld.append("")
            else:
                self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "img":
            self.imgs += 1
            if not a.get("alt", "").strip() and a.get("role") != "presentation":
                self.imgs_no_alt += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            if self._in_ld:
                self._in_ld = False
            elif self._skip:
                self._skip -= 1
        elif tag == "style" and self._skip:
            self._skip -= 1

    def handle_data(self, d):
        if self._in_title:
            self.title += d
        elif self._in_ld:
            self.jsonld[-1] += d
        elif not self._skip:
            self.text.append(d)


def rec(level, msg):
    {"PASS": passes, "WARN": warns, "FAIL": fails}[level].append(msg)
    print(f"{level:5} {msg}")


def audit_page(url, require_indexable=True):
    status, headers, body, final = fetch(url)
    if status != 200:
        rec("FAIL", f"{url} returned {status or 'no response'}")
        return
    p = Page()
    p.feed(body)
    where = urllib.parse.urlparse(url).path or "/"
    title = " ".join(p.title.split())
    desc = p.meta.get("description", "").strip()
    robots = (p.meta.get("robots", "") + " " + headers.get("x-robots-tag", "")).lower()
    if require_indexable and "noindex" in robots:
        rec("FAIL", f"{where}: a page in the sitemap is marked noindex")
    rec("PASS" if 10 <= len(title) <= 70 else "FAIL" if not title else "WARN", f"{where}: title is {len(title)} characters" + ("" if 10 <= len(title) <= 70 else " (aim for 30-60)"))
    rec("PASS" if 50 <= len(desc) <= 170 else "FAIL" if not desc else "WARN", f"{where}: meta description is {len(desc)} characters" + ("" if 50 <= len(desc) <= 170 else " (aim for 70-160)"))
    rec("PASS" if p.h1 == 1 else "FAIL", f"{where}: has {p.h1} h1 (needs exactly 1)")
    canon = p.links.get("canonical", "")
    rec("PASS" if canon and urllib.parse.urlparse(canon).netloc == urllib.parse.urlparse(url).netloc else "FAIL", f"{where}: canonical link " + (canon or "missing"))
    rec("PASS" if p.lang else "WARN", f"{where}: html lang attribute " + (p.lang or "missing"))
    rec("PASS" if "viewport" in p.meta else "FAIL", f"{where}: mobile viewport meta " + ("present" if "viewport" in p.meta else "missing"))
    for k in ("og:title", "og:description", "og:image"):
        if k not in p.meta:
            rec("WARN", f"{where}: missing {k} (social previews)")
    for block in p.jsonld:
        try:
            json.loads(block)
            rec("PASS", f"{where}: JSON-LD block parses")
        except ValueError:
            rec("FAIL", f"{where}: a JSON-LD block is not valid JSON (search engines ignore it)")
    words = len(" ".join(p.text).split())
    if words < 120:
        rec("WARN", f"{where}: only {words} words in the raw HTML: if this page is built by JavaScript, search engines may index it late or poorly (prerender it)")
    if p.imgs_no_alt:
        rec("WARN", f"{where}: {p.imgs_no_alt} of {p.imgs} images have no alt text")
    if len(body) > 1_500_000:
        rec("WARN", f"{where}: HTML is very large ({len(body) // 1024} KB)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--private", nargs="*", default=["/r/example-token", "/app", "/dashboard", "/scan/result"],
                    help="paths that must NOT be indexable (scan results, QR verification, signed-in pages)")
    ap.add_argument("--max-pages", type=int, default=30)
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    host = urllib.parse.urlparse(base).netloc

    if not base.startswith("https://"):
        rec("WARN", "not an https:// site: Google prefers HTTPS and browsers warn")

    s, _, robots, _ = fetch(base + "/robots.txt")
    if s != 200:
        rec("FAIL", f"/robots.txt returned {s}")
    else:
        rec("PASS", "robots.txt exists")
        if re.search(r"(?im)^\s*disallow:\s*/\s*$", robots) and not re.search(r"(?im)^\s*allow:", robots):
            rec("FAIL", "robots.txt blocks the whole site (Disallow: /)")
        if not re.search(r"(?im)^\s*sitemap:\s*\S+", robots):
            rec("FAIL", "robots.txt has no Sitemap: line")
        for path in a.private:
            top = "/" + path.strip("/").split("/")[0] + "/"
            if not re.search(rf"(?im)^\s*disallow:\s*{re.escape(top)}", robots) and not re.search(rf"(?im)^\s*disallow:\s*{re.escape(top.rstrip('/'))}\s*$", robots):
                rec("WARN", f"robots.txt does not disallow {top} (a noindex tag/header is the stronger control: both is best)")

    urls = []
    s, _, sm, _ = fetch(base + "/sitemap.xml")
    if s != 200:
        rec("FAIL", f"/sitemap.xml returned {s}")
    else:
        if re.search(r"<!(DOCTYPE|ENTITY)", sm, re.I):                  # a sitemap never needs a DTD; refusing it blocks entity-expansion attacks
            rec("FAIL", "sitemap.xml contains a DOCTYPE/ENTITY declaration (not a valid sitemap, and unsafe to parse)")
            sm = ""
        try:
            root = ET.fromstring(sm) if sm else None  # nosec B314 - DOCTYPE/ENTITY rejected above
            if root is None:
                raise ET.ParseError()
            urls = [e.text.strip() for e in root.iter() if e.tag.endswith("loc") and e.text]
            rec("PASS" if urls else "FAIL", f"sitemap lists {len(urls)} URLs")
        except ET.ParseError:
            rec("FAIL", "sitemap.xml is not valid XML")
    foreign = [u for u in urls if urllib.parse.urlparse(u).netloc != host]
    if foreign:
        rec("FAIL", f"sitemap contains URLs on another host, e.g. {foreign[0]}")
    for u in urls:
        if any(f"/{x.strip('/').split('/')[0]}" == urllib.parse.urlparse(u).path.rstrip("/")[:len(x.strip('/').split('/')[0]) + 1] for x in a.private):
            rec("FAIL", f"sitemap lists a private/non-indexable URL: {u}")

    for u in [u for u in urls if urllib.parse.urlparse(u).netloc == host][:a.max_pages]:      # never fetch other hosts or schemes a sitemap points at
        audit_page(u)
    if not urls:
        audit_page(base + "/")

    for path in a.private:
        s, h, body, _ = fetch(base + path)
        p = Page()
        p.feed(body)
        robots_meta = (p.meta.get("robots", "") + " " + h.get("x-robots-tag", "")).lower()
        if s in (401, 403, 404, 410) or "noindex" in robots_meta:
            rec("PASS", f"{path}: not indexable (HTTP {s}{', noindex' if 'noindex' in robots_meta else ''})")
        else:
            rec("FAIL", f"{path}: returns {s} and is indexable: scan results and QR links must be noindex")

    s, _, body, _ = fetch(base + "/this-page-should-not-exist-seo-check")
    rec("PASS" if s == 404 else "FAIL", f"unknown URLs return {s} " + ("" if s == 404 else "(needs a real 404, otherwise Google sees 'soft 404' duplicates)"))

    print(f"\n{len(passes)} passed, {len(warns)} warnings, {len(fails)} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
