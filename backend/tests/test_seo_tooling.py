"""The API host is never indexed, and the website SEO checker really detects good and bad sites."""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parent.parent
SCRIPT = str(BACKEND / "scripts" / "seo_check.py")


# ---- the API host -------------------------------------------------------------------------------------------------------------------------------
@pytest.mark.django_db
def test_every_api_response_says_noindex(api):
    for path in ("/api/v1/health/", "/api/v1/plans/", "/api/v1/auth/me/", "/api/v1/scanner/verify/nope/", "/robots.txt", "/admin/login/"):
        r = api.get(path)
        assert "noindex" in r["X-Robots-Tag"] and "nofollow" in r["X-Robots-Tag"], path


@pytest.mark.django_db
def test_robots_txt_blocks_the_whole_api_host(api):
    r = api.get("/robots.txt")
    assert r.status_code == 200 and r["Content-Type"].startswith("text/plain") and r.content.decode() == "User-agent: *\nDisallow: /\n"


# ---- a fake website for the checker ------------------------------------------------------------------------------------------------------------
LOREM = " ".join(["ScanSentry helps you see where a QR code leads before you open it."] * 25)


def page(title="ScanSentry QR scanner: check where a QR code leads", desc="Scan any QR code and see the destination, the website's age and warning signs before you open it. No account needed.",
         h1=1, canonical="http://HOST/", extra="", robots=None, body=LOREM):
    head = f"<title>{title}</title>" if title else ""
    if desc:
        head += f'<meta name="description" content="{desc}">'
    if canonical:
        head += f'<link rel="canonical" href="{canonical}">'
    if robots:
        head += f'<meta name="robots" content="{robots}">'
    head += '<meta name="viewport" content="width=device-width,initial-scale=1"><meta property="og:title" content="t"><meta property="og:description" content="d"><meta property="og:image" content="i">'
    return f'<!doctype html><html lang="en"><head>{head}{extra}</head><body>{"<h1>Heading</h1>" * h1}<p>{body}</p></body></html>'


def good_site(host):
    ld = '<script type="application/ld+json">' + json.dumps({"@context": "https://schema.org", "@type": "WebApplication", "name": "ScanSentry"}) + "</script>"
    sitemap = f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://{host}/</loc></url><url><loc>http://{host}/features</loc></url></urlset>'
    return {
        "/robots.txt": (200, {}, f"User-agent: *\nAllow: /\nDisallow: /r/\nDisallow: /app\nDisallow: /dashboard\nDisallow: /scan/\nSitemap: http://{host}/sitemap.xml\n"),
        "/sitemap.xml": (200, {}, sitemap),
        "/": (200, {}, page(canonical=f"http://{host}/", extra=ld).replace("HOST", host)),
        "/features": (200, {}, page(title="Features: QR codes you can manage and verify", canonical=f"http://{host}/features")),
        "/r/example-token": (200, {"X-Robots-Tag": "noindex, nofollow"}, page(title="Verify this QR code", robots="noindex")),
        "/app": (401, {}, "login"), "/dashboard": (404, {}, "nope"),
        "/scan/result": (200, {}, page(title="Scan result for this code", robots="noindex, nofollow")),
    }


def bad_site(host):
    return {
        "/robots.txt": (200, {}, "User-agent: *\nDisallow: /\n"),
        "/sitemap.xml": (200, {}, f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://{host}/</loc></url><url><loc>http://{host}/r/example-token</loc></url><url><loc>http://other.example/x</loc></url><url><loc>http://{host}/hidden</loc></url></urlset>'),
        "/": (200, {}, page(title="", desc="", h1=2, canonical="", body="short", extra='<script type="application/ld+json">{not json</script>')),
        "/r/example-token": (200, {}, page(title="Verify", canonical=f"http://{host}/r/example-token")),
        "/hidden": (200, {}, page(robots="noindex", canonical=f"http://{host}/hidden")),
        "/app": (200, {}, page()), "/dashboard": (200, {}, page()), "/scan/result": (200, {}, page()),
        "*": (200, {}, page()),                                   # a soft 404: unknown URLs answer 200
    }


@pytest.fixture
def serve():
    servers = []

    def start(builder):
        holder = {}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                host = f"127.0.0.1:{self.server.server_port}"
                site = holder.setdefault("site", builder(host))
                status, headers, body = site.get(self.path.split("?")[0]) or site.get("*") or (404, {}, "not found")
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/xml" if self.path.endswith(".xml") else "text/plain" if self.path.endswith(".txt") else "text/html")
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *a):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"

    yield start
    for s in servers:
        s.shutdown()


def run(url, *extra):
    r = subprocess.run([sys.executable, SCRIPT, url, *extra], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout


def test_a_well_built_site_passes(serve):
    code, out = run(serve(good_site))
    assert code == 0 and "0 failed" in out, out
    assert "sitemap lists 2 URLs" in out and "JSON-LD block parses" in out and "not indexable" in out


def test_a_badly_built_site_fails_for_the_right_reasons(serve):
    code, out = run(serve(bad_site))
    assert code == 1
    for expected in ("blocks the whole site", "no Sitemap:", "another host", "lists a private/non-indexable URL", "marked noindex",
                     "title is 0 characters", "meta description is 0 characters", "has 2 h1", "canonical link missing", "not valid JSON",
                     "returns 200 and is indexable", "unknown URLs return 200"):
        assert expected in out, expected


def test_client_rendered_shells_get_a_prerender_warning(serve):
    spa = lambda host: {**good_site(host), "/": (200, {}, page(body="Loading...").replace("HOST", host))}
    code, out = run(serve(spa))
    assert "built by JavaScript" in out and "WARN" in out


def test_private_paths_are_configurable(serve):
    code, out = run(serve(good_site), "--private", "/r/x")
    assert code == 0 and "/r/x" in out


def test_an_unreachable_site_fails_cleanly():
    code, out = run("http://127.0.0.1:9")
    assert code == 1 and "FAIL" in out


# ---- the checker must be safe to point at a hostile site ----------------------------------------------------------------------------------------
def test_the_checker_refuses_non_http_schemes():
    code, out = run("file:///etc/hosts")
    assert code == 1 and "root:" not in out


def test_a_billion_laughs_sitemap_is_refused_not_parsed(serve):
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>&c;</loc></url></urlset>')
    site = lambda host: {**good_site(host), "/sitemap.xml": (200, {}, bomb)}
    code, out = run(serve(site))
    assert code == 1 and "DOCTYPE/ENTITY" in out


def test_a_sitemap_cannot_make_the_checker_fetch_other_hosts_or_files(serve):
    hits = []

    class Spy(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x")

        def log_message(self, *a):
            pass

    spy = ThreadingHTTPServer(("127.0.0.1", 0), Spy)
    threading.Thread(target=spy.serve_forever, daemon=True).start()
    try:
        spy_url = f"http://localhost:{spy.server_port}/internal-admin"
        sm = lambda host: {**good_site(host), "/sitemap.xml": (200, {}, '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                           f"<url><loc>http://{host}/</loc></url><url><loc>{spy_url}</loc></url><url><loc>file:///etc/passwd</loc></url></urlset>")}
        code, out = run(serve(sm))
        assert "another host" in out and code == 1
        assert hits == []                                   # the other host was never contacted
    finally:
        spy.shutdown()
