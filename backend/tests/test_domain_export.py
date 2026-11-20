import csv
import io

import pytest
from rest_framework.test import APIClient

from apps.billing.models import EntitlementOverride, FeatureDefinition
from apps.domain_intel import export
from apps.domain_intel.models import DomainAssessment

pytestmark = pytest.mark.django_db


@pytest.fixture
def assessment(auth_client, senv):
    senv.publish("shop.com")
    r = auth_client.post("/api/v1/domains/analyze/", {"value": "shop.com"}, format="json")
    assert r.status_code == 200
    return r.data["id"], r.data


def url(aid, kind):
    return f"/api/v1/domains/assessments/{aid}/export/?type={kind}"


def rows(resp):
    return list(csv.reader(io.StringIO(resp.content.decode("utf-8-sig"))))


def test_csv_export_downloads_the_report(auth_client, assessment):
    aid, data = assessment
    r = auth_client.get(url(aid, "csv"))
    assert r.status_code == 200 and r["Content-Type"].startswith("text/csv")
    assert r["Content-Disposition"] == 'attachment; filename="scansentry-shop.com.csv"' and r["Cache-Control"] == "private, no-store"
    table = rows(r)
    assert table[0] == ["section", "field", "value"]
    flat = {(s, f): v for s, f, v in table[1:]}
    assert flat[("overview", "domain")] == "shop.com"
    assert any(s == "registration" and f == "registrar" and v for s, f, v in table)


def test_exports_carry_the_disclaimer_and_the_limitations(auth_client, assessment):
    aid, data = assessment
    t = rows(auth_client.get(url(aid, "csv")))
    assert "never certifies a website as safe" in t[1][2]
    assert data["limitations"] and sum(1 for sec, *_ in t if sec == "limitations") >= 1


def test_missing_checks_are_listed_in_both_formats_never_hidden():
    report = {"domain": "x.com", "missing_checks": [{"check": "rdap", "reason": "registry unreachable"}], "provider_errors": ["web_risk: timeout"],
              "limitations": ["Age is not trust."]}
    t = list(csv.reader(io.StringIO(export.to_csv(report).decode("utf-8-sig"))))
    flat = " | ".join(",".join(r) for r in t)
    assert "registry unreachable" in flat and "web_risk: timeout" in flat
    from pypdf import PdfReader
    pdf_text = " ".join(pg.extract_text() for pg in PdfReader(io.BytesIO(export.to_pdf(report))).pages)
    assert "registry unreachable" in pdf_text and "web_risk: timeout" in pdf_text


def test_exports_never_call_a_site_safe(auth_client, assessment):
    import re
    aid, _ = assessment
    body = auth_client.get(url(aid, "csv")).content.decode("utf-8-sig").replace(export.DISCLAIMER, "")
    assert not re.search(r"\bsafe\b", body, re.I)


def test_pdf_export_is_a_real_pdf(auth_client, assessment):
    aid, _ = assessment
    r = auth_client.get(url(aid, "pdf"))
    assert r.status_code == 200 and r["Content-Type"] == "application/pdf" and r.content.startswith(b"%PDF-") and r.content.rstrip().endswith(b"%%EOF")
    assert r["Content-Disposition"].endswith('.pdf"') and r["X-Content-Type-Options"] == "nosniff"


def test_pdf_text_can_be_read_back(auth_client, assessment):
    from pypdf import PdfReader
    aid, _ = assessment
    text = " ".join(pg.extract_text() for pg in PdfReader(io.BytesIO(auth_client.get(url(aid, "pdf")).content)).pages)
    assert "ScanSentry domain report" in text and "shop.com" in text and "never certifies" in text


def test_exports_need_a_login(api, assessment):
    aid, _ = assessment
    assert api.get(url(aid, "csv")).status_code == 401


def test_exports_are_blocked_by_the_plan_on_the_backend(user, auth_client, assessment):
    aid, _ = assessment
    EntitlementOverride.objects.create(user=user, kind="feature", feature=FeatureDefinition.objects.get(key="domain.reports.export"), enabled=False, note="plan test")
    for kind in ("csv", "pdf"):
        r = auth_client.get(url(aid, kind))
        assert r.status_code == 403 and r.data["error"]["code"] == "feature_not_available"


def test_a_bad_type_or_unknown_assessment(auth_client, assessment):
    aid, _ = assessment
    assert auth_client.get(url(aid, "xlsx")).status_code == 400 and auth_client.get(f"/api/v1/domains/assessments/{aid}/export/").status_code == 400
    assert auth_client.get(url("00000000-0000-0000-0000-000000000000", "csv")).status_code == 404


def test_the_filename_cannot_be_manipulated(auth_client, assessment):
    aid, _ = assessment
    DomainAssessment.objects.filter(pk=aid).update(domain='evil"; x=y\r\nSet-Cookie: a=b.com')
    r = auth_client.get(url(aid, "csv"))
    cd = r["Content-Disposition"]
    assert "\r" not in cd and "\n" not in cd and cd.count('"') == 2


# ---- the renderers directly: hostile content ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("cell", ["=HYPERLINK(\"http://evil\",\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_csv_cells_that_would_run_as_formulas_are_neutralised(cell):
    assert export.csv_safe(cell).startswith("'")
    assert export.csv_safe("normal text") == "normal text" and export.csv_safe("a=b") == "a=b"


def test_hostile_registrar_text_cannot_become_a_formula_in_the_csv():
    report = {"domain": "x.com", "registration": {"registrar": '=cmd|" /C calc"!A0', "nameservers": ["@evil", "ns1.x.com"]}, "missing_checks": []}
    t = list(csv.reader(io.StringIO(export.to_csv(report).decode("utf-8-sig"))))
    values = [v for *_, v in t]
    assert not any(v.startswith(("=", "+", "-", "@")) for v in values)
    assert any(v.startswith("'=cmd") for v in values)


def test_pdf_survives_markup_and_huge_values():
    report = {"domain": "x.com", "display_domain": "<b>x</b>.com & <script>", "checked_at": None,
              "registration": {"registrar": "<para>" * 50 + "&" * 20, "note": "A" * 50000}, "missing_checks": ["a<b", {"x": "&amp;"}], "limitations": ["ok"]}
    pdf = export.to_pdf(report)
    assert pdf.startswith(b"%PDF-") and len(pdf) < 200_000


def test_flatten_keeps_empty_values_visible_instead_of_inventing_them():
    assert export.flatten({"a": None, "b": [], "c": {}, "d": {"e": True}}) == [("a", ""), ("b", ""), ("c", ""), ("d.e", "yes")]
