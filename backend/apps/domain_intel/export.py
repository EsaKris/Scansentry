"""Downloadable domain reports (CSV and PDF), built from the SAME public structure the API returns (presenters.present).

Nothing is computed here: the file says exactly what the report says, including the checks that could not be completed and the limitations.

Security notes
  * CSV: values come from third parties (registrar names, page content, DNS records). A cell starting with = + - @ (or a tab/CR) is run as a formula by
    spreadsheet programs, so such cells are prefixed with an apostrophe.
  * PDF: reportlab parses markup in paragraphs, so every value is XML-escaped; lengths are capped.
"""
import csv
import io
from datetime import date, datetime, timezone
from xml.sax.saxutils import escape

DISCLAIMER = ("ScanSentry never certifies a website as safe. This report lists what was observed at the time shown and which checks could not be completed. "
              "Domain age, HTTPS and the absence of a finding are not proof of legitimacy.")
SKIP_TOP = {"id", "cached", "cache_expires_at"}
MAX_VALUE = 600
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def flatten(value, prefix=""):
    """Nested dict/list -> [(path, text)]. Empty values are kept as '' so absence is visible, never invented."""
    out = []
    if isinstance(value, dict):
        if not value:
            return [(prefix, "")]
        for k, v in value.items():
            out += flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, (list, tuple)):
        if not value:
            return [(prefix, "")]
        if all(not isinstance(i, (dict, list, tuple)) for i in value):
            return [(prefix, ", ".join(text(i) for i in value))]
        for i, v in enumerate(value, 1):
            out += flatten(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, text(value)))
    return out


def text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return str(v)


def csv_safe(cell: str) -> str:
    cell = cell if isinstance(cell, str) else str(cell)
    return "'" + cell if cell.startswith(FORMULA_START) else cell


def sections(report: dict):
    """[(section name, [(field, value)])] in the report's own order."""
    out, general = [], []
    for key, val in report.items():
        if key in SKIP_TOP:
            continue
        if isinstance(val, (dict, list)) and val:
            out.append((key, flatten(val)))
        else:
            general.append((key, text(val)))
    return [("overview", general)] + out


def to_csv(report: dict) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(["section", "field", "value"])
    w.writerow(["notice", "disclaimer", DISCLAIMER])
    w.writerow(["notice", "exported_at", datetime.now(timezone.utc).isoformat(timespec="seconds")])
    for name, rows in sections(report):
        for field, value in rows:
            w.writerow([csv_safe(name), csv_safe(field.removeprefix(name + ".") if field != name else field), csv_safe(value)])
    return b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")          # BOM so spreadsheet programs read UTF-8 correctly


def to_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    cell = ParagraphStyle("cell", parent=ss["BodyText"], fontSize=8, leading=10)
    head = ParagraphStyle("head", parent=ss["Heading2"], textColor=colors.HexColor("#0B1F3A"), spaceBefore=10)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"ScanSentry domain report: {report.get('domain', '')}"[:120], author="ScanSentry")

    def p(value, style=cell):
        return Paragraph(escape(str(value)[:MAX_VALUE]), style)

    story = [Paragraph("ScanSentry domain report", ss["Title"]),
             Paragraph(escape(str(report.get("display_domain") or report.get("domain") or "")), ss["Heading1"]),
             p(f"Checked at: {text(report.get('checked_at'))}  |  Engine: {text(report.get('engine_version'))}  |  Status: {text(report.get('completion_status'))}"),
             Spacer(1, 4 * mm),
             Table([[Paragraph(escape(DISCLAIMER), cell)]], colWidths=[178 * mm],
                   style=TableStyle([("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#0B7A75")), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EAF6F5")),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))]
    for name, rows in sections(report):
        story.append(Paragraph(escape(name.replace("_", " ").title()), head))
        data = [[p(f.removeprefix(name + ".") or f), p(v)] for f, v in rows] or [[p("(nothing recorded)"), p("")]]
        story.append(Table(data, colWidths=[62 * mm, 116 * mm], repeatRows=0,
                           style=TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9D3DF")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                             ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F7FA"))])))
    story += [Spacer(1, 6 * mm), p(f"Exported {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC by ScanSentry.")]
    doc.build(story)
    return buf.getvalue()
