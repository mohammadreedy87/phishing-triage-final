"""Phase 4: Structured HTML (Jinja2) and PDF (ReportLab) Triage Report Exporter."""
from __future__ import annotations

import io
from xml.sax.saxutils import escape
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _wrap(rows):
    """Turn table cells into escaped, wrapping Paragraphs so long text never runs off the page."""
    base = getSampleStyleSheet()["Normal"]
    cell = ParagraphStyle("Cell", parent=base, fontSize=9.5, leading=12)
    head = ParagraphStyle("CellHead", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    return [
        [Paragraph(escape(str(c)), head if i == 0 else cell) for c in row]
        for i, row in enumerate(rows)
    ]


def render_html_report(analysis: Dict[str, Any], templates_dir: str | Path) -> str:
    """Render a standalone printable HTML triage report."""
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report_template.html")
    return template.render(analysis=analysis)


def generate_pdf_report_bytes(analysis: Dict[str, Any]) -> bytes:
    """Generate a structured SOC Phishing Triage PDF report using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0F2942"), spaceAfter=10
    )
    h2_style = ParagraphStyle(
        "SectionH2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1B4965"), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle("Body10", parent=styles["Normal"], fontSize=10, leading=14)

    env = analysis["envelope"]
    risk = analysis["risk"]
    auth = analysis["forensics"]["authentication"]
    routing = analysis["forensics"]["routing"]

    elements = [
        Paragraph("SOC Phishing Triage Investigation Report", title_style),
        Paragraph(
            f"<b>Case ID:</b> {escape(analysis['id'])} &nbsp;|&nbsp; <b>Analyzed At:</b> {escape(analysis['analyzed_at'])} &nbsp;|&nbsp; "
            f"<b>File:</b> {escape(analysis['source_filename'])}",
            body_style,
        ),
        Spacer(1, 8),
        Paragraph("1. Executive Verdict & Risk Summary", h2_style),
        Paragraph(
            f"<b>Phishing Risk Score:</b> {risk['score']}/100 ({escape(risk['verdict'])})<br/>"
            f"<b>Suggested next step (analyst decides):</b> {escape(risk['recommended_action'])}<br/>"
            "<i>Heuristic score, not a confirmed verdict. Corroborate before acting.</i>",
            body_style,
        ),
        Spacer(1, 6),
        Paragraph("2. Email Envelope & Authentication", h2_style),
    ]

    meta_table = Table(
        _wrap([
            ["Field", "Extracted Value"],
            ["From", env.get("from_raw") or "(none)"],
            ["Return-Path", env.get("return_path_raw") or "(none)"],
            ["Reply-To", env.get("reply_to_raw") or "(none)"],
            ["To", ", ".join(env.get("to_addresses", [])) or "(none)"],
            ["Subject", env.get("subject") or "(none)"],
            ["Origin IP", routing.get("origin_ip") or "Not found"],
            ["SPF/DKIM/DMARC (claimed)", f"SPF={auth['spf']} | DKIM={auth['dkim']} | DMARC={auth['dmarc']}"],
            ["Re-validated", "SPF={} | DKIM={} | DMARC={} (SPF/DMARC conditional)".format(*[analysis["forensics"].get("revalidation", {}).get(k, {}).get("result", "n/a") for k in ("spf", "dkim", "dmarc")])],
        ]),
        colWidths=[1.8 * inch, 5.2 * inch],
    )
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F2942")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(meta_table)

    elements.append(Paragraph("3. Risk Score Breakdown", h2_style))
    if risk["breakdown"]:
        b_rows = _wrap([["Category", "Points", "Finding"]] + [
            [item["category"], f"+{item['points']}", item["reason"]] for item in risk["breakdown"]
        ])
        b_table = Table(b_rows, colWidths=[1.7 * inch, 0.8 * inch, 4.5 * inch])
        b_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1B4965")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ]))
        elements.append(b_table)
    else:
        elements.append(Paragraph("No risk-elevating indicators detected.", body_style))

    elements.append(Paragraph("4. Extracted URLs & Attachments", h2_style))
    elements.append(Paragraph(f"<b>Embedded URLs Found:</b> {len(analysis['urls'])}", body_style))
    for u in analysis["urls"][:15]:
        flags = "; ".join(u["heuristic_flags"]) if u["heuristic_flags"] else "No heuristic flags"
        elements.append(Paragraph(escape(f"- [{u['heuristic_risk'].upper()}] {u['url']} ({flags})"), body_style))

    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Attachments Found:</b> {len(analysis['attachments'])}", body_style))
    for att in analysis["attachments"]:
        flags = "; ".join(att["flags"]) if att["flags"] else "No heuristic flags"
        elements.append(
            Paragraph(
                escape(f"- [{att['heuristic_rating'].upper()}] {att['filename']} | SHA-256: {att['sha256'][:24]}... ({flags})"),
                body_style,
            )
        )

    doc.build(elements)
    return buffer.getvalue()
