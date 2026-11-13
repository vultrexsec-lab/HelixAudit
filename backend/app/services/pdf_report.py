"""White-label capable PDF report (Phase B)."""

from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from ..core.config import settings


def build_pdf_report(scan, project, findings, assets, counts) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("T", parent=styles["Heading1"], fontSize=16, spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=5)
    body = styles["BodyText"]
    small = ParagraphStyle("Small", parent=body, fontSize=8, leading=10)
    muted = ParagraphStyle("Muted", parent=body, fontSize=8, textColor=colors.grey)

    brand = settings.BRAND_COMPANY_NAME or settings.PROJECT_NAME
    client = getattr(project, "client_name", None) or getattr(project, "name", None) or "Client"
    footer = settings.BRAND_REPORT_FOOTER

    story = []
    story.append(Paragraph(f"{brand} — Security Assessment Report", title_style))
    story.append(Paragraph(
        f"<b>Prepared for:</b> {client}<br/>"
        f"<b>Project:</b> {getattr(project, 'name', 'N/A')}<br/>"
        f"<b>Target:</b> {scan.target}<br/>"
        f"<b>Scan ID:</b> #{scan.id} &nbsp;|&nbsp; <b>Status:</b> {scan.status}<br/>"
        f"<b>Window:</b> {scan.started_at} → {scan.completed_at}",
        body,
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Automated discovery and assessment support expert review. Authorized use only.",
        muted,
    ))

    exec_findings = [f for f in findings if (getattr(f, "category", None) or "") == "Executive Summary"]
    exec_text = (exec_findings[0].evidence if exec_findings else "") or ""
    story.append(Paragraph("1. Executive Summary", h2))
    if exec_text:
        for line in exec_text.splitlines()[:12]:
            story.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;"), small))
        story.append(Spacer(1, 6))

    summary = [[
        f"Critical: {counts.get('critical', 0)}",
        f"High: {counts.get('high', 0)}",
        f"Medium: {counts.get('medium', 0)}",
        f"Low: {counts.get('low', 0)}",
        f"Info: {counts.get('info', 0)}",
        f"Assets: {len(assets)}",
    ]]
    t = Table(summary, colWidths=[28 * mm] * 6)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(t)

    auth_fs = [
        f for f in findings
        if isinstance(getattr(f, "extra_data", None), dict)
        and (f.extra_data or {}).get("exposure") == "auth"
    ]
    pub_fs = [
        f for f in findings
        if f not in auth_fs and (getattr(f, "category", None) or "") != "Executive Summary"
    ]

    story.append(Paragraph("2. Public surface findings", h2))
    story.append(Paragraph(f"Count: {len(pub_fs)}", small))
    if not pub_fs:
        story.append(Paragraph("No public findings recorded.", body))
    else:
        for i, f in enumerate(pub_fs[:50], 1):
            story.append(Paragraph(f"<b>{i}. [{(f.severity or '').upper()}] {f.title or ''}</b>", small))
            story.append(Paragraph(
                f"Location: {f.location or '—'}<br/>"
                f"Evidence: {str(f.evidence or '—')[:280]}<br/>"
                f"Remediation: {str(f.remediation or '—')[:200]}",
                small,
            ))

    story.append(Paragraph("3. Authenticated findings", h2))
    if not auth_fs:
        story.append(Paragraph("No authenticated findings (login not used or failed).", body))
    else:
        for i, f in enumerate(auth_fs[:30], 1):
            story.append(Paragraph(f"<b>{i}. [{(f.severity or '').upper()}] {f.title or ''}</b>", small))
            story.append(Paragraph(
                f"Location: {f.location or '—'}<br/>Evidence: {str(f.evidence or '—')[:250]}",
                small,
            ))

    story.append(Paragraph("4. Asset sample", h2))
    if not assets:
        story.append(Paragraph("No assets.", body))
    else:
        rows = [["Type", "Value"]]
        for a in assets[:40]:
            rows.append([(a.asset_type or "")[:20], Paragraph((a.value or "")[:90], small)])
        at = Table(rows, colWidths=[30 * mm, 140 * mm])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(at)

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"{footer}<br/>Generated by {brand} v{settings.VERSION}",
        muted,
    ))
    doc.build(story)
    return buffer.getvalue()
