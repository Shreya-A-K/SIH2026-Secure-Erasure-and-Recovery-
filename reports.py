"""
reports.py — Role 6: PDF certificate + forensic report generation.
"""

import os
import hashlib
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

styles = getSampleStyleSheet()
title_style = ParagraphStyle("TitleBig", parent=styles["Title"], fontSize=18, spaceAfter=12)
h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=10, spaceAfter=6)
body = styles["BodyText"]


def _kv_table(rows):
    t = Table(rows, colWidths=[55 * mm, 110 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return t


def generate_certificate(operation: dict, score: dict) -> str:
    """Generates a sanitization/erase certificate PDF. Returns absolute file path."""
    op_id = operation["operation_id"]
    filename = f"CERT-{op_id}.pdf"
    path = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    elements = []

    elements.append(Paragraph("SANITIZATION / ERASURE CERTIFICATE", title_style))
    elements.append(Paragraph("SIH 2026 — Secure Data Erasure & Digital Forensics Tool", body))
    elements.append(Spacer(1, 10 * mm))

    elements.append(Paragraph("Operation Summary", h2))
    elements.append(
        _kv_table(
            [
                ["Operation ID", op_id],
                ["Type", operation.get("op_type", "")],
                ["Target", operation.get("target", "")],
                ["Performed By", operation.get("performed_by", "")],
                ["Start Time", operation.get("start_time", "")],
                ["End Time", operation.get("end_time", "")],
                ["Status", operation.get("status", "")],
            ]
        )
    )
    elements.append(Spacer(1, 8 * mm))

    elements.append(Paragraph("Assurance Score", h2))
    elements.append(
        _kv_table(
            [
                ["Score", f"{score['score']} / {score['max_score']}"],
                ["Grade", score["grade"]],
                ["Verdict", score["verdict"]],
                ["Sanitization Method", str(score["breakdown"]["sanitization_method_score"])],
                ["Verification", str(score["breakdown"]["verification_passed"])],
                ["Recovery Validation", str(score["breakdown"]["recovery_validation_passed"])],
                ["Audit Chain Intact", str(score["breakdown"]["audit_chain_intact"])],
            ]
        )
    )
    elements.append(Spacer(1, 8 * mm))

    honesty_note = (
        "Note: Assurance scores reflect verifiable evidence collected during this operation. "
        "Recovery validation runs a partial-scope recovery attempt, not an exhaustive forensic "
        "sweep. On flash-based media (SSD/USB with wear-leveling), complete physical erasure of "
        "all cells cannot be guaranteed by software alone; this score represents confidence based "
        "on available evidence, not an absolute guarantee."
    )
    elements.append(Paragraph(honesty_note, ParagraphStyle("note", parent=body, textColor=colors.grey, fontSize=8)))
    elements.append(Spacer(1, 6 * mm))
    elements.append(Paragraph(f"Generated at: {datetime.now(timezone.utc).isoformat()}", body))

    doc.build(elements)
    return os.path.abspath(path)


def generate_forensic_report(operation: dict, score: dict, audit_entries: list) -> str:
    """Generates the detailed forensic report PDF including a slice of the audit trail."""
    op_id = operation["operation_id"]
    filename = f"REPORT-{op_id}.pdf"
    path = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    elements = []

    elements.append(Paragraph("FORENSIC REPORT", title_style))
    elements.append(Paragraph(f"Operation: {op_id}", body))
    elements.append(Spacer(1, 8 * mm))

    elements.append(Paragraph("Chain of Custody / Audit Trail", h2))
    rows = [["Seq", "Event Type", "Timestamp", "Hash (truncated)"]]
    for e in audit_entries:
        rows.append([str(e["sequence"]), e["event_type"], e["timestamp"], e["hash"][:16] + "..."])
    audit_table = Table(rows, colWidths=[15 * mm, 45 * mm, 55 * mm, 50 * mm])
    audit_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    elements.append(audit_table)
    elements.append(Spacer(1, 8 * mm))

    elements.append(Paragraph("Assurance Assessment", h2))
    elements.append(Paragraph(f"Score: {score['score']}/100 — {score['grade']} ({score['verdict']})", body))

    doc.build(elements)
    return os.path.abspath(path)


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
