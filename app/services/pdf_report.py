from __future__ import annotations

from collections import Counter
from html import escape
from io import BytesIO
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#13213A")
BLUE = colors.HexColor("#2457D6")
SOFT = colors.HexColor("#F5F8FC")
BORDER = colors.HexColor("#DDE5F0")
MUTED = colors.HexColor("#6C7A8C")
TEXT = colors.HexColor("#263448")
GREEN = colors.HexColor("#147A5A")
AMBER = colors.HexColor("#D38B16")
RED = colors.HexColor("#BF3348")
WHITE = colors.white
SEV_COLORS = {"Critical": RED, "High": colors.HexColor("#E26A2C"), "Medium": AMBER, "Low": BLUE}
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _clean(value: Any) -> str:
    text = "" if value is None else str(value)
    for old, new in {"–": "-", "—": "-", "•": "-", "…": "...", "✓": "Yes", "✗": "No", "\u00a0": " "}.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "replace").decode("latin-1")


def _safe(value: Any) -> str:
    return escape(_clean(value))


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=NAVY),
        "subtitle": ParagraphStyle("subtitle", parent=base["BodyText"], fontSize=10, leading=14, textColor=MUTED),
        "section": ParagraphStyle("section", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=8, spaceAfter=7),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=8.7, leading=12.5, textColor=TEXT),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=6.8, leading=9, textColor=MUTED),
        "tiny": ParagraphStyle("tiny", parent=base["BodyText"], fontSize=6.4, leading=8.5, textColor=TEXT),
        "head": ParagraphStyle("head", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=WHITE),
        "center": ParagraphStyle("center", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=18, leading=21, textColor=NAVY, alignment=TA_CENTER),
        "center_small": ParagraphStyle("center_small", parent=base["BodyText"], fontSize=6.6, leading=8, textColor=MUTED, alignment=TA_CENTER),
    }


def _p(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_safe(value), style)


def _markup(value: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(value, style)


def _page(canvas, doc) -> None:
    canvas.saveState()
    canvas.setStrokeColor(BORDER)
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9 * mm, "CertShield - Customer PKI Assessment")
    canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _score_band(score: Any) -> tuple[str, colors.Color]:
    value = _num(score)
    if value is None:
        return "Not assessed", MUTED
    if value >= 85:
        return "Strong", GREEN
    if value >= 70:
        return "Managed", BLUE
    if value >= 50:
        return "Elevated risk", AMBER
    return "High risk", RED


def _summary(score: Any, critical: int, high: int) -> str:
    if critical:
        return f"The assessment identified {critical} critical exposure(s). Immediate ownership and remediation planning are recommended."
    if high:
        return f"The assessment identified {high} high-priority exposure(s). A time-bound remediation plan is recommended."
    value = _num(score)
    if value is None:
        return "The available evidence is not sufficient for a complete executive risk rating."
    if value >= 85:
        return "The PKI demonstrates a strong overall control posture. Continue monitoring and periodic validation."
    if value >= 70:
        return "The PKI is generally managed, with a limited number of improvement areas."
    return "The PKI has control and evidence gaps that reduce assurance and require management attention."


def _kpi(label: str, value: Any, caption: str, style: dict[str, ParagraphStyle], accent: colors.Color) -> Table:
    table = Table([[_p(label.upper(), style["center_small"])], [_p(value if value is not None else "-", style["center"])], [_p(caption, style["center_small"])]], colWidths=[75 * mm])
    table.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, BORDER), ("LINEBEFORE", (0, 0), (0, -1), 3, accent), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    return table


def _score_chart(scores: list[float]) -> Drawing:
    drawing = Drawing(245, 170)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 38, 32, 180, 105
    chart.data = [scores]
    chart.categoryAxis.categoryNames = ["Posture", "Health", "Controls"]
    chart.valueAxis.valueMin, chart.valueAxis.valueMax, chart.valueAxis.valueStep = 0, 100, 20
    chart.bars[0].fillColor = BLUE
    chart.bars[0].strokeColor = NAVY
    chart.valueAxis.labels.fontSize = 6
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.dy = -4
    drawing.add(chart)
    drawing.add(String(8, 154, "Assurance scores", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    return drawing


def _severity_chart(counts: Counter[str]) -> Drawing:
    drawing = Drawing(245, 170)
    drawing.add(String(8, 154, "Finding severity", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    labels = [name for name in ("Critical", "High", "Medium", "Low") if counts.get(name)]
    if not labels:
        drawing.add(String(78, 82, "No findings", fontName="Helvetica-Bold", fontSize=12, fillColor=GREEN))
        return drawing
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 54, 26, 105, 105
    pie.data = [counts[name] for name in labels]
    pie.labels = [f"{name}: {counts[name]}" for name in labels]
    pie.sideLabels = True
    pie.slices.strokeColor = WHITE
    for index, name in enumerate(labels):
        pie.slices[index].fillColor = SEV_COLORS[name]
        pie.slices[index].fontSize = 6
    drawing.add(pie)
    return drawing


def _priority_lines(value: Any, limit: int = 8) -> list[str]:
    output: list[str] = []

    def visit(item: Any) -> None:
        if item is None or len(output) >= limit:
            return
        if isinstance(item, dict):
            for key in ("title", "action", "recommendation", "description", "summary", "remediation", "name"):
                if item.get(key):
                    output.append(_clean(item[key]))
                    return
            for nested in item.values():
                visit(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item:
                visit(nested)
        else:
            text = _clean(item).strip()
            if text and text not in output:
                output.append(text)

    visit(value)
    return output[:limit]


def build_customer_pdf(payload: dict[str, Any]) -> bytes:
    buffer = BytesIO()
    st = _styles()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=22 * mm, title="CertShield Customer PKI Assessment", author="CertShield")

    env = payload.get("environment") or {}
    scan = payload.get("scan_metadata") or {}
    executive = payload.get("executive_summary") or {}
    findings = payload.get("findings") or []
    priorities = _priority_lines(payload.get("remediation_priorities"))
    counts: Counter[str] = Counter(_clean(item.get("severity") or "Unknown") for item in findings)
    posture = executive.get("pki_posture_score")
    health = executive.get("pki_health_score")
    controls = executive.get("best_practice_score")
    critical, high = counts.get("Critical", 0), counts.get("High", 0)
    posture_label, posture_color = _score_band(posture)
    story: list[Any] = []

    brand = Table(
        [
            [
                _markup("<b>CERTSHIELD</b>", ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=13, textColor=WHITE)),
                _markup("CUSTOMER PKI ASSESSMENT", ParagraphStyle("brand2", fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#D7E5FF"), alignment=TA_RIGHT)),
            ]
        ],
        colWidths=[90 * mm, 69 * mm],
    )
    brand.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story += [brand, Spacer(1, 14), _p("PKI Security & Assurance Report", st["title"]), _markup(f"Executive and technical assessment for <b>{_safe(env.get('name') or 'Selected PKI Environment')}</b>", st["subtitle"]), Spacer(1, 8)]

    meta = Table(
        [
            [_p("Environment", st["small"]), _p(env.get("name") or "Not specified", st["body"]), _p("Collector", st["small"]), _p((env.get("collector_type") or "ADCS").upper(), st["body"])],
            [_p("Scan", st["small"]), _p(f"#{scan.get('id', '-')} / Sequence {scan.get('scan_sequence', '-')}", st["body"]), _p("Current", st["small"]), _p("Yes" if scan.get("is_current_for_environment") else "No", st["body"])],
        ],
        colWidths=[27 * mm, 53 * mm, 25 * mm, 54 * mm],
    )
    meta.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SOFT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [meta, Spacer(1, 12), _p("Executive Summary", st["section"]), _p(_summary(posture, critical, high), st["body"]), Spacer(1, 8)]

    kpis = Table(
        [
            [_kpi("PKI posture", posture, posture_label, st, posture_color), _kpi("PKI health", health, "Operational health", st, BLUE)],
            [_kpi("Controls", controls, "Best-practice alignment", st, colors.HexColor("#6C55C7")), _kpi("Open findings", len(findings), f"{critical} critical / {high} high", st, RED if critical else AMBER if high else GREEN)],
        ],
        colWidths=[79.5 * mm, 79.5 * mm],
    )
    kpis.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story += [kpis, Spacer(1, 10)]

    scores = [float(_num(posture) or 0), float(_num(health) or 0), float(_num(controls) or 0)]
    charts = Table([[_score_chart(scores), _severity_chart(counts)]], colWidths=[80 * mm, 79 * mm])
    charts.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, BORDER), ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [charts, Spacer(1, 10), _p("What management should know", st["section"])]
    for point in (
        f'The overall PKI posture is rated {posture_label.lower()} with a score of {posture if posture is not None else "not assessed"}.',
        f'The assessment identified {critical} critical, {high} high, {counts.get("Medium", 0)} medium, and {counts.get("Low", 0)} low findings.',
        "The PDF is intended for customer and executive review. JSON remains available as a technical export.",
    ):
        story.append(Paragraph(_safe(point), st["body"], bulletText="-"))

    story += [Spacer(1, 8), _p("Priority Actions", st["section"])]
    if priorities:
        for index, item in enumerate(priorities, 1):
            row = Table([[_p(index, ParagraphStyle(f"n{index}", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE, alignment=TA_CENTER)), _p(item, st["body"])]], colWidths=[12 * mm, 147 * mm])
            row.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), BLUE),
                        ("BACKGROUND", (1, 0), (1, 0), SOFT),
                        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story += [row, Spacer(1, 5)]
    else:
        story.append(_p("No structured remediation priorities were included in this scan. Review the top risks and assign owners.", st["body"]))

    story += [Spacer(1, 6), _p("Top Risks", st["section"])]
    ranked = sorted(findings, key=lambda item: (SEV_RANK.get(_clean(item.get("severity")), 9), -int(_num(item.get("risk_score")) or 0)))[:10]
    rows = [[_p("Priority", st["head"]), _p("Risk", st["head"]), _p("Business meaning", st["head"]), _p("Recommended action", st["head"])]]
    for item in ranked:
        severity = _clean(item.get("severity") or "Unknown")
        rows.append(
            [
                _p(severity, st["tiny"]),
                _markup(f"<b>{_safe(item.get('title') or 'Untitled finding')}</b><br/><font color='#6C7A8C'>{_safe(item.get('affected') or 'PKI-wide')}</font>", st["tiny"]),
                _p(item.get("business_impact") or item.get("technical_impact") or "Business impact requires review.", st["tiny"]),
                _p(item.get("remediation") or "Assign an owner and create a time-bound remediation plan.", st["tiny"]),
            ]
        )
    risk_table = LongTable(rows, colWidths=[20 * mm, 45 * mm, 49 * mm, 45 * mm], repeatRows=1)
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_index in range(1, len(rows)):
        table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), WHITE if row_index % 2 else SOFT))
    risk_table.setStyle(TableStyle(table_style))
    story.append(risk_table)

    story += [Spacer(1, 10), _p("Environment & Scope", st["section"])]
    scope = [
        ["Environment", env.get("name") or "Not specified"],
        ["Environment key", env.get("environment_key") or "Not specified"],
        ["Collector type", (env.get("collector_type") or "adcs").upper()],
        ["Scan ID", scan.get("id") or "-"],
        ["Scan sequence", scan.get("scan_sequence") or "-"],
        ["Previous scan", scan.get("previous_scan_id") or "None"],
        ["CA inventory", ", ".join(_clean(name) for name in payload.get("cas") or []) or "No CA names collected"],
    ]
    scope_table = Table([[_p(label, st["small"]), _p(value, st["body"])] for label, value in scope], colWidths=[38 * mm, 121 * mm])
    scope_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), SOFT),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(scope_table)

    story += [PageBreak(), _p("Detailed Findings Appendix", st["section"]), _p("Technical context for the customer security and PKI teams.", st["body"])]
    for index, item in enumerate(ranked[:20], 1):
        severity = _clean(item.get("severity") or "Unknown")
        detail = Table(
            [
                [_p(f"{index}. {_clean(item.get('title') or 'Untitled finding')}", st["section"]), "", _p(severity, ParagraphStyle(f"s{index}", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE, alignment=TA_CENTER))],
                [_p("Affected", st["small"]), _p(item.get("affected") or "PKI-wide", st["body"]), ""],
                [_p("Business impact", st["small"]), _p(item.get("business_impact") or "Business impact requires review.", st["body"]), ""],
                [_p("Technical impact", st["small"]), _p(item.get("technical_impact") or "Refer to collected evidence.", st["body"]), ""],
                [_p("Recommended action", st["small"]), _p(item.get("remediation") or "Assign an owner and create a time-bound remediation plan.", st["body"]), ""],
            ],
            colWidths=[34 * mm, 91 * mm, 34 * mm],
        )
        detail.setStyle(
            TableStyle(
                [
                    ("SPAN", (0, 0), (1, 0)),
                    ("SPAN", (1, 1), (2, 1)),
                    ("SPAN", (1, 2), (2, 2)),
                    ("SPAN", (1, 3), (2, 3)),
                    ("SPAN", (1, 4), (2, 4)),
                    ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#EAF1FF")),
                    ("BACKGROUND", (2, 0), (2, 0), SEV_COLORS.get(severity, MUTED)),
                    ("BACKGROUND", (0, 1), (0, -1), SOFT),
                    ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                    ("INNERGRID", (0, 1), (-1, -1), 0.3, BORDER),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story += [detail, Spacer(1, 8)]

    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return buffer.getvalue()
