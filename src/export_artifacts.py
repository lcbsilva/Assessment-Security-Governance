#!/usr/bin/env python3
"""Gera XLSX, PPTX e PDF resumidos a partir do contrato normalizado.

Os formatos são complementares ao HTML. O conteúdo é derivado do JSON local;
nenhuma chamada externa é feita por este script.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Exporta artefatos do assessment")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    data = json.loads(args.data.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_xlsx(data, args.output_dir / "assessment-action-plan.xlsx")
    write_pptx(data, args.output_dir / "assessment-executive-summary.pptx")
    write_pdf(data, args.output_dir / "assessment-executive-summary.pdf")
    print(f"Artefatos exportados em {args.output_dir}")


def write_xlsx(data: dict, path: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    book = Workbook()
    sheet = book.active
    sheet.title = "Plano de ação"
    headers = ["ID", "Achado", "Severidade", "Impacto", "Risco", "Esforço", "Quadrante", "Frente consultiva", "Responsável", "Status", "Dependências", "30 dias", "60 dias", "90 dias"]
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="5B2C83")
    for item in data.get("findings", []):
        actions = item.get("action_30_60_90", {})
        severity = item.get("severity", "medium")
        impact = "Muito alto" if severity == "critical" else ("Alto" if severity == "high" else ("Médio" if severity == "medium" else "Baixo"))
        effort = int(item.get("effort", 3) or 3)
        risk = int(item.get("risk_score", 0) or 0)
        quadrant = "Alto impacto / baixo esforço" if risk >= 70 and effort <= 2 else ("Alto impacto / alto esforço" if risk >= 70 else ("Baixo impacto / baixo esforço" if effort <= 2 else "Baixo impacto / alto esforço"))
        workstreams = {"ID": "Identity & Access", "SEC": "Cloud & M365 Security", "GOV": "Cloud Governance", "COST": "FinOps & Cloud Optimization"}
        workstream = workstreams.get(str(item.get("control_id", "")).split("-")[0], "Risk & Compliance")
        dependencies = "; ".join(item.get("remediation_dependencies", []))
        sheet.append([item.get("id"), item.get("title"), severity, impact, risk, effort, quadrant, workstream, item.get("owner"), item.get("status"), dependencies, actions.get("30"), actions.get("60"), actions.get("90")])
    for column in sheet.columns:
        sheet.column_dimensions[column[0].column_letter].width = min(max(len(str(cell.value or "")) for cell in column) + 2, 42)
    sheet.freeze_panes = "A2"
    book.save(path)


def write_pptx(data: dict, path: Path) -> None:
    from pptx import Presentation
    from pptx.util import Inches, Pt

    meta = data.get("metadata", {})
    findings = sorted(data.get("findings", []), key=lambda item: item.get("risk_score", 0), reverse=True)
    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    box = slide.shapes.add_textbox(Inches(0.7), Inches(0.8), Inches(12), Inches(1.2))
    box.text_frame.text = "Security & Governance Assessment"
    box.text_frame.paragraphs[0].font.size = Pt(28)
    box.text_frame.paragraphs[0].font.bold = True
    sub = slide.shapes.add_textbox(Inches(0.7), Inches(2.0), Inches(11), Inches(0.8))
    sub.text_frame.text = f"{meta.get('customer_name', 'Tenant')} · Execução {meta.get('collected_at', 'N/D')}"
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    title = slide.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11), Inches(0.6))
    title.text_frame.text = "Riscos prioritários"
    title.text_frame.paragraphs[0].font.size = Pt(24)
    text = slide.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11), Inches(5.2))
    text.text_frame.text = "\n".join(f"• {item.get('title')} — risco {item.get('risk_score')}/100" for item in findings[:5]) or "Nenhum achado disponível"
    presentation.save(path)


def write_pdf(data: dict, path: Path) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(path), pagesize=A4, title="Security & Governance Assessment")
    meta = data.get("metadata", {})
    findings = sorted(data.get("findings", []), key=lambda item: item.get("risk_score", 0), reverse=True)
    story = [Paragraph("Security & Governance Assessment", styles["Title"]), Paragraph(str(meta.get("customer_name", "Tenant")), styles["Heading2"]), Spacer(1, 18)]
    story.append(Paragraph("Top riscos", styles["Heading2"]))
    for item in findings[:5]:
        story.append(Paragraph(f"{item.get('title')} — risco {item.get('risk_score')}/100", styles["BodyText"]))
        story.append(Spacer(1, 6))
    document.build(story)


if __name__ == "__main__":
    main()
