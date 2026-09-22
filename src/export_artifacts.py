#!/usr/bin/env python3
"""Gera XLSX, PPTX e PDF resumidos a partir do contrato normalizado.

Os formatos são complementares ao HTML. O conteúdo é derivado do JSON local;
nenhuma chamada externa é feita por este script.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from insight_engine import prioritize_findings
from local_privacy import protect_output_directory
from report_context import build as build_report_context


def main() -> None:
    parser = argparse.ArgumentParser(description="Exporta artefatos do assessment")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()
    data = json.loads(args.data.read_text(encoding="utf-8"))
    protect_output_directory(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_xlsx(data, args.output_dir / "assessment-action-plan.xlsx")
    write_pptx(data, args.output_dir / "assessment-executive-summary.pptx")
    write_pdf(data, args.output_dir / "assessment-executive-summary.pdf")
    print(f"Artefatos exportados em {args.output_dir}")


def write_xlsx(data: dict, path: Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    book = Workbook()
    context = build_report_context(data)
    cover = book.active
    cover.title = "Resumo e confidencialidade"
    cover.append(["Security & Governance Assessment", "Classificação e contexto da execução"])
    cover.append(["Classificação", context["classification"]])
    cover.append(["Manuseio", "Confidencial · compartilhar somente com pessoas autorizadas"])
    cover.append(["Execução read-only", "Sim" if data.get("metadata", {}).get("execution", {}).get("tenant_mutation") is False else "Não confirmado"])
    cover.append(["Perfil", context["profile"]])
    cover.append(["Run ID", context["run_id"]])
    cover.append(["Versão do engine", context["engine_version"]])
    cover.append(["Início UTC", context["started_at"]])
    cover.append(["Fim UTC", context["finished_at"]])
    cover.append(["Status do contrato", context["contract_status"]])
    cover.append([])
    cover.append(["Escopo observado", "Quantidade"])
    for row in context["scope_rows"]:
        cover.append([row["label"], row["value"]])
    cover.append([])
    cover.append(["Limitações registradas", len(context["limitations"])])
    cover.append(["Aviso", "Contagens de objetos não comprovam impacto de negócio, incidente ou indisponibilidade."])
    cover.append([])
    cover.append(["Módulos com limitação", "Estado · quantidade · interpretação"])
    for item in context["limitations"]:
        cover.append([item["module"], f"{item['status']} · {item['records']} · {item['summary']}"])
    for column in cover.columns:
        cover.column_dimensions[column[0].column_letter].width = 42
    for cell in cover[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="5B2C83")
    cover.freeze_panes = "A2"
    sheet = book.create_sheet("Plano de ação", 1)
    headers = ["ID", "Achado", "Severidade", "Impacto técnico", "Risco", "Alcance observado", "Impacto potencial em usuários", "Prioridade", "Score prioridade", "Confiança por achado", "Fonte da evidência", "Módulo", "Estado da coleta", "Janela de coleta", "Sinal financeiro", "Esforço relativo", "Quadrante", "Frente consultiva", "Responsável", "Status", "Dependências", "30 dias", "60 dias", "90 dias"]
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="5B2C83")
    cost_signal = data.get("discovery", {}).get("lifecycle", {}).get("summary", {}).get("Custo mensal potencial", "Não quantificado")
    findings = prioritize_findings(data.get("findings", []), data.get("metadata", {}).get("evidence_quality", {}), cost_signal)
    for item in findings:
        actions = item.get("action_30_60_90", {})
        severity = item.get("severity", "medium")
        impact = "Muito alto" if severity == "critical" else ("Alto" if severity == "high" else ("Médio" if severity == "medium" else "Baixo"))
        effort = int(item.get("effort", 3) or 3)
        risk = int(item.get("risk_score", 0) or 0)
        quadrant = "Alto impacto / baixo esforço" if risk >= 70 and effort <= 2 else ("Alto impacto / alto esforço" if risk >= 70 else ("Baixo impacto / baixo esforço" if effort <= 2 else "Baixo impacto / alto esforço"))
        workstreams = {"ID": "Identity & Access", "SEC": "Cloud & M365 Security", "GOV": "Cloud Governance", "COST": "FinOps & Cloud Optimization"}
        workstream = workstreams.get(str(item.get("control_id", "")).split("-")[0], "Risk & Compliance")
        dependencies = "; ".join(item.get("remediation_dependencies", []))
        lineage = item.get("evidence_lineage", {})
        window = lineage.get("collection_window", {}) or {}
        collection_window = f"{window.get('started_at') or 'N/D'} → {window.get('finished_at') or 'N/D'}"
        sheet.append([item.get("id"), item.get("title"), severity, impact, risk, f"{item.get('affected', 'N/D')} {item.get('affected_unit', 'itens')}", item.get("user_impact", "Não determinado; validar com o owner."), item.get("priority", "P3"), item.get("priority_score", 0), item.get("evidence_confidence", "baixa"), lineage.get("source", item.get("source", "Não informado")), lineage.get("module", "Não vinculado"), lineage.get("source_status", "Não informado"), collection_window, item.get("financial_signal", "unquantified"), item.get("effort_band", effort), quadrant, workstream, item.get("owner"), item.get("status"), dependencies, actions.get("30"), actions.get("60"), actions.get("90")])
    for insight in data.get("discovery", {}).get("cross_domain_insights", []):
        risk = int(insight.get("risk", 0) or 0)
        owner = insight.get("suggested_owner", "Security & Governance")
        sheet.append([insight.get("id"), insight.get("title"), insight.get("severity", "medium"), "Alto" if risk >= 75 else "Médio", risk, f"{insight.get('affected', 'N/D')} itens", "Não determinado; validar com o owner.", insight.get("priority", "P3"), risk, "média", "Evidências cruzadas", "Múltiplos módulos", "Requer validação", "N/D", "unquantified", insight.get("effort_band", "Médio"), "Alto impacto / validar esforço" if risk >= 75 else "Revisão planejada", owner, owner, "Insight — validação", "Validar evidência, escopo e owner", "Executar somente o plano aprovado", "Reavaliar evidência e registrar evolução"])
    for column in sheet.columns:
        sheet.column_dimensions[column[0].column_letter].width = min(max(len(str(cell.value or "")) for cell in column) + 2, 42)
    sheet.freeze_panes = "A2"
    external = data.get("discovery", {}).get("external_assessments", {}).get("microsoft_zero_trust")
    if external:
        def safe_cell(value: object) -> object:
            """Evita que texto de arquivo importado seja interpretado como fórmula Excel."""
            if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                return "'" + value
            return value

        external_sheet = book.create_sheet("Zero Trust Microsoft")
        external_sheet.append(["Fonte", external.get("source", "Microsoft Zero Trust Assessment")])
        external_sheet.append(["Versão", external.get("source_version", "N/D")])
        external_sheet.append(["Importado como referência; não combinado ao score nativo", "Sim"])
        external_sheet.append([])
        headers = ["ID Microsoft", "Pilar(es)", "Verificação", "Estado Microsoft", "Risco do teste", "Licença mínima", "Controles relacionados"]
        external_sheet.append(headers)
        for cell in external_sheet[5]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="5B2C83")
        for item in external.get("tests", []):
            external_sheet.append([
                safe_cell(item.get("test_id")), safe_cell(", ".join(item.get("pillars", []))), safe_cell(item.get("title")),
                safe_cell(item.get("status")), safe_cell(item.get("risk")), safe_cell(", ".join(item.get("minimum_license", [])) or "Não indicado"),
                safe_cell(", ".join(item.get("mapped_control_ids", [])) or "Sem correspondência direta"),
            ])
        for column in external_sheet.columns:
            external_sheet.column_dimensions[column[0].column_letter].width = min(max(len(str(cell.value or "")) for cell in column) + 2, 64)
        external_sheet.freeze_panes = "A6"
    book.save(path)


def write_pptx(data: dict, path: Path) -> None:
    from pptx import Presentation
    from pptx.util import Inches, Pt

    meta = data.get("metadata", {})
    engagement = meta.get("engagement", {}) or {}
    customer = meta.get("customer_name") or engagement.get("customer_name", "Tenant")
    engagement_name = meta.get("engagement_name") or engagement.get("engagement_name", "Security & Governance Assessment")
    consultant = meta.get("consultant_name") or engagement.get("consultant_name", "Consultor não informado")
    classification = meta.get("classification") or engagement.get("classification", "Confidencial — Security & Governance Assessment")
    findings = prioritize_findings(data.get("findings", []), data.get("metadata", {}).get("evidence_quality", {}), data.get("discovery", {}).get("lifecycle", {}).get("summary", {}).get("Custo mensal potencial", "Não quantificado"))
    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    box = slide.shapes.add_textbox(Inches(0.7), Inches(0.8), Inches(12), Inches(1.2))
    box.text_frame.text = engagement_name
    box.text_frame.paragraphs[0].font.size = Pt(28)
    box.text_frame.paragraphs[0].font.bold = True
    sub = slide.shapes.add_textbox(Inches(0.7), Inches(2.0), Inches(11), Inches(0.8))
    context = build_report_context(data)
    scope_text = " · ".join(f"{row['label']}: {row['value']}" for row in context["scope_rows"][:4])
    sub.text_frame.text = f"{customer} · {consultant} · {classification} · Execução {context['started_at']} · Perfil {context['profile']}\n{scope_text}\nConfidencial · compartilhar somente com pessoas autorizadas"
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    title = slide.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11), Inches(0.6))
    title.text_frame.text = "Riscos prioritários"
    title.text_frame.paragraphs[0].font.size = Pt(24)
    text = slide.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11), Inches(5.2))
    text.text_frame.text = "\n".join(f"• {item.get('title')} — risco {item.get('risk_score')}/100 · {item.get('affected', 'N/D')} {item.get('affected_unit', 'itens')} · esforço {item.get('effort_band', 'não avaliado')} · confiança {item.get('evidence_confidence', 'não avaliada')} · fonte {item.get('evidence_lineage', {}).get('source', item.get('source', 'N/D'))} ({item.get('evidence_lineage', {}).get('source_status', 'estado N/D')})" for item in findings[:5]) or "Nenhum achado disponível"
    insights = data.get("discovery", {}).get("cross_domain_insights", [])
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    title = slide.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11), Inches(0.6))
    title.text_frame.text = "Insights cruzados — Segurança & Governança"
    title.text_frame.paragraphs[0].font.size = Pt(24)
    text = slide.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11), Inches(5.2))
    text.text_frame.text = "\n".join(f"• {item.get('priority', 'P3')} · {item.get('title')} — {item.get('suggested_owner', 'Security & Governance')} · {item.get('effort_band', 'Médio')}" for item in insights[:5]) or "Nenhum insight cruzado disponível"
    context = build_report_context(data)
    slide = presentation.slides.add_slide(presentation.slide_layouts[6])
    title = slide.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11.5), Inches(0.7))
    title.text_frame.text = "Cobertura e limitações da execução"
    title.text_frame.paragraphs[0].font.size = Pt(22)
    status_text = " · ".join(f"{status}: {count}" for status, count in context["status_counts"].items()) or "Sem manifesto de coletores"
    limitation_lines = [f"• {item['module']} — {item['status']}: {item['summary']}" for item in context["limitations"][:10]]
    body = slide.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11.2), Inches(4.8))
    body.text_frame.text = f"Perfil {context['profile']} · contrato {context['contract_status']}\nMódulos: {status_text}\n\n" + ("\n".join(limitation_lines) if limitation_lines else "Nenhuma limitação de módulo registrada.") + "\n\nContagens de alcance não comprovam impacto operacional; validar com os owners."
    body.text_frame.paragraphs[0].font.size = Pt(14)
    external = data.get("discovery", {}).get("external_assessments", {}).get("microsoft_zero_trust")
    if external:
        slide = presentation.slides.add_slide(presentation.slide_layouts[6])
        title = slide.shapes.add_textbox(Inches(0.7), Inches(0.5), Inches(11.5), Inches(0.7))
        title.text_frame.text = "Microsoft Zero Trust Assessment — referência externa"
        title.text_frame.paragraphs[0].font.size = Pt(22)
        summary = external.get("status_counts", {})
        status_line = " · ".join(f"{key}: {value}" for key, value in summary.items())
        pillar_lines = []
        for pillar in external.get("pillars", []):
            pillar_lines.append(f"{pillar.get('name')}: {pillar.get('tests')} verificações · " + ", ".join(f"{key} {value}" for key, value in pillar.get("statuses", {}).items()))
        body = slide.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11.2), Inches(4.8))
        body.text_frame.text = f"Versão {external.get('source_version', 'N/D')} · {external.get('tests_total', 0)} verificações\n{status_line}\n\n" + "\n".join(pillar_lines) + "\n\nScore Microsoft mantido separado; não combinado ao score do Assessment Engine."
        body.text_frame.paragraphs[0].font.size = Pt(14)
    presentation.save(path)


def write_pdf(data: dict, path: Path) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(str(path), pagesize=A4, title="Security & Governance Assessment")
    meta = data.get("metadata", {})
    context = build_report_context(data)
    engagement = meta.get("engagement", {}) or {}
    customer = meta.get("customer_name") or engagement.get("customer_name", "Tenant")
    engagement_name = meta.get("engagement_name") or engagement.get("engagement_name", "Security & Governance Assessment")
    classification = meta.get("classification") or engagement.get("classification", "Confidencial — Security & Governance Assessment")
    findings = sorted(data.get("findings", []), key=lambda item: item.get("risk_score", 0), reverse=True)
    scope_line = " · ".join(f"{row['label']}: {row['value']}" for row in context["scope_rows"])
    story = [Paragraph(str(engagement_name), styles["Title"]), Paragraph(str(customer), styles["Heading2"]), Paragraph(str(classification), styles["BodyText"]), Paragraph("Confidencial · compartilhar somente com pessoas autorizadas", styles["BodyText"]), Paragraph(f"Perfil {context['profile']} · Run ID {context['run_id']} · Início UTC {context['started_at']} · fim UTC {context['finished_at']}", styles["BodyText"]), Paragraph(scope_line, styles["BodyText"]), Spacer(1, 18)]
    story.append(Paragraph("Top riscos", styles["Heading2"]))
    for item in findings[:5]:
        lineage = item.get("evidence_lineage", {})
        story.append(Paragraph(f"{item.get('title')} — risco {item.get('risk_score')}/100 · alcance: {item.get('affected', 'N/D')} {item.get('affected_unit', 'itens')} · esforço: {item.get('effort_band', 'não avaliado')} · confiança: {item.get('evidence_confidence', 'não avaliada')} · fonte: {lineage.get('source', item.get('source', 'N/D'))} ({lineage.get('source_status', 'estado N/D')})", styles["BodyText"]))
        story.append(Spacer(1, 6))
    insights = data.get("discovery", {}).get("cross_domain_insights", [])
    story.append(Paragraph("Insights cruzados", styles["Heading2"]))
    for item in insights[:5]:
        story.append(Paragraph(f"{item.get('priority', 'P3')} — {item.get('title')} — responsável sugerido: {item.get('suggested_owner', 'Security & Governance')}", styles["BodyText"]))
        story.append(Spacer(1, 6))
    if context["limitations"]:
        story.append(Paragraph("Limitações da execução", styles["Heading2"]))
        for item in context["limitations"][:12]:
            story.append(Paragraph(f"{item['module']} — {item['status']}: {item['summary']}", styles["BodyText"]))
    external = data.get("discovery", {}).get("external_assessments", {}).get("microsoft_zero_trust")
    if external:
        story.append(Spacer(1, 14))
        story.append(Paragraph("Microsoft Zero Trust Assessment — referência externa", styles["Heading2"]))
        story.append(Paragraph(f"Versão {external.get('source_version', 'N/D')} · {external.get('tests_total', 0)} verificações · score não combinado ao score do Assessment Engine.", styles["BodyText"]))
        status_line = " · ".join(f"{key}: {value}" for key, value in external.get("status_counts", {}).items())
        story.append(Paragraph(status_line, styles["BodyText"]))
        for pillar in external.get("pillars", []):
            pillar_status = " · ".join(f"{key}: {value}" for key, value in pillar.get("statuses", {}).items())
            story.append(Paragraph(f"{pillar.get('name')}: {pillar.get('tests')} verificações — {pillar_status}", styles["BodyText"]))
    document.build(story)


if __name__ == "__main__":
    main()
