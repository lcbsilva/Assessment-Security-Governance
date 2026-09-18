#!/usr/bin/env python3
"""Gera um relatório HTML offline a partir de dados normalizados do assessment."""

from __future__ import annotations

import html
import json
import math
import argparse
from datetime import datetime
from pathlib import Path

import yaml
from insight_engine import executive_actions, cross_domain_insights, prioritize_findings


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "controls.yaml"
RUNBOOKS_PATH = ROOT / "catalog" / "runbooks.yaml"
DATA_PATH = ROOT / "mock" / "assessment.json"
OUTPUT_PATH = ROOT / "dist" / "assessment-demo.html"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def pct(value: float) -> str:
    return f"{value:.0f}%"


def score_class(score: float) -> str:
    if score >= 80:
        return "good"
    if score >= 60:
        return "warn"
    return "bad"


def score_label(score: float) -> str:
    if score >= 80:
        return "Postura forte"
    if score >= 60:
        return "Maturidade intermediária"
    return "Atenção prioritária"


def load_data(data_path: Path = DATA_PATH) -> tuple[dict, dict, dict]:
    catalog = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    runbooks = yaml.safe_load(RUNBOOKS_PATH.read_text(encoding="utf-8"))
    data = json.loads(data_path.read_text(encoding="utf-8"))
    return catalog, data, runbooks


def calculate(catalog: dict, data: dict) -> tuple[dict, float, float]:
    definitions = {item["id"]: item for item in catalog["controls"]}
    controls = []
    for result in data["controls"]:
        definition = definitions[result["id"]]
        controls.append({**definition, **result})

    domain_scores = {}
    total_weight = 0.0
    weighted_total = 0.0
    for key, domain in catalog["domains"].items():
        evaluated = [c for c in controls if c["domain"] == key and c["status"] not in {"not_available", "error"}]
        weight = sum(c["weight"] for c in evaluated)
        catalog_weight = sum(c["weight"] for c in controls if c["domain"] == key)
        score = sum(c["score"] * c["weight"] for c in evaluated) / weight if weight else None
        domain_coverage = round(weight / catalog_weight * 100, 1) if catalog_weight else 0
        domain_scores[key] = {**domain, "key": key, "score": score, "evaluated": len(evaluated), "total_controls": sum(1 for c in controls if c["domain"] == key), "coverage": domain_coverage, "coverage_status": "adequate" if domain_coverage >= 80 else "provisional" if domain_coverage > 0 else "insufficient"}
        if score is not None:
            weighted_total += score * domain["weight"]
            total_weight += domain["weight"]

    overall = weighted_total / total_weight if total_weight else 0
    evaluated_controls = sum(1 for item in controls if item["status"] not in {"not_available", "error"})
    coverage = evaluated_controls / len(catalog["controls"]) * 100 if catalog["controls"] else 0
    return domain_scores, overall, coverage


def radar_svg(domain_scores: dict) -> str:
    labels = list(domain_scores.values())
    cx, cy, radius = 180, 150, 105
    points = []
    for index, item in enumerate(labels):
        angle = -math.pi / 2 + (2 * math.pi * index / len(labels))
        value = (item["score"] or 0) / 100
        x = cx + radius * value * math.cos(angle)
        y = cy + radius * value * math.sin(angle)
        points.append(f"{x:.1f},{y:.1f}")
    grid = []
    for level in (0.25, 0.5, 0.75, 1):
        ring = []
        for index in range(len(labels)):
            angle = -math.pi / 2 + (2 * math.pi * index / len(labels))
            ring.append(f"{cx + radius * level * math.cos(angle):.1f},{cy + radius * level * math.sin(angle):.1f}")
        grid.append(f'<polygon points="{" ".join(ring)}" class="radar-grid" />')
    axes = []
    texts = []
    for index, item in enumerate(labels):
        angle = -math.pi / 2 + (2 * math.pi * index / len(labels))
        x2 = cx + radius * math.cos(angle)
        y2 = cy + radius * math.sin(angle)
        tx = cx + (radius + 28) * math.cos(angle)
        ty = cy + (radius + 28) * math.sin(angle) + 4
        axes.append(f'<line x1="{cx}" y1="{cy}" x2="{x2:.1f}" y2="{y2:.1f}" class="radar-axis" />')
        texts.append(f'<text x="{tx:.1f}" y="{ty:.1f}" class="radar-label" text-anchor="middle">{esc(item["name"])}</text>')
    return f'''<svg viewBox="0 0 360 300" role="img" aria-label="Radar de scores por domínio">
      {"".join(grid)}{"".join(axes)}
      <polygon points="{" ".join(points)}" class="radar-value" />
      {"".join(texts)}
    </svg>'''


def render_table(items: list[dict], columns: list[tuple[str, str]]) -> str:
    """Renderiza tabelas de discovery usando somente dados normalizados."""
    if not items:
        return '<div class="empty">Nenhum registro disponível neste módulo.</div>'

    headers = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
    rows = []
    for item in items:
        cells = "".join(f"<td>{esc(item.get(key, '—'))}</td>" for key, _ in columns)
        rows.append(f"<tr>{cells}</tr>")
    return f'<div class="table-scroll"><table data-filterable="true"><thead><tr>{headers}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def render_ca_cards(policies: list[dict]) -> str:
    """Cria uma visão visual por política, inspirada no idPowerApp."""
    if not policies:
        return '<div class="empty">Nenhuma política de Conditional Access disponível.</div>'
    cards = []
    for policy in policies:
        state = str(policy.get("state", "Unknown"))
        state_class = "enabled" if state.lower() == "enabled" else ("report" if "report" in state.lower() else "disabled")
        cards.append(f'''<article class="ca-card">
  <div class="ca-card-top"><span class="ca-state {state_class}">{esc(state)}</span><span class="ca-excluded">Exclusões: {esc(policy.get("excluded", "—"))}</span></div>
  <h4>{esc(policy.get("display_name", "Política sem nome"))}</h4>
  <dl><dt>Usuários</dt><dd>{esc(policy.get("users_scope", "—"))}</dd><dt>Controles</dt><dd>{esc(policy.get("grant_controls", "—"))}</dd><dt>Cobertura</dt><dd>{esc(policy.get("coverage", "—"))}</dd></dl>
</article>''')
    return f'<div class="ca-grid">{"".join(cards)}</div>'


def render_ca_summary(policies: list[dict]) -> str:
    """Resume sinais de cobertura de CA sem inferir conformidade sozinho."""
    enabled = sum(1 for item in policies if str(item.get("state", "")).lower() == "enabled")
    report_only = sum(1 for item in policies if "report" in str(item.get("state", "")).lower())
    disabled = sum(1 for item in policies if str(item.get("state", "")).lower() == "disabled")
    exclusions = 0
    for item in policies:
        value = item.get("excluded", 0)
        try:
            exclusions += int(value)
        except (TypeError, ValueError):
            digits = "".join(character if character.isdigit() else " " for character in str(value))
            exclusions += int(digits.split()[0]) if digits.split() else 0
    mfa_policies = sum("mfa" in str(item.get("grant_controls", "")).lower() for item in policies)
    metrics = [("Ativas", enabled), ("Somente relatório", report_only), ("Desativadas", disabled),
               ("Exclusões identificadas", exclusions), ("Com controle MFA", mfa_policies)]
    return '<div class="mini-grid ca-summary">' + "".join(
        f'<div class="mini"><span>{esc(label)}</span><b>{esc(value)}</b></div>' for label, value in metrics
    ) + '</div>'


def render_domain_card(item: dict) -> str:
    score = item.get("score")
    value = f"{score:.0f}" if score is not None else "N/D"
    css = score_class(score) if score is not None else "unavailable"
    width = f"{score:.0f}" if score is not None else "0"
    coverage = item.get("coverage", 0)
    coverage_label = "Cobertura adequada" if item.get("coverage_status") == "adequate" else "Cobertura provisória" if coverage else "Sem evidência"
    return f'''<div class="domain-card"><div class="domain-name">{esc(item["name"])}</div>
        <div class="domain-score {css}">{value}</div>
        <div class="bar"><span style="width:{width}%"></span></div><div class="domain-coverage">{esc(coverage_label)} · {esc(coverage)}% dos pesos avaliados</div></div>'''


def effort_label(value: object) -> str:
    labels = {1: "Muito baixo", 2: "Baixo", 3: "Médio", 4: "Alto", 5: "Muito alto"}
    try:
        return labels.get(int(value), str(value))
    except (TypeError, ValueError):
        return "Não informado"


def workstream(control: dict) -> str:
    """Mapeia o achado para a frente consultiva que deve receber o plano.

    É uma classificação operacional para facilitar o handoff entre Security,
    Cloud Governance, FinOps e times de Workplace; não é uma promessa de
    produto, licenciamento ou escopo comercial.
    """
    explicit = control.get("workstream")
    if explicit:
        return str(explicit)
    return {
        "identity": "Identity & Access",
        "security": "Cloud & M365 Security",
        "governance": "Cloud Governance",
        "cost": "FinOps & Cloud Optimization",
        "compliance": "Risk & Compliance",
    }.get(control.get("domain"), "Security & Governance")


def render_results_analysis(findings: list[dict], catalog: dict, data: dict) -> str:
    """Cria análises derivadas para transformar achados em decisões executáveis."""
    cost_signal = data.get("discovery", {}).get("lifecycle", {}).get("summary", {}).get("Custo mensal potencial", "Não quantificado")
    findings = prioritize_findings(findings, data.get("metadata", {}).get("evidence_quality", {}), cost_signal)
    definitions = {item["id"]: item for item in catalog.get("controls", [])}
    severity_order = [("critical", "Crítico"), ("high", "Alto"), ("medium", "Médio"), ("low", "Baixo")]
    severity_cards = "".join(
        f'<div class="risk-stat {severity}"><span>{label}</span><b>{sum(1 for item in findings if item.get("severity") == severity)}</b><small>achado(s)</small></div>'
        for severity, label in severity_order
    )
    domain_stats = {}
    for item in findings:
        control = definitions.get(item.get("control_id"), {})
        domain = control.get("domain", "unknown")
        domain_name = catalog.get("domains", {}).get(domain, {}).get("name", domain)
        stat = domain_stats.setdefault(domain_name, {"findings": 0, "risk": 0, "affected": 0})
        stat["findings"] += 1
        stat["risk"] = max(stat["risk"], int(item.get("risk_score", 0)))
        try:
            stat["affected"] += int(item.get("affected", 0))
        except (TypeError, ValueError):
            pass
    domain_rows = [
        {"domain": domain, "findings": values["findings"], "max_risk": values["risk"], "affected": values["affected"]}
        for domain, values in sorted(domain_stats.items(), key=lambda entry: entry[1]["risk"], reverse=True)
    ]
    action_rows = []
    day_labels = {"30": "0–30 dias", "60": "31–60 dias", "90": "61–90 dias"}
    lifecycle_summary = data.get("discovery", {}).get("lifecycle", {}).get("summary", {})
    cost_signal = lifecycle_summary.get("Custo mensal potencial", "Não quantificado")
    for item in findings:
        risk = int(item.get("risk_score", 0) or 0)
        effort = int(item.get("effort", 3) or 3)
        control_prefix = item.get("control_id", "").split("-")[0]
        focus_bonus = 8 if control_prefix in {"SEC", "GOV"} else (5 if control_prefix == "ID" else 0)
        priority_score = int(item.get("priority_score", 0) or 0)
        priority = item.get("priority", "P3")
        cost_impact = cost_signal if item.get("control_id") == "COST-001" else "Não quantificado"
        impact = "Muito alto" if item.get("severity") == "critical" else ("Alto" if item.get("severity") == "high" else ("Médio" if item.get("severity") == "medium" else "Baixo"))
        financial = "Quantificado" if cost_signal != "Não quantificado" and item.get("control_id", "").startswith("COST-") else ("Potencial" if item.get("control_id", "").startswith(("GOV-", "SEC-")) else "Não quantificado")
        quadrant = "Alto impacto / baixo esforço" if risk >= 70 and effort <= 2 else ("Alto impacto / alto esforço" if risk >= 70 else ("Baixo impacto / baixo esforço" if effort <= 2 else "Baixo impacto / alto esforço"))
        for day, action in item.get("action_30_60_90", {}).items():
            action_rows.append({
                "horizon": day_labels.get(str(day), f"{day} dias"),
                "finding": item.get("title", "—"),
                "action": action,
                "owner": item.get("owner", "A definir"),
                "effort": effort_label(item.get("effort")),
                "priority": f"{priority} ({priority_score})",
                "cost_impact": cost_impact,
                "severity": item.get("severity", "—"),
                "impact": impact,
                "financial": financial,
                "priority_score": priority_score,
                "quadrant": quadrant,
                "workstream": workstream(control),
                "focus": "Primário" if control_prefix in {"SEC", "GOV"} else ("Relacionado" if control_prefix == "ID" else "Complementar"),
                "status": item.get("status", "Open"),
            })
    action_rows.sort(key=lambda row: (row["horizon"], row["finding"]))
    evidence_rows = []
    for item in data.get("discovery", {}).get("collection_log", []):
        evidence_rows.append({
            "module": item.get("module", "—"),
            "source": item.get("source", "—"),
            "records": item.get("records", "—"),
            "status": item.get("status", "—"),
            "note": item.get("note", "—"),
            "limitation_category": item.get("limitation_category", "—"),
        })
    quality = data.get("metadata", {}).get("evidence_quality", {})
    quality_note = quality.get("interpretation", "Qualidade calculada a partir do manifesto de evidências.")
    return f'''<section class="section" id="analysis">
  <h2>Análise de resultados</h2>
  <p class="section-intro">Os achados foram convertidos em volume de risco, impacto observado e ações executáveis. A quantidade afetada é uma indicação de exposição, não uma contagem automática de incidentes.</p>
  <div class="risk-stats">{severity_cards}</div>
  <div class="analysis-grid">
    <div class="panel"><h3>Concentração de risco por domínio</h3>{render_table(domain_rows, [("domain", "Domínio"), ("findings", "Achados"), ("max_risk", "Maior risco"), ("affected", "Itens afetados")])}</div>
    <div class="panel"><h3>Critério de priorização</h3><ul><li><b>Risco:</b> combinação de impacto, exposição e criticidade do controle.</li><li><b>Esforço:</b> estimativa relativa para planejamento inicial.</li><li><b>Confiança:</b> qualidade e completude da evidência coletada; atualmente aplicada de forma uniforme a todos os achados.</li><li><b>Financeiro:</b> só recebe peso quando há sinal quantificado.</li><li><b>Validação:</b> o proprietário do serviço deve confirmar contexto e exceções.</li></ul></div>
  </div>
  <div class="panel"><h3>Matriz de priorização</h3><p class="section-intro">Segurança e Governança são o foco primário da oferta. Prioridade combina risco observado, impacto executivo, esforço relativo e sinal financeiro. “Potencial” exige validação em Cost Management; não é economia garantida.</p>{render_table(action_rows, [("horizon", "Horizonte"), ("priority", "Prioridade"), ("focus", "Foco"), ("quadrant", "Quadrante"), ("impact", "Impacto"), ("financial", "Impacto financeiro"), ("workstream", "Frente consultiva"), ("finding", "Origem"), ("action", "Ação"), ("effort", "Esforço"), ("cost_impact", "Custo potencial"), ("status", "Status")])}</div>
  <div class="panel"><h3>Manifesto de evidências</h3><p class="section-intro"><b>Qualidade da evidência: {esc(quality.get("score", "N/D"))}/100.</b> {esc(quality_note)}</p>{render_table(evidence_rows, [("module", "Módulo"), ("source", "Fonte"), ("records", "Registros"), ("status", "Status"), ("limitation_category", "Classificação"), ("note", "Observação")])}</div>
</section>'''


def render_decision_layer(data: dict) -> str:
    intersections = data.get("discovery", {}).get("risk_intersections", [])
    actions = executive_actions(data.get("findings", []))
    evidence = data.get("metadata", {}).get("evidence_by_control", [])
    return f'''<section class="section" id="decision-layer">
  <h2>Camada de decisão</h2>
  <p class="section-intro">Correlação de sinais para orientar o workshop. Uma correlação indica prioridade de investigação; não representa automaticamente um incidente.</p>
  <div class="analysis-grid"><div class="panel"><h3>Interseções críticas</h3>{render_table(intersections, [("severity", "Severidade"), ("title", "Interseção"), ("risk", "Risco"), ("affected", "Afetados"), ("evidence", "Evidência"), ("action", "Próxima ação")])}</div>
  <div class="panel"><h3>Primeiras decisões executivas</h3>{render_table(actions, [("priority", "Prioridade"), ("finding", "Achado"), ("risk", "Risco"), ("owner", "Owner"), ("outcome", "Resultado esperado")])}</div></div>
  <div class="panel"><h3>Cobertura da evidência por controle</h3>{render_table(evidence, [("control_id", "Controle"), ("control", "Nome"), ("domain", "Domínio"), ("module", "Módulo"), ("status", "Status"), ("records", "Registros"), ("confidence", "Confiança"), ("limitation", "Limitação")])}</div>
</section>'''


def render_executive_security_kpis(data: dict) -> str:
    """Mostra os sinais prioritários na primeira tela, preservando o detalhe abaixo."""
    discovery = data.get("discovery", {})
    users = discovery.get("users", [])
    user_summary = discovery.get("user_summary", {})
    value = lambda label, fallback: user_summary.get(label, fallback)
    mfa_gap = sum(1 for item in users if item.get("mfa_status") == "Not registered")
    privileged_gap = sum(1 for item in users if item.get("privileged") and item.get("mfa_status") == "Not registered")
    public_resources = sum(1 for item in discovery.get("resources", []) if str(item.get("exposure", "")).lower().startswith("public"))
    policy_gap = sum(int(item.get("non_compliant", 0) or 0) for item in discovery.get("policy_compliance", []))
    high_rbac = sum(1 for item in discovery.get("rbac", []) if item.get("access_risk") in {"Crítico", "Alto"})
    device_summary = discovery.get("device_summary", {})
    endpoint_gap = int(device_summary.get("non_compliant", 0) or 0) + int(device_summary.get("unmanaged", 0) or 0)
    metrics = [("Sem MFA", value("Usuários sem MFA", mfa_gap), "Identidade"), ("Privilegiados sem MFA", value("Privilegiados sem MFA", privileged_gap), "Crítico"), ("Convidados externos", value("Convidados externos", 0), "Governança"), ("RBAC alto risco", high_rbac, "Acesso"), ("Recursos públicos", public_resources, "Exposição"), ("Não conformidades", policy_gap, "Azure Policy"), ("Endpoints em atenção", endpoint_gap, "Endpoint")]
    cards = "".join(f'<div class="exec-kpi"><span>{esc(label)}</span><b>{esc(amount)}</b><small>{esc(context)}</small></div>' for label, amount, context in metrics)
    return f'<section class="section exec-kpi-section"><div class="section-heading"><div><div class="eyebrow">Sinais prioritários</div><h2>Onde concentrar a atenção</h2></div><span class="section-intro">Indicadores derivados das evidências desta execução</span></div><div class="exec-kpis">{cards}</div></section>'


def render_lifecycle(data: dict) -> str:
    """Renderiza FinOps e ciclo de vida sem executar ações destrutivas."""
    lifecycle = data.get("discovery", {}).get("lifecycle", {})
    summary = lifecycle.get("summary", {})
    metrics = "".join(
        f'<div class="mini"><span>{esc(label)}</span><b>{esc(value)}</b></div>'
        for label, value in summary.items()
    )
    orphan_rows = lifecycle.get("orphan_resources", [])
    retirement_rows = lifecycle.get("service_retirements", [])
    advisor_rows = lifecycle.get("advisor_recommendations", [])
    age_rows = lifecycle.get("resource_age", [])
    cost_rows = data.get("discovery", {}).get("cost_summary", [])
    finops = data.get("discovery", {}).get("finops_summary", {})
    benefits = data.get("discovery", {}).get("benefits", [])
    return f'''<section class="section" id="lifecycle">
  <h2>FinOps e ciclo de vida</h2>
  <p class="section-intro">Identificação de desperdícios potenciais, recursos antigos e serviços em aposentadoria. O assessment somente recomenda e documenta ações; não exclui nem altera recursos.</p>
  <div class="mini-grid">{metrics}</div>
  <div class="panel"><h3>Recursos órfãos e custo potencial</h3>{render_table(orphan_rows, [
      ("name", "Recurso"), ("type", "Tipo"), ("subscription", "Subscription"),
      ("resource_group", "Resource group"), ("reason", "Motivo"), ("monthly_cost", "Custo/mês"),
      ("last_activity", "Última atividade"), ("owner", "Owner"), ("recommended_action", "Ação recomendada")])}</div>
  <div class="panel"><h3>Recomendações oficiais do Azure Advisor</h3><p class="section-intro">Recomendações ativas retornadas pelo Azure Advisor. O assessment apenas organiza evidências e não aplica as ações.</p>{render_table(advisor_rows, [
      ("category", "Categoria"), ("impact", "Impacto"), ("description", "Recomendação"),
      ("subscription", "Subscription"), ("resource_group", "Resource group"), ("resource_id", "Recurso afetado"),
      ("annual_savings", "Economia anual"), ("currency", "Moeda"), ("last_updated", "Atualizada em"), ("status", "Status")])}</div>
  <div class="panel"><h3>Custos por recurso — Cost Management</h3><p class="section-intro">Consulta agregada do período configurado, agrupada por recurso quando a API e a permissão permitem. Valores não representam economia garantida.</p>{render_table(cost_rows, [("ResourceId", "Resource ID"), ("ResourceGroupName", "Resource group"), ("PreTaxCost", "Custo"), ("Currency", "Moeda")])}</div>
  <div class="panel"><h3>FinOps avançado: distribuição e anomalias</h3><p class="section-intro">Consolida custo por resource group e tipo de recurso, além de uma heurística conservadora de picos diários. Não é alerta oficial nem promessa de economia.</p>{render_table([finops] if finops else [], [("cost_total_period", "Custo no período"), ("currency", "Moeda"), ("resource_groups", "Resource groups"), ("resource_types", "Tipos de recurso"), ("reservations", "Reservas"), ("savings_plans", "Savings Plans")])}{render_table(finops.get("cost_by_resource_group", []), [("resource_group", "Resource group"), ("cost", "Custo")])}{render_table(finops.get("cost_by_resource_type", []), [("resource_type", "Tipo de recurso"), ("cost", "Custo")])}{render_table((finops.get("anomalies") or {}).get("anomaly_days", []), [("date", "Data"), ("cost", "Custo"), ("baseline", "Mediana"), ("signal", "Sinal")])}</div>
  <div class="panel"><h3>Reservas e Savings Plans — inventário</h3><p class="section-intro">Metadados expostos pelo Resource Graph. Quantidade zero significa que nenhum recurso foi retornado neste escopo, não que não exista benefício em outro contrato ou billing account.</p>{render_table(benefits, [("name", "Nome"), ("benefit_kind", "Tipo"), ("type", "Resource type"), ("subscription", "Subscription"), ("resource_group", "Resource group"), ("region", "Região")])}</div>
  <div class="panel"><h3>Serviços e features em aposentadoria</h3>{render_table(retirement_rows, [
      ("service", "Serviço"), ("feature", "Feature"), ("retirement_date", "Data de aposentadoria"),
      ("days_remaining", "Dias restantes"), ("impacted_resources", "Recursos impactados"),
      ("action", "Ação"), ("owner", "Owner"), ("status", "Status")])}</div>
  <div class="panel"><h3>Idade dos recursos</h3>{render_table(age_rows, [("age_band", "Faixa de idade"), ("resources", "Recursos"), ("percentage", "% do inventário")])}</div>
  <div class="notice"><b>Runbook seguro:</b> primeiro confirmar dependência, owner, criticidade, backup e janela de mudança. Somente depois registrar aprovação para anexar, mover, atualizar ou descomissionar.</div>
</section>'''


def render_runbooks(runbooks: dict) -> str:
    """Exibe procedimentos associados aos achados sem execução automática."""
    items = []
    for item in runbooks.get("runbooks", []):
        items.append({
            "id": item.get("id", "—"),
            "name": item.get("name", "—"),
            "trigger": item.get("trigger", "—"),
            "evidence": item.get("evidence", "—"),
            "validation": item.get("validation", "—"),
            "actions": ", ".join(item.get("actions", [])),
            "guardrail": item.get("guardrail", "—"),
        })
    return f'''<section class="section" id="runbooks">
  <h2>Runbooks de correção</h2>
  <p class="section-intro">Procedimentos versionados para orientar validação e remediação. Eles não são executados pelo assessment read-only.</p>
  {render_table(items, [("id", "ID"), ("name", "Runbook"), ("trigger", "Quando usar"), ("evidence", "Evidência"), ("validation", "Validação obrigatória"), ("actions", "Opções"), ("guardrail", "Barreira")])}
</section>'''


def render_comparison(data: dict) -> str:
    comparison = data.get("comparison") or {}
    if not comparison:
        return ""
    score = comparison.get("overall_score", {})
    coverage = comparison.get("coverage", {})
    rows = [{"metric": "Score geral", "previous": score.get("previous", "N/D"), "current": score.get("current", "N/D"), "delta": "—" if score.get("previous") is None or score.get("current") is None else round(score["current"] - score["previous"], 2)}, {"metric": "Cobertura", "previous": coverage.get("previous", "N/D"), "current": coverage.get("current", "N/D"), "delta": coverage.get("delta", "—")}, {"metric": "Score no conjunto comparável", "previous": "—", "current": comparison.get("comparability", {}).get("average_delta_on_overlap", "N/D"), "delta": "variação média"}]
    comparability = comparison.get("comparability", {})
    notice = "A cobertura mudou; use a variação média no conjunto comparável para interpretar tendência." if comparability.get("coverage_changed") else "A cobertura permaneceu estável; a variação média usa controles avaliados nas duas execuções."
    return f'''<section class="section panel" id="trend"><h2>Evolução entre execuções</h2><p class="section-intro">Comparação histórica de métricas agregadas. Mudanças de permissão, escopo ou licença podem alterar a cobertura sem representar evolução real.</p>{render_table(rows, [("metric", "Métrica"), ("previous", "Anterior"), ("current", "Atual"), ("delta", "Variação")])}<div class="notice"><b>Comparabilidade:</b> {esc(comparability.get("comparable_controls", 0))} controles avaliados nas duas execuções. {esc(notice)}</div><p><b>Achados novos:</b> {esc(len(comparison.get("findings_new", [])))} · <b>Achados resolvidos:</b> {esc(len(comparison.get("findings_resolved", [])))}</p></section>'''


def render_scope_coverage(data: dict) -> str:
    """Mostra o mapa 360 do produto sem confundir roadmap com evidência coletada."""
    logs = data.get("discovery", {}).get("collection_log", [])
    modules = data.get("metadata", {}).get("modules", {})

    def status(tokens: tuple[str, ...], module_key: str | None = None) -> tuple[str, str]:
        if module_key and module_key in modules:
            value = str(modules[module_key])
            return value, "Módulo executado; ver manifesto de evidências."
        match = next((item for item in logs if any(token.lower() in str(item.get("module", "")).lower() for token in tokens)), None)
        if match:
            return str(match.get("status", "not_available")), str(match.get("note", "Evidência registrada no manifesto."))
        return "roadmap", "Integração planejada; não é evidência desta execução."

    areas = [
        ("Azure / Portal", "Governança, inventário, hierarquia, RBAC, Policy, Advisor e exposição.", ("Azure inventory", "Azure hierarchy", "RBAC", "Policy"), "governance"),
        ("Entra ID / Identidade", "Usuários, MFA, CA, sign-ins, PIM, grupos e aplicações.", ("Identity", "MFA", "Conditional", "PIM"), "identity"),
        ("Microsoft 365 / Segurança", "Secure Score, Defender, dispositivos e postura de endpoint.", ("Secure", "Defender", "Entra devices"), "security"),
        ("Microsoft Intune", "Dispositivos gerenciados, conformidade e postura de endpoint.", ("Intune",), None),
        ("Licenças M365", "SKUs, unidades habilitadas/consumidas e sinais de licenciamento.", ("M365 licenses",), None),
        ("FinOps Azure", "Custos, Advisor, recursos órfãos, reservas e oportunidades de otimização.", ("Cost Management", "Advisor", "Orphan"), "cost"),
        ("Power Platform", "Ambientes, Power Apps, Power Automate, conectores e owners.", ("Power Platform",), "power_platform"),
        ("Copilot Studio / Agents", "Inventário e governança de agentes quando publicado no inventário Power Platform.", ("Power Platform",), None),
        ("Azure DevOps", "Projetos, repositórios, pipelines e políticas de branch.", ("Azure DevOps",), "azure_devops"),
        ("Purview / Compliance", "Contas Purview e sinais de governança de dados; DLP, retenção e auditoria dependem de APIs/licenças adicionais.", ("Purview", "Compliance"), "analytics"),
        ("Power BI", "Workspaces, datasets, gateways, compartilhamento e refresh.", ("Power BI",), None),
        ("Fabric / Synapse / Databricks", "Analytics, workspaces, lakehouse e governança de dados via metadados read-only.", ("Fabric", "Synapse", "Databricks"), "analytics"),
    ]
    labels = {"success": "Coletado", "partial": "Parcial", "not_available": "Indisponível", "error": "Erro controlado", "not_run": "Não executado", "roadmap": "Próxima integração"}
    cards = []
    for name, description, tokens, key in areas:
        value, note = status(tokens, key)
        cards.append(f'<article class="scope-card scope-{esc(value)}"><div class="scope-top"><b>{esc(name)}</b><span class="status {esc(value)}">{esc(labels.get(value, value.replace("_", " ").title()))}</span></div><p>{esc(description)}</p><small>{esc(note)}</small></article>')
    return f'''<section class="section" id="coverage"><div class="section-heading"><div><div class="eyebrow">Visão 360 do ecossistema</div><h2>O que este assessment contempla</h2></div><span class="section-intro">Cada card diferencia evidência coletada de integração futura.</span></div><div class="scope-grid">{"".join(cards)}</div></section>'''


def render_inventory_overview(data: dict) -> str:
    """Resumo visual estilo inventário: volume, postura e pontos de atenção."""
    discovery = data.get("discovery", {})
    resources = discovery.get("resources", [])
    users = discovery.get("users", [])
    policies = discovery.get("policy_compliance", [])
    rbac = discovery.get("rbac", [])
    registrations = discovery.get("app_registrations", [])
    lifecycle = discovery.get("lifecycle", {})
    counts = {
        "Recursos Azure": len(resources),
        "Usuários avaliados": len(users),
        "Não conformidades Policy": sum(1 for row in policies if str(row.get("compliance_state", "")).lower() != "compliant"),
        "Recursos públicos": sum(1 for row in resources if str(row.get("exposure", "")).lower().startswith("public")),
        "RBAC alto risco": sum(1 for row in rbac if row.get("access_risk") in {"Crítico", "Alto"}),
        "Credenciais expiradas": sum(int(row.get("expired_credentials", 0) or 0) for row in registrations),
        "Recomendações Advisor": len(lifecycle.get("advisor_recommendations", [])),
        "Recursos órfãos": len(lifecycle.get("orphan_resources", [])),
    }
    maximum = max(counts.values()) or 1
    cards = "".join(f'<article class="inventory-card"><span>{esc(label)}</span><b>{esc(value)}</b><div class="inventory-bar"><i style="width:{max(4, round(value / maximum * 100))}%"></i></div></article>' for label, value in counts.items())
    return f'''<section class="section" id="inventory-overview"><div class="section-heading"><div><div class="eyebrow">Discovery em números</div><h2>Visão geral do ambiente</h2></div><span class="section-intro">Indicadores derivados exclusivamente da evidência coletada.</span></div><div class="inventory-grid">{cards}</div></section>'''


def render_preflight(data: dict) -> str:
    """Readiness Gate: mostra por que a execução iniciou e onde há limitação."""
    gate = data.get("metadata", {}).get("preflight") or {}
    checks = gate.get("checks", [])
    if not checks:
        return ""
    labels = {"pass": "Pronto", "warning": "Atenção", "blocked": "Bloqueado", "not_checked": "Não validado"}
    icons = {"pass": "✓", "warning": "!", "blocked": "×", "not_checked": "?"}
    rows = "".join(
        f'<article class="readiness-card readiness-{esc(item.get("status", "not_checked"))}"><div class="readiness-top"><span class="readiness-icon">{icons.get(item.get("status"), "?")}</span><b>{esc(item.get("label", item.get("name", "Check")))}</b><span class="status {esc(item.get("status", "not_checked"))}">{esc(labels.get(item.get("status"), item.get("status", "Não validado")))}</span></div><p>{esc(item.get("detail", "—"))}</p><small><b>Impacto:</b> {esc(item.get("impact", "—"))}</small><small><b>Próximo passo:</b> {esc(item.get("remediation", "—"))}</small></article>'
        for item in checks
    )
    summary = gate.get("summary", {})
    duration = gate.get("estimated_duration", {})
    module_rows = "".join(f'<tr><td>{esc(item.get("module", "—"))}</td><td>{esc(item.get("domain", "—"))}</td><td>{esc(item.get("expected_read_scope", "—"))}</td><td><span class="status {esc(item.get("status", "not_checked"))}">{esc(item.get("status", "not_checked").replace("_", " ").title())}</span></td></tr>' for item in gate.get("module_readiness", []))
    decision = gate.get("execution_decision", "run_full")
    decision_label = {"run_full": "Execução full liberada", "run_full_with_limitations": "Execução full liberada com limitações", "blocked": "Execução bloqueada"}.get(decision, decision)
    return f'''<section class="section readiness-section" id="readiness"><div class="section-heading"><div><div class="eyebrow">Readiness Gate</div><h2>Pré-requisitos da execução</h2></div><span class="section-intro">Validações feitas antes da coleta; nenhum check concede permissão ou altera o tenant.</span></div><div class="readiness-banner"><b>{esc(decision_label)}</b><span>{esc(summary.get("pass", 0))} prontos · {esc(summary.get("warning", 0))} alertas · {esc(summary.get("blocked", 0))} bloqueios</span><span>Estimativa: {esc(duration.get("low_minutes", "N/D"))}–{esc(duration.get("high_minutes", "N/D"))} min</span></div><div class="readiness-grid">{rows}</div><details class="readiness-manifest"><summary>Manifesto de escopos por módulo</summary><div class="table-scroll"><table><thead><tr><th>Módulo</th><th>Domínio</th><th>Escopo esperado</th><th>Estado</th></tr></thead><tbody>{module_rows}</tbody></table></div></details></section>'''


def render_execution_health(data: dict) -> str:
    health = data.get("metadata", {}).get("execution_health") or {}
    if not health:
        return ""
    counts = health.get("status_counts", {})
    limitations = health.get("limitations", [])
    coverage_rows = data.get("metadata", {}).get("coverage_map", [])
    rows = "".join(f'<tr><td>{esc(item.get("module"))}</td><td><span class="status {esc(item.get("status"))}">{esc(item.get("status", "—").replace("_", " ").title())}</span></td><td>{esc(item.get("records", 0))}</td><td>{esc(item.get("category", "—"))}</td></tr>' for item in limitations)
    coverage_table = render_table(coverage_rows, [("module", "Módulo"), ("domain", "Domínio"), ("expected_read_scope", "Escopo esperado"), ("status", "Estado"), ("records", "Registros"), ("evidence_confidence", "Confiança"), ("limitation", "Como destravar / observação")]) if coverage_rows else '<p class="empty">Manifesto de cobertura não disponível nesta execução.</p>'
    return f'''<section class="section execution-health" id="execution-health"><div class="section-heading"><div><div class="eyebrow">Integridade da coleta</div><h2>Saúde da execução</h2></div><span class="section-intro">A cobertura é medida pelo status da fonte, não pelo volume de registros.</span></div><div class="health-banner"><b>{esc(health.get("health", "—").title())}</b><span>{esc(health.get("completed_modules", 0))}/{esc(health.get("total_modules", 0))} módulos concluídos</span><span>{esc(health.get("coverage_percent", 0))}% de cobertura operacional</span><span>Sucesso: {esc(counts.get("success", 0))} · Parciais: {esc(counts.get("partial", 0))} · Indisponíveis: {esc(counts.get("not_available", 0))} · Erros: {esc(counts.get("error", 0))}</span></div><div class="notice"><b>Regra de integridade:</b> {esc(health.get("interpretation", "—"))}</div>{('<div class="table-scroll"><table><thead><tr><th>Módulo</th><th>Status</th><th>Registros</th><th>Classificação</th></tr></thead><tbody>' + rows + '</tbody></table></div>') if rows else '<p class="empty">Todos os módulos executados terminaram com sucesso.</p>'}<details class="coverage-details"><summary>Mapa completo de cobertura, escopos e limitações</summary>{coverage_table}</details></section>'''


def render_discovery(data: dict) -> str:
    """Renderiza a camada técnica detalhada; listas são opcionais para fail gracefully."""
    discovery = data.get("discovery", {})
    users = discovery.get("users", [])
    policies = discovery.get("conditional_access", [])
    legacy_signins = discovery.get("legacy_auth_signins", [])
    secure_score_controls = discovery.get("secure_score_controls", [])
    secure_score_summary = discovery.get("secure_score_summary", {})
    devices = discovery.get("devices", [])
    enterprise_applications = discovery.get("enterprise_applications", [])
    app_registrations = discovery.get("app_registrations", [])
    pim_assignments = discovery.get("pim_assignments", [])
    defender_summary = discovery.get("defender_summary", {})
    defender_alerts = discovery.get("defender_alerts", [])
    defender_vulnerabilities = discovery.get("defender_vulnerabilities", [])
    power_platform = discovery.get("power_platform", [])
    power_platform_summary = discovery.get("power_platform_summary", {})
    azure_devops = discovery.get("azure_devops", {})
    azure_devops_summary = discovery.get("azure_devops_summary", {})
    resources = discovery.get("resources", [])
    rbac = discovery.get("rbac", [])
    policy_compliance = discovery.get("policy_compliance", [])
    policy_summary = discovery.get("policy_summary", [])
    collection_log = discovery.get("collection_log", [])
    module_status = data.get("metadata", {}).get("modules", {})
    module_names = {
        "identity": "Identidade / Graph",
        "security": "Segurança / Defender",
        "governance": "Governança / ARG",
        "cost": "Custo / Cost Management",
        "compliance": "Compliance / Policy Insights",
        "power_platform": "Power Platform / ARG",
        "analytics": "Dados / Analytics",
    }
    module_rows = "".join(
        f'<tr><td>{esc(module_names.get(key, key))}</td><td><span class="status {esc(value)}">{esc(value.replace("_", " ").title())}</span></td></tr>'
        for key, value in module_status.items()
    )
    users_summary = discovery.get("user_summary", {})
    user_metrics = "".join(
        f'<div class="mini"><span>{esc(label)}</span><b>{esc(value)}</b></div>'
        for label, value in users_summary.items()
    )
    return f'''<section class="section" id="discovery">
  <h2>Discovery técnico</h2>
  <p class="section-intro">Visão detalhada dos objetos encontrados durante a coleta. Nesta demonstração os registros são sintéticos; em uma execução real, cada linha preserva a evidência retornada pelos coletores e seus limites.</p>
  <div class="explorer-toolbar"><label for="discoverySearch">Pesquisar nos resultados detalhados</label><input id="discoverySearch" aria-label="Pesquisar nos resultados detalhados" type="search" placeholder="Nome, UPN, recurso, política, owner..." autocomplete="off"><span id="discoveryCount">Todos os registros</span><button id="clearDiscovery" type="button">Limpar</button><button id="exportDiscovery" type="button">Exportar CSV</button></div>
  <div class="mini-grid">{user_metrics}</div>
  <div class="panel"><h3>Identidades avaliadas</h3>{render_table(users, [
      ("display_name", "Nome"), ("user_principal_name", "UPN"), ("account_type", "Tipo"),
      ("mfa_status", "MFA"), ("privileged_roles", "Funções privilegiadas"), ("ca_coverage", "Conditional Access"), ("risk", "Risco Entra"), ("posture_level", "Postura"), ("posture_signal", "Sinais"),
      ("last_sign_in", "Último sign-in")])}</div>
  <div class="panel"><h3>Funções privilegiadas do Entra ID</h3>{render_table(discovery.get("directory_roles", []), [("role", "Função"), ("role_id", "ID técnico")])}</div>
  <div class="panel"><h3>PIM: elegível versus ativo</h3><p class="section-intro">A coleta diferencia atribuições elegíveis de ativações/atribuições ativas, resolve o principal quando possível e classifica o nível do escopo. O relatório não altera funções nem ativa acessos.</p>{render_table(pim_assignments, [("principal_name", "Principal"), ("principal_id", "ID do principal"), ("role", "Função"), ("role_id", "ID da função"), ("assignment_type", "Tipo"), ("member_type", "Membro"), ("scope_kind", "Nível"), ("scope", "Escopo"), ("start", "Início"), ("end", "Fim")])}</div>
  <div class="panel"><h3>Políticas de Conditional Access</h3>{render_table(policies, [
      ("display_name", "Política"), ("state", "Estado"), ("users_scope", "Usuários"),
      ("included", "Incluídos"), ("excluded", "Exclusões"), ("grant_controls", "Controles"), ("coverage", "Cobertura"), ("risk_signal", "Sinal")])}</div>
  <div class="panel"><h3>Visão visual das políticas</h3><p class="section-intro">Cada política é apresentada como uma unidade de revisão para facilitar a leitura com segurança, IAM e proprietários de aplicações.</p>{render_ca_summary(policies)}{render_ca_cards(policies)}</div>
  <div class="panel"><h3>Sign-ins com autenticação legada</h3><p class="section-intro">Registros limitados à janela configurada. Use-os para identificar usuário e aplicação antes de bloquear protocolos antigos.</p>{render_table(legacy_signins, [("user_display_name", "Usuário"), ("user_principal_name", "UPN"), ("client_app", "Cliente"), ("application", "Aplicação"), ("created_at", "Data"), ("result", "Resultado")])}</div>
  <div class="panel"><h3>Microsoft Secure Score</h3>{render_table([secure_score_summary] if secure_score_summary else [], [("current", "Atual"), ("maximum", "Máximo"), ("percentage", "Percentual"), ("recommendations", "Recomendações"), ("high_impact_recommendations", "Baixo/médio esforço")])}</div>
  <div class="panel"><h3>Recomendações do Microsoft Secure Score</h3>{render_table(secure_score_controls, [("id", "Controle"), ("title", "Recomendação"), ("category", "Categoria"), ("max_score", "Score máximo"), ("implementation_cost", "Custo de implementação"), ("remediation", "Remediação")])}</div>
  <div class="panel"><h3>Postura de dispositivos e endpoints</h3><p class="section-intro">Inventário combinado de Entra ID e Intune quando disponível. Dispositivo não encontrado ou com estado desconhecido não é tratado automaticamente como conforme.</p>{render_table(devices, [("name", "Dispositivo"), ("operating_system", "Sistema"), ("os_version", "Versão"), ("trust_type", "Confiança"), ("compliant", "Conformidade"), ("managed", "Gerenciamento"), ("last_sign_in", "Última atividade"), ("user", "Usuário"), ("source", "Fonte")])}</div>
  <div class="panel"><h3>Enterprise Applications</h3>{render_table(enterprise_applications, [("name", "Aplicação"), ("app_id", "App ID"), ("enabled", "Ativa"), ("type", "Tipo"), ("assignment_required", "Exige atribuição"), ("audience", "Audiência"), ("created_at", "Criada em")])}</div>
  <div class="panel"><h3>Grupos do Entra ID / Microsoft 365</h3>{render_table(discovery.get("groups", []), [("name", "Grupo"), ("group_type", "Tipo"), ("security_enabled", "Segurança"), ("mail_enabled", "Mail"), ("visibility", "Visibilidade"), ("dynamic", "Dinâmico"), ("created_at", "Criado em")])}</div>
  <div class="panel"><h3>Licenças Microsoft 365 — visão agregada</h3><p class="section-intro">Exibe consumo e unidades habilitadas por SKU; não coleta dados individuais de atribuição.</p>{render_table([discovery.get("license_summary", {})] if discovery.get("license_summary") else [], [("sku_count", "SKUs"), ("consumed_total", "Consumidas"), ("enabled_total", "Habilitadas"), ("suspended_total", "Suspensas"), ("product_families", "Famílias")])}{render_table(discovery.get("license_summary", {}).get("skus", []), [("sku", "SKU"), ("product_family", "Família"), ("consumed", "Consumidas"), ("enabled", "Habilitadas"), ("unused_enabled", "Não utilizadas"), ("utilization_percent", "Utilização %"), ("signal", "Sinal")])}</div>
  <div class="panel"><h3>Postura de domínios M365</h3><p class="section-intro">Verificação read-only de sinais DNS SPF, DMARC e DKIM. Não acessa mensagens, caixas, destinatários ou conteúdo; falha de DNS aparece como limitação.</p>{render_table([discovery.get("m365_summary", {})] if discovery.get("m365_summary") else [], [("domains", "Domínios"), ("spf_present", "SPF"), ("dmarc_present", "DMARC"), ("dkim_selector1_present", "DKIM selector1"), ("dkim_selector2_present", "DKIM selector2")])}{render_table(discovery.get("m365_domain_posture", []), [("domain", "Domínio"), ("status", "Estado"), ("spf", "SPF"), ("dmarc", "DMARC"), ("dkim_selector1", "DKIM selector1"), ("dkim_selector2", "DKIM selector2"), ("signals", "Sinais")])}</div>
  <div class="panel"><h3>Mapa de cobertura M365</h3><p class="section-intro">Integrações específicas aparecem explicitamente como não configuradas; o engine não transforma ausência de endpoint em conformidade.</p>{render_table(discovery.get("m365_capability_manifest", []), [("module", "Capacidade"), ("status", "Estado"), ("required_integration", "Integração/escopo"), ("note", "Limitação")])}</div>
  <div class="panel"><h3>Auditoria de diretório e sinais de compliance</h3><p class="section-intro">Eventos administrativos agregados do Microsoft Graph. A camada técnica não exibe atores, IPs ou detalhes sensíveis; a IA recebe apenas contagens e categorias.</p>{render_table([discovery.get("directory_audit_summary", {})] if discovery.get("directory_audit_summary") else [], [("events", "Eventos"), ("high_risk_operation_signals", "Sinais de operações sensíveis"), ("categories", "Categorias"), ("pii_excluded", "PII excluída")])}</div>
  <div class="panel"><h3>App Registrations e credenciais</h3><p class="section-intro">Somente metadados, contagens e datas de expiração são exibidos; segredos, certificados e valores sensíveis não são coletados para a camada de IA.</p>{render_table(app_registrations, [("name", "Aplicação"), ("app_id", "App ID"), ("audience", "Audiência"), ("required_permissions", "Recursos requeridos"), ("credentials", "Credenciais"), ("password_credentials", "Secrets"), ("certificate_credentials", "Certificados"), ("expired_credentials", "Expiradas"), ("expiring_30d", "Vencem em 30d"), ("credential_risk", "Risco"), ("credential_expirations", "Expirações"), ("created_at", "Criada em")])}</div>
  <div class="panel"><h3>Consentimentos OAuth e permissões delegadas</h3><p class="section-intro">Visão read-only dos consentimentos registrados. Valores de alto impacto são destacados para revisão; nenhum consentimento é alterado.</p>{render_table(discovery.get("oauth2_permission_grants", []), [("client", "Aplicação cliente"), ("resource", "API recurso"), ("consent_type", "Tipo de consentimento"), ("principal_id", "Principal"), ("scope_count", "Qtd. escopos"), ("high_impact_scopes", "Escopos de alto impacto"), ("scopes", "Escopos")])}</div>
  <div class="panel"><h3>Defender — resumo operacional</h3><p class="section-intro">O módulo é opcional e só apresenta contagens agregadas de alertas. Sem licença ou permissão, o estado aparece no manifesto como não disponível.</p>{render_table([defender_summary] if defender_summary else [], [("alerts", "Alertas"), ("high", "Alta severidade"), ("medium", "Média severidade"), ("active", "Ativos")])}</div>
  <div class="panel"><h3>Defender — alertas e vulnerabilidades</h3>{render_table(defender_alerts, [("severity", "Severidade"), ("status", "Status"), ("source", "Origem"), ("created_at", "Criado em")])}{render_table(defender_vulnerabilities, [("name", "Vulnerabilidade"), ("severity", "Severidade"), ("status", "Status"), ("created_at", "Criada em"), ("updated_at", "Atualizada em")])}</div>
  <div class="panel"><h3>Power Platform — Apps, Automate, Copilot e agentes</h3><p class="section-intro">Inventário read-only de metadados disponíveis no Azure Resource Graph. Não são coletados fórmulas, conteúdo de fluxos, mensagens, dados de negócio, prompts ou segredos de conexões.</p>{render_table([power_platform_summary] if power_platform_summary else [], [("resources", "Recursos"), ("power_apps", "Power Apps"), ("power_automate", "Power Automate"), ("copilot_studio_agents", "Copilot/agentes"), ("environments", "Ambientes"), ("without_owner", "Sem owner"), ("premium_connectors", "Conectores premium"), ("credit_consumption", "Créditos")])}{render_table(power_platform, [("name", "Nome"), ("product", "Produto"), ("kind", "Tipo"), ("environment", "Ambiente"), ("owner", "Owner"), ("state", "Estado"), ("connector_count", "Conectores"), ("premium_connectors", "Premium"), ("governance_signal", "Governança"), ("posture_signals", "Sinais"), ("modified_at", "Modificado em")])}</div>
  <div class="panel"><h3>Azure DevOps — governança de engenharia</h3><p class="section-intro">Integração opcional read-only por organização. Mostra projetos, repositórios, visibilidade, pipelines e evidência de políticas de branch; não lê código, commits, work items, logs ou segredos.</p>{render_table([azure_devops_summary] if azure_devops_summary else [], [("projects", "Projetos"), ("repositories", "Repositórios"), ("pipelines", "Pipelines"), ("public_repositories", "Repositórios públicos"), ("repositories_without_branch_policy_evidence", "Sem política demonstrada")])}{render_table(azure_devops.get("repositories", []), [("name", "Repositório"), ("project", "Projeto"), ("default_branch", "Branch padrão"), ("visibility", "Visibilidade"), ("governance_signal", "Governança"), ("posture_signals", "Sinais")])}{render_table(azure_devops.get("pipelines", []), [("name", "Pipeline"), ("project", "Projeto"), ("type", "Tipo"), ("queue_status", "Fila")])}</div>
  <div class="panel"><h3>Purview, Power BI, Fabric, Synapse e Databricks</h3><p class="section-intro">Inventário de metadados e existência. Não são coletados modelos semânticos, relatórios, datasets, notebooks, consultas, documentos, usuários, permissões detalhadas ou dados de negócio.</p>{render_table([discovery.get("analytics_summary", {})] if discovery.get("analytics_summary") else [], [("azure_resources", "Recursos Azure"), ("purview", "Purview"), ("synapse", "Synapse"), ("databricks", "Databricks"), ("fabric_azure", "Fabric Azure"), ("powerbi_fabric_workspaces", "Workspaces Power BI/Fabric")])}{render_table(discovery.get("analytics_resources", []), [("name", "Recurso"), ("category", "Categoria"), ("type", "Tipo"), ("subscription", "Subscription"), ("resource_group", "Resource group"), ("region", "Região"), ("state", "Estado"), ("sku", "SKU")])}{render_table(discovery.get("powerbi_workspaces", []), [("name", "Workspace"), ("type", "Tipo"), ("category", "Categoria"), ("state", "Estado"), ("is_on_dedicated_capacity", "Capacidade dedicada")])}</div>
  <div class="panel"><h3>Insights cruzados — segurança × governança</h3><p class="section-intro">Correlações indicativas entre fontes diferentes para priorizar revisão consultiva. Um insight não é declaração de incidente e não executa remediação.</p>{render_table(discovery.get("cross_domain_insights") or cross_domain_insights(discovery), [("severity", "Severidade"), ("domain", "Domínio"), ("title", "Insight"), ("risk", "Risco"), ("affected", "Afetados"), ("evidence", "Evidência"), ("action", "Ação recomendada")])}</div>
  <div class="panel"><h3>Inventário de recursos Azure</h3>{render_table(resources, [
      ("name", "Recurso"), ("type", "Tipo"), ("subscription", "Subscription"),
      ("resource_group", "Resource group"), ("region", "Região"), ("exposure", "Exposição"), ("exposure_reason", "Evidência de exposição"),
      ("security_signal", "Sinal de segurança"), ("governance_signal", "Sinal de governança"),
      ("posture_signals", "Sinais"), ("owner", "Owner"), ("tags", "Tags"), ("created_at", "Criado em"), ("age_days", "Idade (dias)")])}</div>
  <div class="panel"><h3>Hierarquia Azure</h3>{render_table(discovery.get("containers", []), [("name", "Nome"), ("type", "Tipo"), ("subscription", "Subscription"), ("tenant", "Tenant")])}</div>
  <div class="panel"><h3>Atribuições RBAC</h3>{render_table(rbac, [
      ("principal_name", "Principal"), ("principal", "ID do principal"), ("principal_account_type", "Tipo de conta"), ("principal_mfa", "MFA"), ("principal_type", "Tipo"), ("role", "Função"),
      ("scope", "Escopo"), ("scope_kind", "Nível"), ("inheritance", "Herança"),
      ("assignment_type", "Tipo de atribuição"), ("pim", "PIM"), ("access_risk", "Risco"), ("review", "Revisão"), ("review_reason", "Motivo")])}</div>
  <div class="panel"><h3>Resumo de compliance por Policy</h3>{render_table(policy_summary, [("policy", "Policy"), ("assignment", "Assignment"), ("subscription", "Subscription"), ("evaluated", "Avaliados"), ("compliant", "Conformes"), ("non_compliant", "Não conformes"), ("exemptions", "Isenções"), ("compliance_rate", "Taxa %"), ("risk_signal", "Risco")])}</div>
  <div class="panel"><h3>Compliance Azure Policy — evidência por recurso</h3>{render_table(policy_compliance, [
      ("policy", "Policy"), ("assignment", "Assignment"), ("compliance_state", "Estado"),
      ("non_compliant", "Não conformes"), ("exemptions", "Isenções"), ("last_evaluated", "Avaliado em")])}</div>
  <div class="panel"><h3>Execução e cobertura dos coletores</h3>
    <div class="table-scroll"><table data-filterable="true"><thead><tr><th>Módulo</th><th>Status</th></tr></thead><tbody>{module_rows}</tbody></table></div>
    {render_table(collection_log, [("module", "Módulo"), ("source", "Fonte"), ("status", "Status"), ("records", "Registros"), ("note", "Observação")])}
  </div>
</section>'''


def render(catalog: dict, data: dict, runbooks: dict) -> str:
    meta = {
        "customer_name": "Tenant não identificado",
        "collected_at": "Não informado",
        "run_id": "não informado",
        "engine_version": "0.1.8",
        **data.get("metadata", {}),
    }
    data.setdefault("findings", [])
    data.setdefault("controls", [])
    domain_scores, overall, coverage = calculate(catalog, data)
    findings = sorted(data["findings"], key=lambda item: item.get("risk_score", 0), reverse=True)
    quick_wins = [item for item in findings if item.get("quick_win")]
    definitions = {item["id"]: item for item in catalog.get("controls", [])}
    status_labels = {"pass": "Conforme", "partial": "Parcial", "fail": "Não conforme", "not_available": "Não disponível"}
    domain_cards = "".join(render_domain_card(item) for item in domain_scores.values())
    finding_cards = "".join(
        # O control_id é usado apenas para classificação e rastreabilidade.
        # Nenhum dado adicional do tenant é enviado para essa camada.
        f'''<article class="finding">
          <div class="finding-top"><span class="severity {esc(item["severity"])}">{esc(item["severity"].upper())}</span>
          <span class="risk">Risco {item["risk_score"]}/100</span></div>
          <h3>{esc(item["title"])}</h3><div class="finding-meta"><span>Frente: {esc(workstream(definitions.get(item.get("control_id"), {})))}</span><span>Responsável: {esc(item.get("owner", "A definir"))}</span><span>Afetados: {esc(item.get("affected", "N/D"))}</span><span>Esforço: {esc(effort_label(item.get("effort")))}</span></div><p>{esc(item["summary"])}</p>
          <details><summary>Ver evidências e recomendação</summary>
            <h4>Evidências</h4><ul>{"".join(f"<li>{esc(ev)}</li>" for ev in item["evidence"])}</ul>
            <h4>Rastreabilidade e decisão</h4><p><b>Fonte:</b> {esc(item.get("evidence_lineage", {}).get("source", item.get("source", "—")))}</p><p><b>Por que esta prioridade:</b> {esc(item.get("priority_rationale", "Risco, esforço e impacto devem ser validados."))}</p><p><b>Dependências:</b> {esc("; ".join(item.get("remediation_dependencies", [])) or "Validar com o owner")}</p>
            <h4>Recomendação</h4><p>{esc(item["recommendation"])}</p>
            <h4>Plano 30/60/90</h4><ul>{"".join(f"<li><b>{day} dias:</b> {esc(action)}</li>" for day, action in item["action_30_60_90"].items())}</ul>
            <h4>Limitações</h4><ul>{"".join(f"<li>{esc(lim)}</li>" for lim in item["limitations"])}</ul>
          </details>
        </article>'''
        for item in findings
    )
    quick_win_list = "".join(f"<li><b>{esc(item['title'])}</b> — esforço baixo, risco {item['risk_score']}/100.</li>" for item in quick_wins)
    control_rows = "".join(
        f'''<tr><td>{esc(item["id"])}</td><td>{esc(item["title"])}</td><td>{esc(item["domain"])}</td><td>{esc(workstream(item))}</td>
        <td><span class="status {esc(item["status"])}">{status_labels.get(item["status"], item["status"])}</span></td><td>{esc(item.get("evidence_state", "LEGACY_FIXTURE"))}</td>
        <td>{"N/D" if item["status"] in {"not_available", "error"} else f'{item["score"]}/100'}</td><td>{esc(item["confidence"])}</td></tr>'''
        for result in data["controls"]
        for item in [{**next(d for d in catalog["controls"] if d["id"] == result["id"]), **result}]
    )
    discovery_html = render_discovery(data)
    analysis_html = render_results_analysis(findings, catalog, data)
    lifecycle_html = render_lifecycle(data)
    runbooks_html = render_runbooks(runbooks)
    comparison_html = render_comparison(data)
    preflight_html = render_preflight(data)
    execution_health_html = render_execution_health(data)
    readiness_nav = '<a href="#readiness">Readiness</a>' if preflight_html else ''
    decision_html = render_decision_layer(data)
    executed_modules = sum(1 for value in meta.get("modules", {}).values() if value in {"success", "partial"})
    total_modules = len(meta.get("modules", {}))
    evaluated_control_count = sum(1 for item in data["controls"] if item.get("status") not in {"not_available", "error"})
    score_text = score_label(overall)
    score_methodology = meta.get("score_methodology", {"name": "Score ponderado por controles disponíveis", "coverage_rule": "Controles not_available/error são excluídos do denominador do score, mas reduzem a cobertura exibida."})
    evidence_quality = meta.get("evidence_quality", {})
    executive_security_kpis = render_executive_security_kpis(data)
    top_findings = "".join(
        f'''<div class="insight-row"><span class="insight-rank">0{index}</span><div><b>{esc(item["title"])}</b><span>{esc(item["summary"])}</span></div><strong>{item["risk_score"]}</strong></div>'''
        for index, item in enumerate(findings[:3], start=1)
    )
    strengths = [
        item for item in domain_scores.values()
        if item["score"] is not None and item["score"] >= 80
    ]
    strengths_text = ", ".join(item["name"] for item in strengths) or "Nenhum domínio atingiu 80 pontos nesta execução"
    coverage_notice = "" if coverage >= 80 else f'<div class="notice"><b>Limitação de cobertura:</b> {coverage:.0f}% dos controles possuem evidência nesta execução. O score não deve ser comparado diretamente com outro tenant ou usado como conclusão definitiva até ampliar as permissões e módulos.</div>'
    return f'''<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security & Governance Assessment — {esc(meta["customer_name"])}</title>
<style>
:root{{--ink:#24212a;--muted:#746d80;--purple:#5b2a86;--deep:#251332;--magenta:#e5007d;--pink:#ff5ca8;--bg:#f5f2f7;--card:#fff;--line:#e5dfea;--green:#16845b;--orange:#bb6c00;--red:#b32638;--shadow:0 10px 30px #2b163b12}}
*{{box-sizing:border-box;scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px Inter,Segoe UI,Arial,sans-serif;line-height:1.5}}
.wrap{{max-width:1240px;margin:auto;padding:28px}}header{{background:radial-gradient(circle at 85% 0%,#8946a6 0,#5b2a86 30%,#251332 78%);color:#fff;position:relative;overflow:hidden}}
header:after{{content:"";position:absolute;width:380px;height:380px;border:1px solid #ffffff2a;border-radius:50%;right:-120px;top:-230px;box-shadow:0 0 0 28px #ffffff0e,0 0 0 58px #ffffff08}}.hero{{position:relative;z-index:1;padding:34px 28px 38px}}.brand{{font-weight:800;letter-spacing:.4px;font-size:16px;display:flex;align-items:center;gap:10px}}.brand-mark{{width:28px;height:28px;display:inline-grid;place-items:center;border-radius:9px;background:linear-gradient(135deg,var(--magenta),var(--pink));font-size:11px;font-weight:900}}.brand-name{{font-weight:800;letter-spacing:-.4px}}.brand-name em{{font-style:normal;color:#ff9aca}}.hero-label{{margin-top:46px;text-transform:uppercase;letter-spacing:1.6px;font-size:11px;color:#f4dff0}}header h1{{margin:7px 0 6px;font-size:38px;line-height:1.12;max-width:720px}}header p{{margin:0;color:#e9dff0;font-size:15px}}
.hero-meta{{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}}.hero-meta span{{border:1px solid #ffffff33;background:#ffffff12;border-radius:99px;padding:6px 11px;font-size:12px;color:#f5edf8}}
.section{{margin:30px 0}}h2{{font-size:22px;letter-spacing:-.3px;margin:0 0 14px}}h3{{margin:8px 0;font-size:17px}}h4{{margin-bottom:4px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.card,.finding,.domain-card,.panel{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 3px 12px #2b163b0b}}
.card{{position:relative;overflow:hidden}}.card:before{{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:linear-gradient(var(--purple),var(--magenta))}}.metric-label{{color:var(--muted);font-size:12px}}.metric{{font-size:34px;font-weight:800;color:var(--purple);letter-spacing:-1px}}.metric small{{font-size:14px;color:var(--muted);letter-spacing:0}}.metric-note{{display:block;color:var(--muted);font-size:11px;margin-top:2px}}
.dashboard{{display:grid;grid-template-columns:1fr 1.2fr;gap:16px}}.domains{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}.domain-name{{font-weight:700}}.domain-score{{font-size:28px;font-weight:700;margin:5px 0}}.good{{color:var(--green)}}.warn{{color:var(--orange)}}.bad{{color:var(--red)}}.bar{{height:7px;background:#eee8f1;border-radius:8px;overflow:hidden}}.bar span{{display:block;height:100%;background:linear-gradient(90deg,var(--purple),var(--magenta));border-radius:8px}}
.domain-score.unavailable{{color:#a49cab;font-size:22px}}.domain-card:has(.unavailable){{background:#faf9fb}}
.radar svg{{width:100%;height:285px}}.radar-grid{{fill:none;stroke:#ded5e5;stroke-width:1}}.radar-axis{{stroke:#e5dfea;stroke-width:1}}.radar-value{{fill:#5b2a8644;stroke:var(--magenta);stroke-width:2}}.radar-label{{fill:var(--muted);font-size:10px}}
.finding-list{{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}}.finding{{border-top:4px solid var(--red)}}.finding-top{{display:flex;justify-content:space-between;align-items:center}}.severity,.status{{border-radius:99px;padding:4px 9px;font-size:11px;font-weight:700}}.severity.critical,.severity.high{{background:#fde3e7;color:var(--red)}}.severity.medium{{background:#fff0d6;color:var(--orange)}}.severity.low{{background:#e4f5ed;color:var(--green)}}.risk{{font-size:12px;color:var(--muted)}}details{{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}}summary{{cursor:pointer;color:var(--purple);font-weight:700}}
.finding-meta{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0;color:var(--muted);font-size:11px}}.finding-meta span{{background:#f7f4f8;border-radius:6px;padding:4px 7px}}
.status.pass,.status.success{{background:#e4f5ed;color:var(--green)}}.status.partial{{background:#fff0d6;color:var(--orange)}}.status.fail,.status.error{{background:#fde3e7;color:var(--red)}}.status.not_run,.status.not_available{{background:#eeeaf1;color:var(--muted)}}table{{border-collapse:collapse;width:100%;background:#fff;border-radius:12px;overflow:hidden}}th,td{{padding:11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{background:#f0ebf4;color:var(--purple);font-size:12px}}.table-scroll{{overflow-x:auto}}.table-scroll table{{min-width:720px}}.section-intro{{color:var(--muted);margin-top:-6px}}.mini-grid{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0}}.mini{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:11px}}.mini span{{display:block;color:var(--muted);font-size:11px}}.mini b{{font-size:20px;color:var(--purple)}}.empty{{color:var(--muted);padding:14px;background:#faf9fb;border-radius:8px}}ul{{padding-left:20px}}.notice{{background:#fff8e8;border-left:4px solid #e1a228;padding:14px;border-radius:8px}}footer{{margin-top:30px;padding:20px 0;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}}
.explorer-toolbar{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#fff;border:1px solid var(--line);border-radius:12px;padding:12px;margin:14px 0}}.explorer-toolbar label{{font-weight:700;color:var(--purple);font-size:12px}}.explorer-toolbar input{{flex:1;min-width:240px;border:1px solid #cfc4d8;border-radius:8px;padding:9px 11px;font:inherit}}.explorer-toolbar input:focus{{outline:2px solid #e5007d55;border-color:var(--magenta)}}.explorer-toolbar span{{color:var(--muted);font-size:12px}}.explorer-toolbar button{{border:1px solid #cfc4d8;background:#fff;color:var(--purple);border-radius:8px;padding:8px 11px;font-weight:700;cursor:pointer}}.explorer-toolbar button:hover{{border-color:var(--magenta);color:var(--magenta)}}
 .ca-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}}.ca-card{{border:1px solid var(--line);border-radius:12px;padding:15px;background:linear-gradient(145deg,#fff,#faf7fc)}}.ca-card-top{{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px}}.ca-state{{border-radius:99px;padding:4px 9px;font-size:11px;font-weight:800}}.ca-state.enabled{{background:#e4f5ed;color:var(--green)}}.ca-state.report{{background:#fff0d6;color:var(--orange)}}.ca-state.disabled{{background:#eeeaf1;color:var(--muted)}}.ca-excluded{{color:var(--muted);font-size:11px}}.ca-card h4{{margin:4px 0 12px;color:var(--deep);font-size:15px}}.ca-card dl{{display:grid;grid-template-columns:82px 1fr;gap:5px;margin:0;font-size:12px}}.ca-card dt{{color:var(--muted)}}.ca-card dd{{margin:0;font-weight:600;overflow-wrap:anywhere}}
 .summary-grid{{display:grid;grid-template-columns:1.15fr .85fr;gap:16px}}.executive{{background:linear-gradient(135deg,#fff,#f7f0fa);border:1px solid #ded0e8;border-radius:16px;padding:22px;box-shadow:0 10px 30px #2b163b12}}.executive h2{{color:var(--deep)}}.executive p{{font-size:16px;max-width:720px;margin:4px 0 18px}}.eyebrow{{color:var(--magenta);font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1.3px}}.score-panel{{background:var(--deep);color:#fff;border-radius:16px;padding:22px;display:flex;gap:18px;align-items:center;box-shadow:0 10px 30px #2b163b20}}.score-ring{{width:132px;height:132px;border-radius:50%;background:conic-gradient(var(--pink) 0 {overall:.0f}%,#ffffff18 0);display:grid;place-items:center;flex:none;position:relative}}.score-ring:after{{content:"";position:absolute;inset:11px;border-radius:50%;background:var(--deep)}}.score-ring b,.score-ring span{{position:relative;z-index:1;text-align:center;display:block}}.score-ring b{{font-size:38px;line-height:1}}.score-ring span{{font-size:11px;color:#dccfe4}}.score-copy h3{{font-size:20px;margin:0 0 6px}}.score-copy p{{color:#dfd2e7;font-size:13px;margin:0}}.insights{{background:#fff;border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 10px 30px #2b163b12}}.insights h3{{margin-top:0}}.insight-row{{display:grid;grid-template-columns:32px 1fr 34px;gap:10px;align-items:center;padding:12px 0;border-bottom:1px solid var(--line)}}.insight-row:last-child{{border-bottom:0}}.insight-rank{{color:var(--magenta);font-weight:800}}.insight-row b,.insight-row span{{display:block}}.insight-row span{{font-size:12px;color:var(--muted);margin-top:2px}}.insight-row strong{{color:var(--red);font-size:20px;text-align:right}}.nav{{display:flex;gap:8px;flex-wrap:wrap;margin:24px 0 0}}.nav a{{color:var(--purple);text-decoration:none;border:1px solid var(--line);background:#fff;border-radius:99px;padding:7px 12px;font-size:12px;font-weight:700}}.nav a:hover{{border-color:var(--magenta);color:var(--magenta)}}.panel{{box-shadow:0 10px 30px #2b163b12}}
.risk-stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}}.risk-stat{{background:#fff;border:1px solid var(--line);border-left:4px solid #aaa;border-radius:10px;padding:14px}}.risk-stat span,.risk-stat small{{display:block;color:var(--muted);font-size:11px}}.risk-stat b{{display:block;font-size:28px;line-height:1.1;margin:4px 0}}.risk-stat.critical,.risk-stat.high{{border-left-color:var(--red)}}.risk-stat.critical b,.risk-stat.high b{{color:var(--red)}}.risk-stat.medium{{border-left-color:var(--orange)}}.risk-stat.medium b{{color:var(--orange)}}.risk-stat.low{{border-left-color:var(--green)}}.risk-stat.low b{{color:var(--green)}}.analysis-grid{{display:grid;grid-template-columns:1.15fr .85fr;gap:16px;margin-bottom:16px}}
.value-strip{{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;align-items:center;gap:14px;background:linear-gradient(110deg,#251332,#5b2a86);color:#fff;border-radius:16px;padding:18px 22px;box-shadow:0 10px 30px #2b163b20}}.value-strip div{{display:flex;flex-direction:column;gap:2px}}.value-strip b{{font-size:16px;color:#fff}}.value-strip span{{font-size:12px;color:#e5d9eb}}.value-strip i{{font-style:normal;color:#ff8fc5;font-size:22px}}
.exec-kpi-section{{margin-top:24px}}.section-heading{{display:flex;justify-content:space-between;align-items:end;gap:16px;margin-bottom:12px}}.section-heading h2{{margin:2px 0 0}}.exec-kpis{{display:grid;grid-template-columns:repeat(7,1fr);gap:9px}}.exec-kpi{{background:#fff;border:1px solid var(--line);border-radius:11px;padding:12px;border-top:3px solid var(--magenta)}}.exec-kpi span,.exec-kpi small{{display:block;color:var(--muted);font-size:10px;line-height:1.25}}.exec-kpi b{{display:block;color:var(--purple);font-size:25px;line-height:1.2;margin:5px 0}}
@media(max-width:800px){{.grid,.domains,.finding-list,.dashboard,.mini-grid,.summary-grid,.analysis-grid,.risk-stats,.ca-grid,.exec-kpis,.scope-grid,.inventory-grid{{grid-template-columns:1fr}}.section-heading{{display:block}}.value-strip{{grid-template-columns:1fr;padding:16px}}.value-strip i{{transform:rotate(90deg);justify-self:center}}.wrap{{padding:16px}}header h1{{font-size:28px}}.score-panel{{align-items:flex-start;flex-direction:column}}table{{font-size:12px}}}}
</style><style>
/* SoftwareOne-inspired presentation layer: dark graphite, white space and cyan/magenta accents. */
:root{{--ink:#171717;--muted:#667085;--purple:#006f9f;--deep:#111827;--magenta:#e6007e;--pink:#ff4fa3;--bg:#f6f7f9;--card:#fff;--line:#e4e7ec;--green:#087443;--orange:#b54708;--red:#b42318;--shadow:0 8px 24px #10182812}}
body{{background:var(--bg);font-family:Inter,Segoe UI,Arial,sans-serif}}
header{{background:radial-gradient(circle at 82% -10%,#0089bd 0,#173b55 24%,#111827 55%,#07090c 100%)}}
header:after{{border-color:#ffffff22;box-shadow:0 0 0 28px #00aeea12,0 0 0 58px #e6007e10}}
.brand-mark{{background:linear-gradient(135deg,#00aeea,#e6007e);border-radius:4px}}
.brand-name em{{color:#62d6ff}}
.card:before{{background:linear-gradient(var(--purple),var(--magenta))}}
.metric,.mini b{{color:var(--deep)}}
.bar span{{background:linear-gradient(90deg,#00aeea,var(--magenta))}}
.radar-value{{fill:#00aeea26;stroke:var(--magenta)}}
th{{background:#eef7fb;color:#075985}}
.nav{{position:sticky;top:0;z-index:20;padding:10px 0;background:#f6f7f9ee;backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}}
.nav a{{color:#075985;background:#fff;border-color:#d0d5dd}}
.nav a:hover{{border-color:#00aeea;color:#006f9f}}
.value-strip{{background:linear-gradient(110deg,#111827,#075985);}}
.score-panel{{background:#111827}}
.executive{{background:linear-gradient(135deg,#fff,#f1faff);border-color:#cbe8f3}}
.panel{{transition:box-shadow .2s ease}}
.panel.collapsed{{padding-bottom:14px}}
.panel.collapsed > :not(h3){{display:none}}
.panel h3{{display:flex;align-items:center;justify-content:space-between;gap:12px;cursor:pointer;color:#172b4d}}
.panel h3::after{{content:'−';font-size:22px;line-height:1;color:#00aeea;font-weight:400}}
.panel.collapsed h3::after{{content:'+'}}
.collapse-note{{font-size:11px;color:var(--muted);font-weight:400;margin-left:auto}}
.hero-pillars{{display:flex;gap:8px;flex-wrap:wrap;margin-top:24px}}.hero-pillars span{{border:1px solid #ffffff38;background:#ffffff14;border-radius:99px;padding:7px 12px;font-size:12px;color:#fff}}.hero-pillars b{{color:#62d6ff}}
.scope-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.scope-card{{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;min-height:142px;border-top:3px solid #98a2b3}}.scope-card.scope-success{{border-top-color:#12b76a}}.scope-card.scope-partial{{border-top-color:#f79009}}.scope-card.scope-not_available,.scope-card.scope-roadmap{{border-top-color:#00aeea}}.scope-top{{display:flex;justify-content:space-between;align-items:flex-start;gap:8px}}.scope-card p{{font-size:12px;color:#475467;margin:12px 0 10px;line-height:1.45}}.scope-card small{{display:block;font-size:10px;color:var(--muted);line-height:1.35}}.scope-card .status{{white-space:nowrap}}
.inventory-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.inventory-card{{background:#111827;color:#fff;border-radius:12px;padding:15px;min-height:100px}}.inventory-card span{{display:block;color:#cbd5e1;font-size:11px}}.inventory-card b{{display:block;font-size:30px;line-height:1.2;margin:8px 0;color:#fff}}.inventory-bar{{height:5px;border-radius:6px;background:#ffffff1f;overflow:hidden}}.inventory-bar i{{display:block;height:100%;background:linear-gradient(90deg,#00aeea,#e6007e);border-radius:6px}}
.readiness-banner{{display:flex;gap:18px;align-items:center;flex-wrap:wrap;background:#111827;color:#fff;border-radius:12px;padding:15px 18px;margin-bottom:12px}}.readiness-banner b{{color:#62d6ff}}.readiness-banner span{{font-size:12px;color:#d0d5dd}}.readiness-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.readiness-card{{background:#fff;border:1px solid var(--line);border-left:4px solid #98a2b3;border-radius:10px;padding:13px;min-height:150px}}.readiness-pass{{border-left-color:#12b76a}}.readiness-warning{{border-left-color:#f79009}}.readiness-blocked{{border-left-color:#b42318}}.readiness-top{{display:flex;align-items:center;gap:7px}}.readiness-top b{{flex:1;font-size:13px}}.readiness-icon{{width:23px;height:23px;border-radius:50%;display:grid;place-items:center;background:#eef2f6;color:#475467;font-weight:800}}.readiness-pass .readiness-icon{{background:#dcfae6;color:#087443}}.readiness-warning .readiness-icon{{background:#fef0c7;color:#b54708}}.readiness-blocked .readiness-icon{{background:#fee4e2;color:#b42318}}.readiness-card p{{font-size:11px;color:#475467;margin:12px 0 8px;line-height:1.4}}.readiness-card small{{display:block;color:var(--muted);font-size:10px;line-height:1.35;margin-top:5px}}
.health-banner{{display:flex;gap:16px;align-items:center;flex-wrap:wrap;background:#eef7fb;border:1px solid #b9e6f5;border-radius:12px;padding:14px 16px;color:#075985}}.health-banner b{{font-size:16px;color:#111827}}.health-banner span{{font-size:12px}}.execution-health .notice{{margin:12px 0}}
@media(max-width:800px){{.nav{{top:0;overflow-x:auto;flex-wrap:nowrap}}.nav a{{white-space:nowrap}}}}
</style></head><body>
<header><div class="wrap hero"><div class="brand"><span class="brand-mark">SWO</span><span class="brand-name">Software<em>One</em></span><span>·</span><span>SECURITY & GOVERNANCE</span></div><div class="hero-label">Assessment de postura · relatório confidencial</div><h1>Visibilidade para decidir. Evidência para agir.</h1><p>Assessment Executivo de Segurança e Governança</p><div class="hero-pillars"><span><b>Descobrir</b> exposição</span><span><b>Governar</b> identidades e recursos</span><span><b>Otimizar</b> risco e investimento</span></div><div class="hero-meta"><span>{esc(meta["customer_name"])}</span><span>Execução: {esc(meta["collected_at"])} UTC</span><span>Run ID: {esc(meta["run_id"])}</span><span>Uso interno · consultivo</span></div></div></header>
<main class="wrap">
{coverage_notice}
<nav class="nav"><a href="#executive-summary">Resumo executivo</a>{readiness_nav}<a href="#coverage">Cobertura 360</a><a href="#inventory-overview">Números</a><a href="#risks">Riscos prioritários</a><a href="#decision-layer">Decisões</a><a href="#analysis">Análise e plano</a><a href="#discovery">Discovery técnico</a><a href="#lifecycle">FinOps e ciclo de vida</a><a href="#runbooks">Runbooks</a><a href="#controls">Controles</a><a href="#transparency">Integridade e limitações</a></nav>
<section class="section summary-grid" id="executive-summary"><div class="executive"><div class="eyebrow">Leitura executiva</div><h2>O que este resultado significa</h2><p>A postura atual apresenta <b>{score_text.lower()}</b>, com maior necessidade de atenção em <b>Governança Azure</b>. O assessment identificou <b>{len(findings)} riscos priorizados</b> e <b>{len(quick_wins)} ações de baixo esforço</b> que podem iniciar a evolução imediatamente.</p><p><b>Ponto forte:</b> {esc(strengths_text)}.</p><div class="notice"><b>Mensagem para liderança:</b> o maior risco está na combinação entre identidades sem proteção adequada, privilégios amplos e recursos Azure com exposição ou governança incompleta.</div></div><div class="score-panel"><div class="score-ring"><div><b>{overall:.0f}</b><span>/ 100</span></div></div><div class="score-copy"><h3>{score_text}</h3><p>{esc(score_methodology.get("name", "Score ponderado pelos controles disponíveis"))}. Cobertura geral: <b>{coverage:.0f}%</b>. {esc(score_methodology.get("coverage_rule", "A interpretação deve considerar licenças e limitações."))}</p></div></div></section>
{executive_security_kpis}
{preflight_html}
{execution_health_html}
{render_scope_coverage(data)}
{render_inventory_overview(data)}
<section class="section value-strip"><div><b>Avaliar</b><span>evidências do tenant</span></div><i>→</i><div><b>Priorizar</b><span>risco, esforço e impacto</span></div><i>→</i><div><b>Otimizar</b><span>roadmap para decisão</span></div></section>
<section class="section"><div class="grid"><div class="card"><div class="metric-label">Controles avaliados</div><div class="metric">{coverage:.0f}<small>%</small></div><span class="metric-note">{evaluated_control_count} de {len(catalog["controls"])} controles com evidência</span></div><div class="card"><div class="metric-label">Módulos executados</div><div class="metric">{executed_modules}<small>/{total_modules}</small></div><span class="metric-note">Módulos success ou partial</span></div><div class="card"><div class="metric-label">Achados priorizados</div><div class="metric">{len(findings)}</div><span class="metric-note">Ordenados por risco</span></div><div class="card"><div class="metric-label">Quick wins</div><div class="metric">{len(quick_wins)}</div><span class="metric-note">Alto impacto e baixo esforço</span></div><div class="card"><div class="metric-label">Qualidade da evidência</div><div class="metric">{esc(evidence_quality.get("score", "N/D"))}<small>/100</small></div><span class="metric-note">Permissões, licenças e execução</span></div></div></section>
<section class="section dashboard"><div class="panel"><h2>Score por domínio</h2><div class="domains">{domain_cards}</div><div class="notice" style="margin-top:16px"><b>Confiança:</b> alta para os módulos executados. Custo e lifecycle estão parciais nesta demonstração.</div></div><div class="panel radar"><h2>Radar de maturidade</h2>{radar_svg(domain_scores)}</div></section>
<section class="section summary-grid" id="risks"><div><h2>Principais riscos</h2><div class="finding-list">{finding_cards}</div></div><div class="insights"><h3>Top 3 para decisão</h3>{top_findings}</div></section>
<section class="section panel"><h2>Quick wins</h2><ul>{quick_win_list or '<li>Nenhum quick win identificado.</li>'}</ul></section>
{analysis_html}
{decision_html}
{lifecycle_html}
{runbooks_html}
{comparison_html}
<section class="section panel" id="controls"><h2>Controles avaliados</h2><p class="section-intro">O estado formal diferencia controle conforme, não conforme e evidência insuficiente. Licença ou permissão ausente nunca é apresentada como conformidade.</p><table><thead><tr><th>ID</th><th>Controle</th><th>Domínio</th><th>Frente consultiva</th><th>Status</th><th>Estado da evidência</th><th>Score</th><th>Confiança</th></tr></thead><tbody>{control_rows}</tbody></table></section>
{discovery_html}
<section class="section panel" id="transparency"><h2>Transparência e limitações</h2><ul><li>Este relatório é uma demonstração com dados fictícios.</li><li>Resultados dependem do escopo, permissões, licenças e período de retenção disponíveis.</li><li>Achados técnicos devem ser validados pelo responsável do recurso antes da remediação.</li><li>O assessment não representa certificação, auditoria legal ou garantia absoluta de segurança.</li></ul></section>
<footer>Engine {esc(meta["engine_version"])} · Catálogo {esc(catalog["catalog_version"])} · Run ID {esc(meta["run_id"])} · Dados coletados em UTC · Relatório autocontido para visualização offline.</footer>
</main>
<script>
(function () {{
  const root = document.getElementById('discovery');
  const input = document.getElementById('discoverySearch');
  const count = document.getElementById('discoveryCount');
  const clear = document.getElementById('clearDiscovery');
  const exportButton = document.getElementById('exportDiscovery');
  if (!root || !input) return;
  const tables = Array.from(root.querySelectorAll('table[data-filterable="true"]'));
  const csvEscape = value => '"' + String(value ?? '').replaceAll('"', '""') + '"';
  function applyFilter() {{
    const query = input.value.trim().toLocaleLowerCase();
    let visible = 0;
    let total = 0;
    tables.forEach(table => {{
      Array.from(table.tBodies).forEach(tbody => Array.from(tbody.rows).forEach(row => {{
        total += 1;
        const match = !query || row.textContent.toLocaleLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible += 1;
      }}));
    }});
    count.textContent = query ? visible + ' de ' + total + ' registros' : total + ' registros';
  }}
  input.addEventListener('input', applyFilter);
  clear.addEventListener('click', () => {{ input.value = ''; applyFilter(); input.focus(); }});
  exportButton.addEventListener('click', () => {{
    const lines = [];
    tables.forEach((table, index) => {{
      const title = table.closest('.panel')?.querySelector('h3,h2')?.textContent || 'Discovery';
      if (index) lines.push([]);
      lines.push([title].map(csvEscape));
      lines.push(Array.from(table.tHead?.rows[0]?.cells || []).map(cell => csvEscape(cell.textContent.trim())));
      Array.from(table.tBodies[0]?.rows || []).filter(row => !row.hidden).forEach(row => {{
        lines.push(Array.from(row.cells).map(cell => csvEscape(cell.textContent.trim())));
      }});
    }});
    const blob = new Blob([lines.map(line => line.join(',')).join('\\n')], {{type: 'text/csv;charset=utf-8'}});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'discovery-detalhado.csv';
    link.click();
    URL.revokeObjectURL(url);
  }});
  applyFilter();
  // Mantém a leitura inicial compacta: o consultor expande apenas o bloco necessário.
  Array.from(root.querySelectorAll(':scope > .panel')).forEach((panel, index) => {{
    const heading = panel.querySelector('h3');
    if (!heading) return;
    if (index > 0) panel.classList.add('collapsed');
    heading.setAttribute('role', 'button');
    heading.setAttribute('tabindex', '0');
    const toggle = () => panel.classList.toggle('collapsed');
    heading.addEventListener('click', toggle);
    heading.addEventListener('keydown', event => {{ if (event.key === 'Enter' || event.key === ' ') {{ event.preventDefault(); toggle(); }} }});
  }});
}}());
</script></body></html>'''


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera HTML autocontido do assessment")
    parser.add_argument("--data", type=Path, default=DATA_PATH, help="Contrato JSON normalizado")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH, help="HTML de saída")
    args = parser.parse_args()
    catalog, data, runbooks = load_data(args.data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(catalog, data, runbooks), encoding="utf-8")
    print(f"Relatório gerado: {args.output}")


if __name__ == "__main__":
    main()
