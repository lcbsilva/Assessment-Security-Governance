"""Deriva insights compostos e rastreabilidade para a decisão consultiva."""

from __future__ import annotations


def prioritize_findings(findings: list[dict], evidence_quality: dict | None = None, cost_signal: object = "Não quantificado") -> list[dict]:
    """Aplica uma prioridade única e auditável aos achados.

    O score de prioridade organiza trabalho; não altera o risco técnico do
    achado. Impacto financeiro só recebe peso adicional quando há sinal
    quantificado publicado pelo Cost Management/Advisor.
    """
    quality_score = int((evidence_quality or {}).get("score", 0) or 0)
    confidence = "alta" if quality_score >= 80 else ("média" if quality_score >= 60 else "baixa")
    result = []
    for item in findings:
        row = dict(item)
        risk = int(item.get("risk_score", 0) or 0)
        effort = max(1, min(5, int(item.get("effort", 3) or 3)))
        prefix = str(item.get("control_id", "")).split("-")[0]
        focus_bonus = 8 if prefix in {"SEC", "GOV"} else (5 if prefix == "ID" else 0)
        financial_bonus = 10 if prefix == "COST" and cost_signal not in {None, "", "Não quantificado"} else 0
        confidence_bonus = 5 if confidence == "alta" else (2 if confidence == "média" else 0)
        priority_score = round(risk * 0.7 + (6 - effort) * 6 + focus_bonus + financial_bonus + confidence_bonus)
        row.update({
            "priority_score": priority_score,
            "priority": "P1" if priority_score >= 80 else ("P2" if priority_score >= 60 else "P3"),
            "evidence_confidence": confidence,
            "financial_signal": "quantified" if financial_bonus else "unquantified",
        })
        result.append(row)
    return sorted(result, key=lambda item: (-item.get("priority_score", 0), -item.get("risk_score", 0), str(item.get("control_id", "")), str(item.get("title", ""))))


def enrich_rbac_identity(discovery: dict) -> list[dict]:
    """Correlaciona RBAC com identidade localmente; não altera a evidência original."""
    users = {str(item.get("id")): item for item in discovery.get("users", []) if item.get("id")}
    rows = discovery.get("rbac", [])
    for row in rows:
        user = users.get(str(row.get("principal")), {})
        row["principal_name"] = user.get("display_name", "Principal não resolvido")
        row["principal_account_type"] = user.get("account_type", "Não resolvido")
        row["principal_mfa"] = user.get("mfa_status", "Não resolvido")
        row["principal_privileged"] = "Sim" if user.get("privileged") else "Não/Não resolvido"
    return rows


def risk_intersections(discovery: dict) -> list[dict]:
    """Encontra combinações de sinais; não transforma correlação em incidente."""
    users = discovery.get("users", [])
    resources = discovery.get("resources", [])
    intersections = []
    missing_admin_mfa = sum(1 for user in users if user.get("privileged") is True and user.get("mfa_status") == "Not registered")
    if missing_admin_mfa:
        intersections.append({"id": "X-001", "title": "Privilégio administrativo combinado com ausência de MFA", "severity": "critical", "risk": 92, "affected": missing_admin_mfa, "evidence": f"{missing_admin_mfa} contas privilegiadas sem MFA registrado", "action": "Proteger administradores com MFA resistente a phishing e revisar exceções."})
    public_unowned = [item for item in resources if str(item.get("exposure", "")).lower().startswith("public") and (not item.get("owner") or item.get("owner") == "A definir")]
    if public_unowned:
        intersections.append({"id": "X-002", "title": "Exposição pública sem owner identificado", "severity": "high", "risk": 88, "affected": len(public_unowned), "evidence": f"{len(public_unowned)} recursos públicos sem owner identificado", "action": "Confirmar criticidade, owner e necessidade de exposição antes de qualquer correção."})
    public_untagged = [item for item in resources if str(item.get("exposure", "")).lower().startswith("public") and ("Nenhuma" in str(item.get("tags", "")) or "env" not in str(item.get("tags", "")).lower())]
    if public_untagged:
        intersections.append({"id": "X-003", "title": "Exposição pública com governança de tags incompleta", "severity": "high", "risk": 84, "affected": len(public_untagged), "evidence": f"{len(public_untagged)} recursos públicos sem taxonomia mínima demonstrada", "action": "Associar owner, ambiente e criticidade ao inventário para priorizar proteção."})
    privileged_rbac_without_mfa = [item for item in discovery.get("rbac", []) if item.get("access_risk") in {"Crítico", "Alto"} and item.get("principal_mfa") == "Not registered"]
    if privileged_rbac_without_mfa:
        intersections.append({"id": "X-004", "title": "Atribuição RBAC de alto risco para principal sem MFA", "severity": "critical", "risk": 94, "affected": len(privileged_rbac_without_mfa), "evidence": f"{len(privileged_rbac_without_mfa)} atribuições RBAC de alto risco associadas a principal sem MFA registrado", "action": "Validar identidade, owner, menor privilégio e proteção MFA antes de revisar o acesso."})
    return intersections


def control_evidence(data: dict, catalog: dict) -> list[dict]:
    """Relaciona controle, domínio e evidência de coleta sem copiar dados sensíveis."""
    prefixes = {"identity": ("Identity", "MFA", "Conditional", "PIM", "Sign-ins", "Directory", "Role members"), "security": ("Secure", "Defender", "devices", "Entra"), "governance": ("Azure inventory", "RBAC", "Policy", "Hierarchy", "Advisor"), "cost": ("Cost", "Azure inventory"), "compliance": ("Policy", "Azure inventory")}
    logs = data.get("discovery", {}).get("collection_log", [])
    rows = []
    for control in catalog.get("controls", []):
        domain = control.get("domain")
        matches = [log for log in logs if any(token.lower() in str(log.get("module", "")).lower() for token in prefixes.get(domain, ()))]
        best = next((log for log in matches if log.get("status") == "success"), matches[0] if matches else {})
        status = best.get("status", "not_available")
        confidence = "alta" if status == "success" else ("média" if status == "partial" else "baixa")
        rows.append({"control_id": control.get("id"), "control": control.get("title"), "domain": domain, "module": best.get("module", "Não encontrado"), "status": status, "records": best.get("records", 0), "confidence": confidence, "limitation": best.get("note", "Evidência não disponível")})
    return rows


def executive_actions(findings: list[dict]) -> list[dict]:
    outcomes = {"ID-001": "Reduzir exposição de identidade", "ID-002": "Reduzir risco de comprometimento privilegiado", "ID-009": "Reduzir privilégio permanente", "SEC-005": "Diminuir tempo de resposta a alertas", "GOV-003": "Reduzir superfície de acesso", "GOV-004": "Reduzir exposição de rede", "GOV-006": "Aumentar conformidade de workloads"}
    actions = []
    for item in sorted(findings, key=lambda row: row.get("risk_score", 0), reverse=True)[:5]:
        actions.append({"priority": "P1" if int(item.get("risk_score", 0)) >= 75 else "P2", "finding": item.get("title", "—"), "risk": item.get("risk_score", 0), "owner": item.get("owner", "A definir"), "outcome": outcomes.get(item.get("control_id"), "Aumentar controle e rastreabilidade")})
    return actions


def cross_domain_insights(discovery: dict) -> list[dict]:
    """Conecta evidências de segurança e governança em mensagens acionáveis.

    A correlação é indicativa: ela prioriza revisão, mas nunca declara incidente
    ou autoriza remediação automática.
    """
    users = discovery.get("users", [])
    resources = discovery.get("resources", [])
    rbac = discovery.get("rbac", [])
    policies = discovery.get("conditional_access", [])
    apps = discovery.get("app_registrations", [])
    grants = discovery.get("oauth2_permission_grants", [])
    insights = []

    privileged_guests = [u for u in users if u.get("privileged") is True and str(u.get("account_type", "")).lower() == "guest"]
    if privileged_guests:
        insights.append({"id": "I-001", "domain": "Identity + Governance", "severity": "critical", "risk": 96, "affected": len(privileged_guests), "title": "Convidado externo com privilégio administrativo", "evidence": f"{len(privileged_guests)} convidados aparecem associados a privilégio administrativo.", "action": "Validar necessidade, owner, expiração e escopo antes de manter o acesso."})

    stale_privileged = [u for u in users if u.get("privileged") is True and str(u.get("last_sign_in", "")).lower() in {"never", "unknown", "none"}]
    if stale_privileged:
        insights.append({"id": "I-002", "domain": "Identity + Lifecycle", "severity": "high", "risk": 90, "affected": len(stale_privileged), "title": "Privilégio sem atividade recente demonstrada", "evidence": f"{len(stale_privileged)} contas privilegiadas não possuem atividade recente demonstrada.", "action": "Confirmar owner e necessidade; considerar acesso elegível e revisão periódica."})

    ca_without_mfa = [p for p in policies if str(p.get("state", "")).lower() == "enabled" and "mfa" not in str(p.get("grant_controls", "")).lower()]
    if ca_without_mfa:
        insights.append({"id": "I-003", "domain": "Identity + Conditional Access", "severity": "high", "risk": 82, "affected": len(ca_without_mfa), "title": "Conditional Access habilitado sem controle MFA explícito", "evidence": f"{len(ca_without_mfa)} políticas habilitadas não demonstram controle MFA no retorno coletado.", "action": "Validar intenção, condições, controles e exclusões da política."})

    public_rbac = [r for r in rbac if r.get("access_risk") in {"Crítico", "Alto"} and str(r.get("scope_kind", "")).lower() in {"management group", "subscription"}]
    if public_rbac:
        insights.append({"id": "I-004", "domain": "Azure Governance + RBAC", "severity": "critical", "risk": 94, "affected": len(public_rbac), "title": "Acesso administrativo amplo em escopo Azure elevado", "evidence": f"{len(public_rbac)} atribuições de alto risco aparecem em Management Group ou Subscription.", "action": "Revisar menor privilégio, herança, owner e elegibilidade PIM."})

    expired_apps = [a for a in apps if int(a.get("expired_credentials", 0) or 0) > 0]
    if expired_apps:
        insights.append({"id": "I-005", "domain": "Application Security", "severity": "critical", "risk": 91, "affected": len(expired_apps), "title": "Aplicações com credenciais expiradas", "evidence": f"{len(expired_apps)} registros de aplicação possuem credenciais expiradas.", "action": "Identificar owner e dependência, rotacionar de forma controlada e validar workload identity."})

    high_consent = [g for g in grants if int(g.get("high_impact_count", 0) or 0) > 0 or str(g.get("high_impact_scopes", "")).strip() not in {"", "Nenhum sinal de alto impacto", "—"}]
    if high_consent:
        insights.append({"id": "I-006", "domain": "Application Governance", "severity": "high", "risk": 87, "affected": len(high_consent), "title": "Consentimentos OAuth de alto impacto", "evidence": f"{len(high_consent)} consentimentos demonstram escopos de alto impacto.", "action": "Validar publisher, owner, justificativa e menor privilégio do consentimento."})

    public_no_owner = [r for r in resources if str(r.get("exposure", "")).lower().startswith("public") and r.get("owner") in {None, "", "A definir"}]
    if public_no_owner:
        insights.append({"id": "I-007", "domain": "Azure Security + Governance", "severity": "critical", "risk": 93, "affected": len(public_no_owner), "title": "Exposição pública sem responsabilização demonstrada", "evidence": f"{len(public_no_owner)} recursos públicos não demonstram owner.", "action": "Priorizar validação de criticidade, owner e necessidade de exposição."})

    return sorted(insights, key=lambda row: row["risk"], reverse=True)
