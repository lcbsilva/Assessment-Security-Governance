"""Deriva insights compostos e rastreabilidade para a decisão consultiva."""

from __future__ import annotations


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
