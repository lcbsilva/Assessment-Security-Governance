"""Deriva insights compostos e rastreabilidade para a decisão consultiva."""

from __future__ import annotations


def prioritize_findings(findings: list[dict], evidence_quality: dict | None = None, cost_signal: object = "Não quantificado") -> list[dict]:
    """Aplica uma prioridade única e auditável aos achados.

    O score de prioridade organiza trabalho; não altera o risco técnico do
    achado. Impacto financeiro só recebe peso adicional quando há sinal
    quantificado publicado pelo Cost Management/Advisor.
    """
    quality_score = int((evidence_quality or {}).get("score", 0) or 0)
    overall_confidence = "alta" if quality_score >= 80 else ("média" if quality_score >= 60 else "baixa")
    effort_bands = {1: "Muito baixo", 2: "Baixo", 3: "Moderado", 4: "Alto", 5: "Muito alto"}
    result = []
    for item in findings:
        row = dict(item)
        risk = int(item.get("risk_score", 0) or 0)
        effort = max(1, min(5, int(item.get("effort", 3) or 3)))
        control_confidence = str(item.get("control_confidence", "")).lower()
        confidence = (
            "alta" if control_confidence in {"high", "alta"} else
            "média" if control_confidence in {"medium", "média", "media"} else
            "baixa" if control_confidence in {"low", "baixa"} or str(item.get("evidence_state", "")).upper() == "INSUFFICIENT_EVIDENCE" else
            overall_confidence
        )
        prefix = str(item.get("control_id", "")).split("-")[0]
        focus_bonus = 8 if prefix in {"SEC", "GOV"} else (5 if prefix == "ID" else 0)
        financial_bonus = 10 if prefix == "COST" and cost_signal not in {None, "", "Não quantificado"} else 0
        confidence_bonus = 5 if confidence == "alta" else (2 if confidence == "média" else 0)
        priority_score = round(risk * 0.7 + (6 - effort) * 6 + focus_bonus + financial_bonus + confidence_bonus)
        insufficient = str(item.get("evidence_state", "")).upper() == "INSUFFICIENT_EVIDENCE"
        calculated_priority = "P1" if priority_score >= 80 else ("P2" if priority_score >= 60 else "P3")
        # P1 is reserved for findings backed by sufficient evidence. A
        # conditional signal remains visible, but must be validated first.
        priority = "P2" if insufficient and calculated_priority == "P1" else calculated_priority
        row.update({
            "priority_score": priority_score,
            "priority": priority,
            "priority_eligibility": "conditional_review" if insufficient else "eligible",
            "evidence_confidence": confidence,
            "financial_signal": "quantified" if financial_bonus else "unquantified",
            "effort_band": effort_bands[effort],
            "effort_basis": "Estimativa relativa para planejamento; não representa horas nem custo confirmado.",
            "affected_unit": item.get("affected_unit", _affected_unit(item.get("control_id"))),
            "impact_interpretation": "Contagem de objetos/sinais associados ao achado; não comprova impacto operacional ou incidente.",
            "user_impact": item.get("user_impact", _user_impact(item.get("control_id"))),
        })
        if insufficient:
            row["priority_rationale"] = "Não elegível para P1: evidência insuficiente ou entitlement não verificado; validar antes de tratar como risco confirmado."
        result.append(row)
    return sorted(result, key=lambda item: (-item.get("priority_score", 0), -item.get("risk_score", 0), str(item.get("control_id", "")), str(item.get("title", ""))))


def _affected_unit(control_id: object) -> str:
    return {
        "ID-001": "usuários", "ID-002": "contas privilegiadas", "ID-004": "exclusões de política",
        "ID-005": "usuários afetados", "ID-008": "contas", "ID-009": "atribuições de função",
        "GOV-002": "recursos", "GOV-003": "atribuições RBAC", "GOV-004": "recursos",
        "GOV-006": "registros Azure Policy", "COST-001": "recursos", "COST-002": "avisos de ciclo de vida",
        "SEC-001": "métrica do tenant", "SEC-002": "dispositivos", "SEC-003": "aplicações",
        "SEC-005": "alertas",
    }.get(str(control_id), "itens observados; unidade a validar")


def _user_impact(control_id: object) -> str:
    return {
        "ID-001": "Direto: usuários com lacuna de MFA; impacto operacional não medido.",
        "ID-002": "Direto: contas administrativas; impacto operacional não medido.",
        "ID-005": "Potencial: usuários afetados por autenticação legada; validar dependências.",
        "ID-008": "Potencial: contas sem atividade recente ou convidados; validar owners.",
        "SEC-002": "Potencial: acesso de usuários em dispositivos; validar política e escopo.",
    }.get(str(control_id), "Não determinado pela evidência técnica coletada; validar com o owner.")


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
    public_unowned = [item for item in resources if str(item.get("exposure", "")).lower().startswith("public") and item.get("exposure_class", "confirmed") in {"confirmed", "heuristic"} and (not item.get("owner") or item.get("owner") == "A definir")]
    if public_unowned:
        intersections.append({"id": "X-002", "title": "Exposição pública sem owner identificado", "severity": "high", "risk": 88, "affected": len(public_unowned), "evidence": f"{len(public_unowned)} recursos públicos sem owner identificado", "action": "Confirmar criticidade, owner e necessidade de exposição antes de qualquer correção."})
    public_untagged = [item for item in resources if str(item.get("exposure", "")).lower().startswith("public") and item.get("exposure_class", "confirmed") in {"confirmed", "heuristic"} and ("Nenhuma" in str(item.get("tags", "")) or "env" not in str(item.get("tags", "")).lower())]
    if public_untagged:
        intersections.append({"id": "X-003", "title": "Exposição pública com governança de tags incompleta", "severity": "high", "risk": 84, "affected": len(public_untagged), "evidence": f"{len(public_untagged)} recursos públicos sem taxonomia mínima demonstrada", "action": "Associar owner, ambiente e criticidade ao inventário para priorizar proteção."})
    privileged_rbac_without_mfa = [item for item in discovery.get("rbac", []) if item.get("access_risk") in {"Crítico", "Alto"} and item.get("principal_mfa") == "Not registered"]
    if privileged_rbac_without_mfa:
        intersections.append({"id": "X-004", "title": "Atribuição RBAC de alto risco para principal sem MFA", "severity": "critical", "risk": 94, "affected": len(privileged_rbac_without_mfa), "evidence": f"{len(privileged_rbac_without_mfa)} atribuições RBAC de alto risco associadas a principal sem MFA registrado", "action": "Validar identidade, owner, menor privilégio e proteção MFA antes de revisar o acesso."})
    return intersections


def control_evidence(data: dict, catalog: dict) -> list[dict]:
    """Relaciona cada controle às fontes e janelas de coleta que podem sustentá-lo."""
    tokens_by_control = {
        "ID-001": ("MFA",), "ID-002": ("MFA", "Directory roles"), "ID-003": ("Conditional Access",),
        "ID-004": ("Conditional Access",), "ID-005": ("Sign-ins / legacy auth",),
        "ID-006": ("Identity basic", "Groups"), "ID-007": ("PIM",), "ID-008": ("Identity", "Groups"),
        "ID-009": ("PIM",), "SEC-001": ("Secure Score",), "SEC-002": ("Entra devices", "Intune managed devices"),
        "SEC-003": ("Enterprise applications", "App registrations"), "SEC-004": ("Directory audit events",),
        "SEC-005": ("Defender alerts", "Defender vulnerabilities"), "GOV-001": ("Azure hierarchy",),
        "GOV-002": ("Azure inventory",), "GOV-003": ("RBAC",), "GOV-004": ("Azure inventory",),
        "GOV-005": ("Azure Policy",), "GOV-006": ("Azure Policy",), "COST-001": ("Orphan resources", "Cost Management"),
        "COST-002": ("Service retirement",), "CMP-001": ("Purview DLP", "DLP policies"),
        "CMP-002": ("Purview labels", "Sensitivity labels"), "CMP-003": ("Purview retention", "Retention policies"),
    }
    logs = data.get("discovery", {}).get("collection_log", [])
    controls_by_id = {str(item.get("id")): item for item in data.get("controls", [])}
    rank = {"success": 0, "partial": 1, "not_available": 2, "not_run": 3, "error": 4}
    rows = []
    for control in catalog.get("controls", []):
        control_id = str(control.get("id"))
        tokens = tokens_by_control.get(control_id, ())
        matches = [log for log in logs if any(token.casefold() in str(log.get("module", "")).casefold() for token in tokens)]
        matches.sort(key=lambda log: (rank.get(str(log.get("status", "unknown")), 5), str(log.get("module", ""))))
        best = matches[0] if matches else {}
        result = controls_by_id.get(control_id, {})
        status = best.get("status", "not_available")
        control_confidence = str(result.get("confidence", "low"))
        confidence = {"high": "alta", "medium": "média", "low": "baixa"}.get(control_confidence, "baixa")
        source_list = [
            {key: log.get(key) for key in ("module", "source", "status", "records", "started_at", "finished_at", "duration_seconds", "limitation_category") if log.get(key) not in (None, "")}
            for log in matches
        ]
        if matches:
            starts = [str(log["started_at"]) for log in matches if log.get("started_at")]
            finishes = [str(log["finished_at"]) for log in matches if log.get("finished_at")]
            window = {"started_at": min(starts) if starts else None, "finished_at": max(finishes) if finishes else None}
            window_display = f"{window['started_at'] or 'início não registrado'} → {window['finished_at'] or 'fim não registrado'}"
            limitation_by_status = {
                "partial": "Coleta parcial; cobertura e paginação precisam ser consideradas.",
                "not_available": "Fonte indisponível nesta execução; validar licença, permissão e disponibilidade.",
                "not_run": "Módulo fora do perfil selecionado; não representa conformidade.",
                "error": "Falha controlada; consultar o manifesto técnico confidencial.",
            }
            limitation = "; ".join(dict.fromkeys(
                limitation_by_status.get(str(log.get("status")), "Consultar evidência normalizada do controle.")
                for log in matches
            ))
        else:
            window = {"started_at": None, "finished_at": None}
            window_display = "Não coletado nesta execução"
            limitation = "Nenhuma fonte correspondente foi coletada nesta execução; evidência insuficiente."
        rows.append({
            "control_id": control_id, "control": control.get("title"), "domain": control.get("domain"),
            "module": best.get("module", "Fonte não coletada"), "source": best.get("source", "Não disponível"),
            "status": status, "evidence_state": result.get("evidence_state", "INSUFFICIENT_EVIDENCE"),
            "records": best.get("records", 0), "confidence": confidence, "limitation": limitation,
            "collection_window": window, "collection_window_display": window_display,
            "sources": source_list,
            "sources_display": "; ".join(dict.fromkeys(str(item.get("source", "")) for item in source_list if item.get("source"))) or "Não disponível",
        })
    return rows


def attach_finding_lineage(findings: list[dict], control_rows: list[dict]) -> list[dict]:
    """Adiciona referências operacionais de coleta a achados sem copiar registros brutos."""
    evidence_by_id = {str(item.get("control_id")): item for item in control_rows}
    enriched = []
    for finding in findings:
        row = dict(finding)
        source = evidence_by_id.get(str(row.get("control_id")))
        if source:
            lineage = dict(row.get("evidence_lineage", {}))
            lineage.update({
                "control_id": source.get("control_id"), "module": source.get("module"),
                "source": source.get("source"), "source_status": source.get("status"), "evidence_state": source.get("evidence_state"),
                "confidence": source.get("confidence"), "collection_window": source.get("collection_window"),
                "sources": source.get("sources", []), "limitation": source.get("limitation"),
            })
            row["evidence_lineage"] = lineage
            row.setdefault("evidence_state", source.get("evidence_state", "INSUFFICIENT_EVIDENCE"))
            row.setdefault("control_confidence", {"alta": "high", "média": "medium", "baixa": "low"}.get(source.get("confidence"), "low"))
        enriched.append(row)
    return enriched


def executive_actions(findings: list[dict]) -> list[dict]:
    outcomes = {"ID-001": "Reduzir exposição de identidade", "ID-002": "Reduzir risco de comprometimento privilegiado", "ID-009": "Reduzir privilégio permanente", "SEC-005": "Diminuir tempo de resposta a alertas", "GOV-003": "Reduzir superfície de acesso", "GOV-004": "Reduzir exposição de rede", "GOV-006": "Aumentar conformidade de workloads"}
    actions = []
    for item in sorted(findings, key=lambda row: row.get("risk_score", 0), reverse=True)[:5]:
        insufficient = str(item.get("evidence_state", "")).upper() == "INSUFFICIENT_EVIDENCE"
        actions.append({"priority": "P2" if insufficient else ("P1" if int(item.get("risk_score", 0)) >= 75 else "P2"), "finding": item.get("title", "—"), "risk": item.get("risk_score", 0), "owner": item.get("owner", "A definir"), "outcome": outcomes.get(item.get("control_id"), "Aumentar controle e rastreabilidade"), "priority_eligibility": "conditional_review" if insufficient else "eligible"})
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

    public_no_owner = [r for r in resources if str(r.get("exposure", "")).lower().startswith("public") and r.get("exposure_class", "confirmed") in {"confirmed", "heuristic"} and r.get("owner") in {None, "", "A definir"}]
    if public_no_owner:
        insights.append({"id": "I-007", "domain": "Azure Security + Governance", "severity": "critical", "risk": 93, "affected": len(public_no_owner), "title": "Exposição pública sem responsabilização demonstrada", "evidence": f"{len(public_no_owner)} recursos públicos não demonstram owner.", "action": "Priorizar validação de criticidade, owner e necessidade de exposição."})

    posture_summary = discovery.get("security_posture_summary", {})
    explicit_signals = int(posture_summary.get("resources_with_explicit_signals", 0) or 0)
    signal_rows = posture_summary.get("by_signal", [])
    if explicit_signals and signal_rows:
        top_signals = ", ".join(f"{row.get('signal', 'sinal')} ({row.get('resources', 0)})" for row in signal_rows[:3])
        public_signal = any("públic" in str(row.get("signal", "")).lower() or "firewall" in str(row.get("signal", "")).lower() for row in signal_rows)
        insights.append({
            "id": "I-008",
            "domain": "Azure Security + Governance",
            "severity": "high" if public_signal else "medium",
            "risk": 88 if public_signal else 76,
            "affected": explicit_signals,
            "title": "Recursos Azure com sinais explícitos de postura para revisão",
            "evidence": f"{explicit_signals} recursos apresentam sinais retornados explicitamente pelo inventário: {top_signals}.",
            "action": "Validar criticidade, exposição, owner, exceções aprovadas e configuração efetiva antes de qualquer remediação.",
        })

    governance_summary = discovery.get("governance_summary", {})
    governance_resources = int(governance_summary.get("resources_assessed", 0) or 0)
    without_owner = int(governance_summary.get("without_owner", 0) or 0)
    policy_evaluated = int(governance_summary.get("policy_evaluated", 0) or 0)
    policy_non_compliant = int(governance_summary.get("policy_non_compliant", 0) or 0)
    if governance_resources and without_owner:
        owner_ratio = without_owner / governance_resources
        insights.append({
            "id": "I-009",
            "domain": "Azure Governance",
            "severity": "high" if owner_ratio >= 0.5 else "medium",
            "risk": 80 if owner_ratio >= 0.5 else 68,
            "affected": without_owner,
            "title": "Recursos sem responsabilização demonstrada",
            "evidence": f"{without_owner} de {governance_resources} recursos não demonstram owner no inventário coletado.",
            "action": "Definir owner técnico e de negócio, criticidade e ambiente antes de priorizar mudanças.",
        })
    if policy_evaluated and policy_non_compliant:
        policy_rate = policy_non_compliant / policy_evaluated
        insights.append({
            "id": "I-010",
            "domain": "Azure Governance + Compliance",
            "severity": "high" if policy_rate >= 0.5 else "medium",
            "risk": 84 if policy_rate >= 0.5 else 72,
            "affected": policy_non_compliant,
            "title": "Não conformidades observadas em Azure Policy",
            "evidence": f"{policy_non_compliant} de {policy_evaluated} avaliações retornaram estado não conforme.",
            "action": "Validar escopo, exceções, data da avaliação e owner da Policy antes de corrigir recursos.",
        })

    owner_map = {
        "identity": "Identidade / Entra",
        "application": "Segurança de Aplicações",
        "azure governance": "Cloud Governance",
        "azure security": "Cloud Security",
        "azure security + governance": "Cloud Security + Governance",
    }
    for row in insights:
        risk = int(row.get("risk", 0) or 0)
        domain = str(row.get("domain", "")).lower()
        row["priority"] = "P1" if risk >= 90 else ("P2" if risk >= 75 else "P3")
        row["suggested_owner"] = next((value for key, value in owner_map.items() if key in domain), "Security & Governance")
        row["effort_band"] = "Baixo" if risk < 80 else "Médio" if risk < 90 else "Alto"
    return sorted(insights, key=lambda row: (-row["risk"], str(row.get("id", ""))))
