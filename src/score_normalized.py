#!/usr/bin/env python3
"""Deriva controles e achados a partir do contrato normalizado.

As regras são intencionalmente conservadoras: falta de evidência gera
``not_available``/``partial`` e não é tratada como ambiente conforme.
"""

from __future__ import annotations


def status(score: int | None) -> str:
    if score is None:
        return "not_available"
    if score >= 80:
        return "pass"
    if score >= 60:
        return "partial"
    return "fail"


def evidence_state(control_status: str) -> tuple[str, str]:
    """Estado formal da evidência; ausência não é conformidade."""
    if control_status == "pass":
        return "CONFORMANT", "score_at_or_above_threshold"
    if control_status in {"partial", "fail"}:
        return "NON_CONFORMANT", "score_below_threshold"
    if control_status == "not_available":
        return "INSUFFICIENT_EVIDENCE", "missing_permission_license_or_data"
    return "INSUFFICIENT_EVIDENCE", "collector_execution_error"


def count_from_signal(value: object) -> int:
    """Parseia contagens numéricas ou rótulos como '2 break-glass'."""
    if isinstance(value, bool) or value is None:
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    import re
    match = re.search(r"\d+", str(value))
    return int(match.group(0)) if match else 0


def license_gate_status(control_id: str, discovery: dict) -> str:
    """Indica se a fonte/licença mínima do controle apareceu na coleta."""
    if control_id == "SEC-001":
        return "satisfied" if discovery.get("secure_score") else "not_satisfied_or_not_available"
    if control_id == "SEC-005":
        return "satisfied" if discovery.get("defender_summary") else "not_satisfied_or_not_available"
    if control_id == "SEC-002":
        return "satisfied" if discovery.get("device_summary") or discovery.get("devices") else "not_verified"
    return "not_applicable_or_not_declared"


def finding(control_id: str, title: str, severity: str, risk: int, effort: int, affected: int, summary: str, evidence: list[str], recommendation: str, owner: str, source: str, action: dict) -> dict:
    dependencies = {
        "ID-001": ["Comunicação e registro de MFA", "Validação de exceções"],
        "ID-002": ["Contas break-glass identificadas", "Método resistente a phishing"],
        "ID-003": ["Inventário de aplicações", "Janela de mudança aprovada"],
        "ID-004": ["Justificativa dos owners", "Contas de emergência protegidas"],
        "ID-005": ["Mapeamento de dependências legadas", "Plano de comunicação"],
        "ID-008": ["Owner do usuário ou convidado", "Política de expiração"],
        "ID-009": ["Owners de funções", "Fluxo de aprovação PIM"],
        "SEC-001": ["Licenciamento aplicável", "Owners dos controles Secure Score"],
        "SEC-002": ["Inventário de dispositivos", "Políticas de conformidade"],
        "SEC-003": ["Owners das aplicações", "Calendário de rotação"],
        "SEC-005": ["SLA de SOC", "Acesso ao Defender"],
        "GOV-002": ["Taxonomia de tags", "Owners por workload"],
        "GOV-003": ["Owners dos escopos", "Modelo de acesso privilegiado"],
        "GOV-004": ["Criticidade do workload", "Arquitetura de rede aprovada"],
        "GOV-006": ["Owners das subscriptions", "Processo de exceção"],
        "COST-001": ["Validação de dependência", "Custo real no Cost Management"],
        "COST-002": ["Inventário afetado", "Plano de upgrade/migração"],
    }.get(control_id, ["Owner do controle", "Validação técnica"])
    return {
        "id": f"AUTO-{control_id}", "control_id": control_id, "title": title,
        "severity": severity, "risk_score": risk, "effort": effort,
        "quick_win": effort <= 2, "owner": owner, "source": source,
        "affected": affected, "status": "Open", "summary": summary,
        "evidence": evidence, "recommendation": recommendation,
        "limitations": ["Achado derivado automaticamente; validar contexto, exceções e proprietário antes de remediar."],
        "action_30_60_90": action,
        "evidence_lineage": {"source": source, "facts": evidence, "collection_scope": "Dados agregados e/ou normalizados do módulo indicado."},
        "remediation_dependencies": dependencies,
        "validation_questions": ["O owner confirma a evidência?", "Existe exceção documentada e aprovada?", "A ação pode ser executada sem impacto operacional?"],
        "priority_rationale": f"Risco {risk}/100, esforço relativo {effort}/5 e severidade {severity}; validar impacto financeiro quando indicado.",
    }


def derive(data: dict, catalog: dict) -> dict:
    discovery = data.setdefault("discovery", {})
    users = discovery.get("users", [])
    policies = discovery.get("conditional_access", [])
    resources = discovery.get("resources", [])
    rbac = discovery.get("rbac", [])
    retirements = discovery.get("lifecycle", {}).get("service_retirements", [])
    orphan_resources = discovery.get("lifecycle", {}).get("orphan_resources", [])
    policy_rows = discovery.get("policy_compliance", [])
    legacy_summary = discovery.get("legacy_auth_summary", {})
    secure_scores = discovery.get("secure_score", [])
    secure_score_controls = discovery.get("secure_score_controls", [])
    devices = discovery.get("devices", [])
    pim_summary = discovery.get("pim_summary", {})
    guests = [item for item in users if str(item.get("account_type", "")).lower() == "guest"]
    inactive = [item for item in users if str(item.get("last_sign_in", "")).lower() in {"never", "none"} or item.get("account_enabled") is False]
    applications = discovery.get("enterprise_applications", [])
    registrations = discovery.get("app_registrations", [])
    defender_summary = discovery.get("defender_summary", {})
    containers = discovery.get("containers", [])
    controls: dict[str, dict] = {}
    findings: list[dict] = []

    def put(control_id: str, score: int | None, confidence: str = "medium") -> None:
        definition = next((item for item in catalog.get("controls", []) if item.get("id") == control_id), {})
        gate = definition.get("license_gate", "not_required_or_not_declared")
        gate_status = license_gate_status(control_id, discovery)
        # A control that depends on an entitlement cannot become compliant
        # solely because a collector returned a default or partial value.
        # Missing entitlement evidence is explicitly insufficient evidence.
        gated_out = gate != "not_required_or_not_declared" and gate_status != "satisfied"
        control_status = "not_available" if gated_out else status(score)
        state, reason = evidence_state(control_status)
        if gated_out:
            reason = "license_or_entitlement_not_verified"
            confidence = "low"
        controls[control_id] = {"id": control_id, "status": control_status, "score": score or 0, "confidence": confidence, "evidence_state": state, "evidence_reason": reason, "license_gate": gate, "license_gate_status": gate_status}

    if users:
        registered = sum(1 for item in users if item.get("mfa_status") == "Registered")
        missing = sum(1 for item in users if item.get("mfa_status") == "Not registered")
        mfa_score = round(registered / len(users) * 100)
        put("ID-001", mfa_score, "high")
        if missing:
            findings.append(finding("ID-001", "Usuários sem cobertura adequada de MFA", "high" if mfa_score < 80 else "medium", max(55, 100 - mfa_score), 2, missing, f"{missing} usuários sem registro de MFA", [f"Usuários avaliados: {len(users)}", f"Cobertura calculada: {mfa_score}%"], "Priorizar registro de MFA e validar exceções no Conditional Access.", "Identity / IAM", "Graph authenticationMethods/userRegistrationDetails", {"30": "Classificar usuários sem MFA e exceções.", "60": "Aplicar política-piloto.", "90": "Expandir cobertura e revisar exceções."}))
    else:
        put("ID-001", None, "low")

    enabled_ca = [item for item in policies if str(item.get("state", "")).lower() == "enabled"]
    put("ID-003", 100 if enabled_ca else (40 if policies else None), "high" if policies else "low")
    exclusions = sum(count_from_signal(item.get("excluded", 0)) for item in policies)
    put("ID-004", 100 if policies and exclusions == 0 else (70 if policies else None), "high" if policies else "low")
    if policies and exclusions:
        findings.append(finding("ID-004", "Exclusões em Conditional Access exigem revisão", "medium", 58, 2, exclusions, f"Foram identificadas {exclusions} exclusões configuradas em Conditional Access.", [f"Políticas avaliadas: {len(policies)}", f"Exclusões contabilizadas: {exclusions}"], "Documentar justificativas, reduzir exclusões e proteger contas de emergência.", "Identity / IAM", "Microsoft Graph Conditional Access", {"30": "Documentar exceções.", "60": "Reduzir exclusões não justificadas.", "90": "Implantar revisão periódica."}))
    legacy_count = int(legacy_summary.get("legacy_signins", 0) or 0)
    signins_reviewed = int(legacy_summary.get("signins_reviewed", 0) or 0)
    if legacy_summary and signins_reviewed > 0:
        legacy_score = 95 if legacy_count == 0 else 35
        put("ID-005", legacy_score, "high")
        if legacy_count:
            affected = int(legacy_summary.get("affected_users", legacy_count) or legacy_count)
            findings.append(finding("ID-005", "Uso de autenticação legada identificado", "high", 78, 3, affected, f"{legacy_count} sign-ins legados foram observados na janela analisada.", [f"Janela: {legacy_summary.get('lookback_days', '—')} dias", f"Usuários afetados: {affected}", f"Sign-ins analisados: {legacy_summary.get('signins_reviewed', '—')}"], "Bloquear protocolos legados após validar dependências e acompanhar falhas de autenticação.", "Identity / IAM", "Microsoft Graph auditLogs/signIns", {"30": "Identificar usuários e aplicações dependentes.", "60": "Bloquear autenticação legada por Conditional Access.", "90": "Monitorar tentativas e remover exceções."}))
    else:
        # A existência de uma política de Conditional Access não prova
        # ausência de autenticação legada. Sem telemetria de sign-ins,
        # o controle permanece sem evidência suficiente.
        put("ID-005", None, "low")
    put("ID-006", 70 if users else None, "medium" if users else "low")
    privileged = [item for item in users if item.get("privileged") is True]
    privileged_missing = [item for item in privileged if item.get("mfa_status") == "Not registered"]
    if privileged:
        admin_mfa_score = round((len(privileged) - len(privileged_missing)) / len(privileged) * 100)
        put("ID-002", admin_mfa_score, "high")
        if privileged_missing:
            findings.append(finding("ID-002", "Administradores sem cobertura adequada de MFA", "critical" if admin_mfa_score < 60 else "high", max(65, 100 - admin_mfa_score), 2, len(privileged_missing), f"{len(privileged_missing)} de {len(privileged)} contas privilegiadas não possuem MFA registrado.", [f"Contas privilegiadas identificadas: {len(privileged)}", f"Administradores sem MFA: {len(privileged_missing)}"], "Aplicar MFA resistente a phishing para funções administrativas e revisar contas de emergência e exclusões.", "Identity / IAM", "Microsoft Graph directoryRoles + authenticationMethods", {"30": "Validar administradores e exceções break-glass.", "60": "Aplicar política de MFA resistente a phishing.", "90": "Revisar privilégios e manter monitoramento contínuo."}))
    else:
        put("ID-002", None, "low")
    put("ID-007", None, "low")
    if pim_summary:
        active = int(pim_summary.get("active", 0) or 0)
        eligible = int(pim_summary.get("eligible", 0) or 0)
        pim_score = round(eligible / (active + eligible) * 100) if active + eligible else None
        put("ID-009", pim_score, "medium")
        permanent_or_active = int(pim_summary.get("permanent_or_active", active) or 0)
        if permanent_or_active:
            findings.append(finding("ID-009", "Privilégios ativos ou permanentes exigem revisão de PIM", "high", 72, 3, active, f"Foram identificadas {active} atribuições ativas e {eligible} elegíveis no diretório.", [f"Atribuições ativas: {active}", f"Atribuições elegíveis: {eligible}"], "Priorizar acesso elegível, aprovação, duração limitada e revisão periódica no PIM.", "Identity / IAM", "Microsoft Graph roleManagement directory schedules", {"30": "Inventariar atribuições permanentes.", "60": "Migrar acessos aprovados para elegíveis.", "90": "Revisar ativações e owners periodicamente."}))
    else:
        put("ID-009", None, "low")
    if users:
        hygiene_score = round(max(0, len(users) - len(inactive)) / len(users) * 100)
        put("ID-008", hygiene_score, "medium")
        if inactive or guests:
            findings.append(finding("ID-008", "Contas inativas ou convidados precisam de governança", "medium", 58, 2, len(inactive) + len(guests), f"Foram identificadas {len(inactive)} contas sem atividade recente detectável e {len(guests)} convidados no inventário.", [f"Usuários avaliados: {len(users)}", f"Contas inativas/sem atividade: {len(inactive)}", f"Convidados: {len(guests)}"], "Validar owner, necessidade, expiração e revisão periódica de contas inativas e convidados.", "Identity / IAM", "Microsoft Graph users", {"30": "Validar contas inativas e convidados.", "60": "Aplicar expiração e revisão de acesso.", "90": "Automatizar governança de ciclo de vida."}))
    else:
        put("ID-008", None, "low")

    if resources:
        required = 0
        tagged = 0
        for item in resources:
            keys = {key.strip().lower() for key in str(item.get("tags", "")).split(",") if key.strip()}
            required += 1
            tagged += int({"owner", "env"}.issubset(keys))
        tag_score = round(tagged / required * 100)
        put("GOV-002", tag_score, "high")
        if tagged < required:
            findings.append(finding("GOV-002", "Recursos sem conjunto mínimo de tags", "medium", 52, 2, required - tagged, f"{required - tagged} recursos não demonstram as tags mínimas owner/env.", [f"Recursos avaliados: {required}", f"Recursos com owner e env: {tagged}"], "Definir taxonomia mínima e aplicar Azure Policy em modo audit antes de qualquer deny.", "Cloud Governance / FinOps", "Azure Resource Graph", {"30": "Definir taxonomia e owners.", "60": "Corrigir recursos prioritários.", "90": "Aplicar governança contínua."}))
    else:
        put("GOV-002", None, "low")
    management_groups = sum(1 for item in containers if "managementgroups" in str(item.get("type", "")).lower())
    subscriptions = sum(1 for item in containers if str(item.get("type", "")).lower().endswith("/subscriptions"))
    put("GOV-001", 85 if management_groups else (60 if subscriptions else (70 if resources else None)), "high" if containers else ("medium" if resources else "low"))
    if rbac:
        broad = sum(1 for item in rbac if str(item.get("role", "")).lower() in {"owner", "contributor", "user access administrator"})
        rbac_score = max(20, round((len(rbac) - broad) / len(rbac) * 100))
        put("GOV-003", rbac_score, "medium")
        if broad:
            findings.append(finding("GOV-003", "Atribuições RBAC amplas exigem revisão", "high", 74, 3, broad, f"{broad} atribuições com funções administrativas amplas foram identificadas.", [f"Atribuições avaliadas: {len(rbac)}", f"Funções amplas: {broad}"], "Validar necessidade, reduzir escopo e migrar acesso permanente para grupos/PIM quando aplicável.", "Cloud Platform / IAM", "AuthorizationResources / Azure Resource Graph", {"30": "Confirmar owners e justificativas.", "60": "Reduzir escopos excessivos.", "90": "Implantar revisão periódica e PIM."}))
    else:
        put("GOV-003", None, "low")
    public_resources = [item for item in resources if str(item.get("exposure", "")).lower().startswith("public")]
    if resources:
        public_score = max(20, round((len(resources) - len(public_resources)) / len(resources) * 100))
        put("GOV-004", public_score, "medium")
        if public_resources:
            findings.append(finding("GOV-004", "Recursos com exposição pública", "high", 82, 3, len(public_resources), f"{len(public_resources)} recursos possuem exposição pública ou rede pública a revisar.", [f"Recursos avaliados: {len(resources)}", f"Recursos públicos ou em revisão: {len(public_resources)}"], "Confirmar necessidade de negócio e priorizar Private Endpoint, firewall ou restrição de rede.", "Azure Platform / Networking", "Azure Resource Graph", {"30": "Confirmar owner e criticidade.", "60": "Corrigir exposições não justificadas.", "90": "Implantar revisão contínua."}))
    else:
        put("GOV-004", None, "low")
    if policy_rows:
        compliant = sum(1 for item in policy_rows if str(item.get("compliance_state", "")).lower() == "compliant")
        policy_score = round(compliant / len(policy_rows) * 100)
        put("GOV-005", policy_score, "high")
        put("GOV-006", policy_score, "high")
        non_compliant = len(policy_rows) - compliant
        if non_compliant:
            findings.append(finding("GOV-006", "Recursos ou estados não conformes com Azure Policy", "high", 70, 3, non_compliant, f"{non_compliant} registros de Policy não estão em estado compliant.", [f"Registros avaliados: {len(policy_rows)}", f"Registros não conformes: {non_compliant}"], "Classificar impacto, corrigir itens prioritários e documentar isenções aprovadas.", "Cloud Governance", "PolicyResources / Azure Resource Graph", {"30": "Classificar não conformidades.", "60": "Corrigir recursos prioritários.", "90": "Revisar assignments e exceções."}))
    else:
        put("GOV-005", None, "low")
        put("GOV-006", None, "low")
    if orphan_resources:
        put("COST-001", 45, "medium")
        findings.append(finding("COST-001", "Recursos órfãos com custo potencial", "medium", 62, 2, len(orphan_resources), f"{len(orphan_resources)} recursos foram classificados como potencialmente órfãos.", [f"Recursos órfãos: {len(orphan_resources)}"], "Validar owner, dependências, backup e custo antes de anexar, mover, reutilizar ou descomissionar.", "Cloud Governance / FinOps", "Azure Resource Graph + Cost Management", {"30": "Validar dependências e custo real.", "60": "Corrigir itens aprovados.", "90": "Implantar detecção periódica."}))
    else:
        put("COST-001", None, "low")
    if retirements:
        put("COST-002", 40, "medium")
        findings.append(finding("COST-002", "Avisos de ciclo de vida exigem acompanhamento", "high", 76, 4, len(retirements), f"{len(retirements)} avisos de Service Health relacionados ao ciclo de vida foram encontrados.", [f"Avisos encontrados: {len(retirements)}"], "Confirmar impacto por recurso, alternativa suportada e plano de migração.", "Cloud Governance + Owners", "ServiceHealthResources / Azure Resource Graph", {"30": "Confirmar escopo e responsáveis.", "60": "Executar atualização ou migração prioritária.", "90": "Implantar acompanhamento contínuo."}))
    else:
        put("COST-002", None, "low")
    if secure_scores:
        latest = secure_scores[0]
        current = float(latest.get("currentScore", 0) or 0)
        maximum = float(latest.get("maxScore", 0) or 0)
        secure_score = round(current / maximum * 100) if maximum else None
        put("SEC-001", secure_score, "high" if secure_score is not None else "low")
        if secure_score is not None and secure_score < 80:
            findings.append(finding("SEC-001", "Microsoft Secure Score abaixo do nível recomendado", "high" if secure_score < 60 else "medium", max(55, 100 - secure_score), 3, 1, f"O Secure Score atual representa {secure_score}% do máximo disponível na data da coleta.", [f"Score atual: {current:g}", f"Score máximo: {maximum:g}", f"Controles detalhados coletados: {len(secure_score_controls)}"], "Priorizar recomendações de maior impacto e menor esforço, validando dependências e licenciamento.", "Security / M365", "Microsoft Graph security/secureScores", {"30": "Classificar recomendações por impacto e esforço.", "60": "Implementar ações aprovadas de maior retorno.", "90": "Acompanhar evolução e exceções do Secure Score."}))
    else:
        put("SEC-001", None, "low")
    put("SEC-004", None, "low")
    if devices:
        non_compliant = sum(1 for item in devices if str(item.get("compliant", "")).lower() in {"false", "noncompliant", "not compliant"})
        unmanaged = sum(1 for item in devices if str(item.get("managed", "")).lower() in {"false", "unmanaged", "not managed"})
        posture_score = round(max(0, len(devices) - non_compliant - unmanaged) / len(devices) * 100)
        put("SEC-002", posture_score, "medium")
        if non_compliant or unmanaged:
            findings.append(finding("SEC-002", "Dispositivos sem postura adequada de endpoint", "high" if non_compliant else "medium", max(55, 100 - posture_score), 3, non_compliant + unmanaged, f"Foram identificados {non_compliant} dispositivos não conformes e {unmanaged} sem gerenciamento conhecido.", [f"Dispositivos avaliados: {len(devices)}", f"Não conformes: {non_compliant}", f"Não gerenciados: {unmanaged}"], "Validar inventário, aplicar políticas de conformidade e investigar dispositivos sem gerenciamento.", "Endpoint / Intune", "Microsoft Graph devices + Intune managedDevices", {"30": "Classificar dispositivos e responsáveis.", "60": "Corrigir conformidade e gerenciamento.", "90": "Implantar revisão contínua de endpoints."}))
    else:
        put("SEC-002", None, "low")
    if applications or registrations:
        credentialed = sum(1 for item in registrations if int(item.get("credentials", 0) or 0) > 0)
        expired_credentials = sum(int(item.get("expired_credentials", 0) or 0) for item in registrations)
        expiring_credentials = sum(int(item.get("expiring_30d", 0) or 0) for item in registrations)
        app_score = round(max(0, len(applications) + len(registrations) - credentialed) / max(1, len(applications) + len(registrations)) * 100)
        put("SEC-003", app_score, "medium")
        if credentialed:
            severity = "critical" if expired_credentials else ("high" if expiring_credentials else "medium")
            risk = 86 if expired_credentials else (74 if expiring_credentials else 60)
            findings.append(finding("SEC-003", "Aplicações com credenciais que exigem inventário", severity, risk, 3, credentialed, f"Foram identificadas {credentialed} aplicações registradas com credenciais cadastradas; {expired_credentials} possuem credenciais expiradas e {expiring_credentials} vencem em até 30 dias.", [f"Enterprise Applications: {len(applications)}", f"App registrations: {len(registrations)}", f"Registros com credenciais: {credentialed}", f"Credenciais expiradas: {expired_credentials}", f"Credenciais vencendo em 30 dias: {expiring_credentials}"], "Identificar owners, revisar expiração, preferir certificados ou workload identity e remover credenciais sem uso após validação.", "Application / IAM", "Microsoft Graph applications + servicePrincipals", {"30": "Inventariar owners e datas de expiração.", "60": "Rotacionar ou remover credenciais obsoletas.", "90": "Implantar governança contínua de aplicações."}))
    else:
        put("SEC-003", None, "low")
    if defender_summary and int(defender_summary.get("alerts", 0) or 0) > 0:
        alerts = int(defender_summary.get("alerts", 0) or 0)
        high_alerts = int(defender_summary.get("high", 0) or 0)
        put("SEC-005", max(20, round((alerts - high_alerts) / alerts * 100)), "medium")
        findings.append(finding("SEC-005", "Alertas do Defender requerem triagem", "critical" if high_alerts else "medium", 88 if high_alerts else 62, 3, alerts, f"O Defender retornou {alerts} alertas agregados, incluindo {high_alerts} de alta severidade.", [f"Alertas: {alerts}", f"Alta severidade: {high_alerts}", f"Ativos: {defender_summary.get('active', '—')}"], "Priorizar triagem dos alertas de alta severidade, validar incidentes e registrar exceções aprovadas.", "Security Operations", "Microsoft Graph security alerts", {"30": "Triar alertas críticos e confirmar incidentes.", "60": "Corrigir causas e ajustar detecções.", "90": "Acompanhar tendências e SLA de resposta."}))
    else:
        put("SEC-005", None, "low")

    # Garante que todos os controles catalogados apareçam no relatório.
    for item in catalog.get("controls", []):
        if item["id"] not in controls:
            put(item["id"], None, "low")
    data["controls"] = list(controls.values())
    data["findings"] = findings
    return data
