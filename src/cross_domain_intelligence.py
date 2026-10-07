"""Correlação consultiva entre domínios usando somente evidência coletada.

Não altera score, controles ou severidade dos achados de origem. Cada insight
expõe as condições observadas e preserva limitações de cobertura.
"""

from __future__ import annotations


LIMITED = {"partial", "not_available", "error"}


def _limited_modules(collection_log: list[dict]) -> set[str]:
    return {
        str(item.get("module", "")).lower()
        for item in collection_log or []
        if str(item.get("status", "")).lower() in LIMITED
    }


def build(discovery: dict, collection_log: list[dict]) -> list[dict]:
    security = discovery.get("security_identity_intelligence", {}) or {}
    identity = security.get("identity_posture", {}) or {}
    privileged = security.get("privileged_access", {}) or {}
    lifecycle = discovery.get("lifecycle_finops", {}) or {}
    signals = lifecycle.get("signals", {}) or {}
    optimization = lifecycle.get("optimization", {}) or {}
    limited = _limited_modules(collection_log)
    insights: list[dict] = []

    if int(privileged.get("broad_scope_assignments", 0) or 0) > 0 and int(identity.get("privileged_without_mfa", 0) or 0) > 0:
        insights.append({
            "id": "XDI-001",
            "title": "Acesso privilegiado amplo combinado com lacuna de MFA",
            "domains": ["Identity & Access", "Security"],
            "severity": "high",
            "risk": 85,
            "priority": "P1",
            "affected": max(int(privileged.get("broad_scope_assignments", 0) or 0), int(identity.get("privileged_without_mfa", 0) or 0)),
            "suggested_owner": "Identity & Access",
            "evidence": ["broad_scope_assignments", "privileged_without_mfa"],
            "interpretation": "Priorizar revisão contextual de contas e escopos; a correlação não prova comprometimento nem excesso de privilégio.",
        })

    orphan_count = int(signals.get("orphan_resources", 0) or 0)
    rightsize = int(optimization.get("rightsizing_candidates", 0) or 0)
    if orphan_count > 0 and rightsize > 0:
        insights.append({
            "id": "XDI-002",
            "title": "Oportunidade conjunta de higiene de recursos e otimização FinOps",
            "domains": ["Cloud Governance", "FinOps"],
            "severity": "medium",
            "risk": 65,
            "priority": "P2",
            "affected": orphan_count + rightsize,
            "suggested_owner": "FinOps & Cloud Governance",
            "evidence": ["orphan_resources", "rightsizing_candidates"],
            "interpretation": "Fila de investigação; não representa economia realizável nem autorização para excluir ou redimensionar recursos.",
        })

    anomaly_days = int(optimization.get("anomaly_days", 0) or 0)
    if anomaly_days > 0 and int(signals.get("advisor_recommendations", 0) or 0) > 0:
        insights.append({
            "id": "XDI-003",
            "title": "Anomalia de custo com recomendações de otimização disponíveis",
            "domains": ["FinOps", "Cloud Governance"],
            "severity": "medium",
            "risk": 60,
            "priority": "P2",
            "affected": anomaly_days,
            "suggested_owner": "FinOps",
            "evidence": ["anomaly_days", "advisor_recommendations"],
            "interpretation": "Usar como ponto de investigação financeira; não atribui causalidade da anomalia às recomendações do Advisor.",
        })

    if limited:
        for item in insights:
            item["coverage_guardrail"] = "Há módulos limitados nesta execução; validar cobertura das fontes relacionadas antes de transformar a correlação em plano de mudança."
            item["limited_modules_present"] = True
    else:
        for item in insights:
            item["coverage_guardrail"] = "Correlação baseada somente nas evidências coletadas; validar owner, escopo e contexto antes de remediar."
            item["limited_modules_present"] = False
    return insights
