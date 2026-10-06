"""Camada de decisão para identidade privilegiada e segurança.

Usa apenas evidência já coletada. Ausência de dados não é tratada como ausência de risco.
"""

from __future__ import annotations
from collections import Counter


def build(discovery: dict, collection_log: list[dict]) -> dict:
    rbac = discovery.get("rbac", []) or []
    pim = discovery.get("pim_assignments", []) or []
    alerts = discovery.get("defender_alerts", []) or []
    vulnerabilities = discovery.get("defender_vulnerabilities", []) or []
    secure_scores = discovery.get("secure_score", []) or []

    unavailable = {
        str(item.get("module", "")).lower(): item
        for item in collection_log
        if str(item.get("status")) in {"not_available", "partial", "error"}
    }

    privileged = [
        item for item in rbac
        if str(item.get("access_risk")) in {"Crítico", "Alto"}
    ]
    broad_scope = [
        item for item in privileged
        if str(item.get("scope_kind", "")).lower() in {"subscription", "management_group", "tenant", "root"}
        or str(item.get("assignment_scope", "")).count("/") <= 2
    ]
    active_pim = [item for item in pim if str(item.get("assignment_type", "")).lower() == "active"]
    eligible_pim = [item for item in pim if str(item.get("assignment_type", "")).lower() == "eligible"]

    alert_severity = Counter(str(item.get("severity", "unknown")).lower() for item in alerts)
    vuln_severity = Counter(str(item.get("severity", "unknown")).lower() for item in vulnerabilities)

    return {
        "privileged_access": {
            "high_or_critical_assignments": len(privileged),
            "broad_scope_assignments": len(broad_scope),
            "pim_active": len(active_pim),
            "pim_eligible": len(eligible_pim),
            "interpretation": "Inventário para revisão; não prova excesso de privilégio sem contexto de função, owner e necessidade.",
        },
        "defender": {
            "alerts": len(alerts),
            "alert_severity": dict(alert_severity),
            "vulnerabilities": len(vulnerabilities),
            "vulnerability_severity": dict(vuln_severity),
            "interpretation": "Contagens refletem somente a cobertura efetivamente coletada; zero não implica ambiente sem alertas ou vulnerabilidades.",
        },
        "secure_score": {
            "records": len(secure_scores),
            "interpretation": "Secure Score é sinal de postura e priorização, não certificação de conformidade.",
        },
        "coverage_limitations": [
            {"module": item.get("module"), "status": item.get("status"), "note": item.get("note")}
            for item in unavailable.values()
            if any(token in str(item.get("module", "")).lower() for token in ("pim", "defender", "secure score", "rbac", "identity"))
        ],
        "guardrails": [
            "Não ampliar permissões apenas para eliminar uma lacuna de coleta; validar endpoint, licença e necessidade primeiro.",
            "Não interpretar zero registros como ausência de risco quando o módulo estiver partial, not_available ou error.",
            "Remediação de acesso privilegiado exige owner, impacto, break-glass e mudança aprovada.",
        ],
    }
