"""Camada de decisão para identidade privilegiada e segurança.

Usa apenas evidência já coletada. Ausência de dados não é tratada como ausência de risco.
"""

from __future__ import annotations
from collections import Counter


_UNAVAILABLE = {"not_available", "error"}


def _source_status(collection_log: list[dict], module_names: tuple[str, ...]) -> str:
    """Retorna o estado da fonte; o erro global do Graph limita seus módulos."""
    names = tuple(name.lower() for name in module_names)
    matching = [
        str(item.get("status", "unknown")).lower()
        for item in collection_log
        if any(name in str(item.get("module", "")).lower() for name in names)
    ]
    if any(status == "error" for status in matching):
        return "error"
    if any(status == "not_available" for status in matching):
        return "not_available"
    if any(status == "partial" for status in matching):
        return "partial"
    if any(status == "success" for status in matching):
        return "success"

    graph_statuses = [
        str(item.get("status", "unknown")).lower()
        for item in collection_log
        if "graph" in str(item.get("module", "")).lower()
    ]
    if any(status in _UNAVAILABLE for status in graph_statuses):
        return "error" if "error" in graph_statuses else "not_available"
    if any(status == "partial" for status in graph_statuses):
        return "partial"
    if any(status == "success" for status in graph_statuses):
        return "success"
    return "unknown"


def _observed_count(items: list, source_status: str) -> int | None:
    # Contagem positiva é evidência observada mesmo em coleta parcial. Lista vazia
    # só pode virar zero quando a fonte confirmou coleta bem-sucedida.
    if items or source_status == "success":
        return len(items)
    return None


def build(discovery: dict, collection_log: list[dict]) -> dict:
    rbac = discovery.get("rbac", []) or []
    pim = discovery.get("pim_assignments", []) or []
    alerts = discovery.get("defender_alerts", []) or []
    vulnerabilities = discovery.get("defender_vulnerabilities", []) or []
    secure_scores = discovery.get("secure_score", []) or []
    users = discovery.get("users", []) or []
    conditional_access = discovery.get("conditional_access", []) or []
    identity_risks = discovery.get("identity_risks", []) or []

    unavailable = {
        str(item.get("module", "")).lower(): item
        for item in collection_log
        if str(item.get("status")) in {"not_available", "partial", "error"}
    }

    identity_status = _source_status(collection_log, ("identity", "mfa", "conditional access"))
    defender_status = _source_status(collection_log, ("defender", "secure score"))
    rbac_status = _source_status(collection_log, ("rbac", "privileged", "pim"))

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

    privileged_users = [item for item in users if item.get("privileged") is True]
    privileged_without_mfa = [item for item in privileged_users if str(item.get("mfa_status", "")).lower() in {"not registered", "disabled", "false"}]
    risky_users = [item for item in identity_risks if str(item.get("risk_level", "")).lower() in {"high", "medium"}]
    ca_enabled = [item for item in conditional_access if str(item.get("state", "")).lower() in {"enabled", "on"}]
    ca_report_only = [item for item in conditional_access if "report" in str(item.get("state", "")).lower()]

    alert_severity = Counter(str(item.get("severity", "unknown")).lower() for item in alerts)
    vuln_severity = Counter(str(item.get("severity", "unknown")).lower() for item in vulnerabilities)

    return {
        "privileged_access": {
            "high_or_critical_assignments": _observed_count(privileged, rbac_status),
            "broad_scope_assignments": _observed_count(broad_scope, rbac_status),
            "pim_active": _observed_count(active_pim, rbac_status),
            "pim_eligible": _observed_count(eligible_pim, rbac_status),
            "evidence_status": rbac_status,
            "interpretation": "Inventário para revisão; não prova excesso de privilégio sem contexto de função, owner e necessidade.",
        },
        "identity_posture": {
            "privileged_users": _observed_count(privileged_users, identity_status),
            "privileged_without_mfa": _observed_count(privileged_without_mfa, identity_status),
            "risky_users_high_or_medium": _observed_count(risky_users, identity_status),
            "conditional_access_enabled": _observed_count(ca_enabled, identity_status),
            "conditional_access_report_only": _observed_count(ca_report_only, identity_status),
            "evidence_status": identity_status,
            "interpretation": "Correlação consultiva sobre evidências coletadas; não presume incidente, comprometimento ou eficácia de política sem validação contextual.",
        },
        "defender": {
            "alerts": _observed_count(alerts, defender_status),
            "alert_severity": dict(alert_severity),
            "vulnerabilities": _observed_count(vulnerabilities, defender_status),
            "vulnerability_severity": dict(vuln_severity),
            "evidence_status": defender_status,
            "interpretation": "Contagens refletem somente a cobertura efetivamente coletada; zero não implica ambiente sem alertas ou vulnerabilidades.",
        },
        "secure_score": {
            "records": _observed_count(secure_scores, defender_status),
            "evidence_status": defender_status,
            "interpretation": "Secure Score é sinal de postura e priorização, não certificação de conformidade.",
        },
        "coverage_limitations": [
            {"module": item.get("module"), "status": item.get("status"), "note": item.get("note")}
            for item in unavailable.values()
            if any(token in str(item.get("module", "")).lower() for token in ("pim", "defender", "secure score", "rbac", "identity", "graph", "mfa", "conditional access"))
        ],
        "guardrails": [
            "Não ampliar permissões apenas para eliminar uma lacuna de coleta; validar endpoint, licença e necessidade primeiro.",
            "Não interpretar zero registros como ausência de risco quando o módulo estiver partial, not_available ou error.",
            "Remediação de acesso privilegiado exige owner, impacto, break-glass e mudança aprovada.",
        ],
    }
