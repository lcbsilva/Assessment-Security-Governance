#!/usr/bin/env python3
"""Prepara somente métricas agregadas para uma futura camada Azure OpenAI.

Este módulo é uma barreira explícita: não recebe nem repassa listas de usuários,
UPNs, nomes de recursos, IDs, e-mails ou evidências textuais potencialmente
identificáveis. A chamada ao modelo ainda não é feita por este MVP.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from local_privacy import protect_output_parent


SENSITIVE_KEYS = {
    "upn", "email", "mail", "userprincipalname", "userid", "objectid",
    "principalid", "principalname", "resourceid", "subscriptionid", "tenantid",
    "appid", "clientid", "ipaddress", "ipaddr", "displayname", "secret",
    "secretvalue", "token", "password", "privatekey", "connectionstring",
}
SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?i)/subscriptions/[0-9a-f-]{36}/resourcegroups/"),
    re.compile(r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
)


def privacy_violations(payload: object) -> list[str]:
    """Procura identificadores, endereços e segredos em chaves e valores."""
    violations: set[str] = set()

    def visit(value: object, path: str = "payload") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized in SENSITIVE_KEYS or any(token in normalized for token in ("secret", "password", "privatekey", "connectionstring")):
                    violations.add(f"campo sensível: {path}.{key}")
                visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        elif isinstance(value, str):
            for pattern in SENSITIVE_VALUE_PATTERNS:
                if pattern.search(value):
                    violations.add(f"padrão identificável ou segredo em {path}")
                    break

    visit(payload)
    return sorted(violations)


def build(data: dict) -> dict:
    findings = data.get("findings", [])
    domains = {}
    for item in findings:
        control = item.get("control_id", "unknown").split("-")[0]
        entry = domains.setdefault(control, {"findings": 0, "max_risk": 0, "affected_total": 0})
        entry["findings"] += 1
        entry["max_risk"] = max(entry["max_risk"], int(item.get("risk_score", 0) or 0))
        entry["affected_total"] += int(item.get("affected", 0) or 0)
    severity = {level: sum(1 for item in findings if item.get("severity") == level) for level in ("critical", "high", "medium", "low")}
    cost_rows = data.get("discovery", {}).get("cost_summary", [])
    total_cost = 0.0
    for row in cost_rows:
        try:
            total_cost += float(row.get("PreTaxCost", 0) or 0)
        except (TypeError, ValueError):
            pass
    advisor_rows = data.get("discovery", {}).get("lifecycle", {}).get("advisor_recommendations", [])
    advisor_savings = 0.0
    for row in advisor_rows:
        try:
            advisor_savings += float(row.get("annual_savings", 0) or 0)
        except (TypeError, ValueError):
            pass
    finops = data.get("discovery", {}).get("finops_summary", {})
    finops_aggregate = {
        "cost_total_period": finops.get("cost_total_period", 0),
        "currency": finops.get("currency", "—"),
        "resource_groups_count": finops.get("resource_groups", 0),
        "resource_types_count": finops.get("resource_types", 0),
        "anomaly_days_count": len((finops.get("anomalies") or {}).get("anomaly_days", [])),
        "reservations_status": finops.get("reservations", "Não quantificado"),
        "savings_plans_status": finops.get("savings_plans", "Não quantificado"),
        "reservation_inventory_count": (data.get("discovery", {}).get("benefits_summary", {}) or {}).get("reservations", 0),
        "savings_plan_inventory_count": (data.get("discovery", {}).get("benefits_summary", {}) or {}).get("savings_plans", 0),
    }
    posture = data.get("discovery", {}).get("security_posture_summary", {}) or {}
    posture_aggregate = {
        "resources_assessed": int(posture.get("resources", 0) or 0),
        "resources_with_explicit_signals": int(posture.get("resources_with_explicit_signals", 0) or 0),
        "signals_total": int(posture.get("signals_total", 0) or 0),
        "signals": [
            {"signal": item.get("signal", "—"), "resources": int(item.get("resources", 0) or 0)}
            for item in posture.get("by_signal", [])
            if isinstance(item, dict)
        ],
        "interpretation": "Sinais explícitos para priorização de revisão; ausência de sinal não é conformidade.",
    }
    evidence_quality = data.get("metadata", {}).get("evidence_quality", {}) or {}
    rbac = data.get("discovery", {}).get("rbac_summary", {}) or {}
    rbac_aggregate = {
        "assignments": int(rbac.get("assignments", 0) or 0),
        "high_risk_assignments": int(rbac.get("high_risk_assignments", 0) or 0),
        "critical_assignments": int(rbac.get("critical_assignments", 0) or 0),
        "permanent_or_unknown_assignments": int(rbac.get("permanent_or_unknown_assignments", 0) or 0),
        "by_scope": [
            {"scope_kind": item.get("scope_kind", "—"), "assignments": int(item.get("assignments", 0) or 0)}
            for item in rbac.get("by_scope", [])
            if isinstance(item, dict)
        ],
        "interpretation": "Resumo de atribuições observadas; não representa uso efetivo nem herança completa.",
    }
    governance = data.get("discovery", {}).get("governance_summary", {}) or {}
    governance_aggregate = {key: governance.get(key) for key in ("resources_assessed", "without_owner", "without_environment_tag", "without_tags", "policy_evaluated", "policy_non_compliant", "policy_compliance_rate")}
    governance_aggregate["interpretation"] = "Indicadores agregados para priorização; ausência de tag ou Policy não prova risco isoladamente."
    return {
        "purpose": "Executive summary for security and governance assessment",
        "engine_version": data.get("metadata", {}).get("engine_version", "unknown"),
        "modules": data.get("metadata", {}).get("modules", {}),
        "focus": data.get("metadata", {}).get("focus", {"primary_domains": ["security", "governance"]}),
        "scope_counts": {key: value for key, value in data.get("metadata", {}).get("scope", {}).items() if isinstance(value, (int, float))},
        "severity_counts": severity,
        "finding_count": len(findings),
        "evidence_quality": {key: evidence_quality.get(key) for key in ("score", "success", "partial", "not_available", "error", "not_run") if key in evidence_quality},
        "coverage": data.get("metadata", {}).get("coverage", "Não calculada"),
        "azure_security_posture": posture_aggregate,
        "azure_rbac_posture": rbac_aggregate,
        "azure_governance_posture": governance_aggregate,
        "financial_aggregates": {"cost_rows": len(cost_rows), "cost_total_period": round(total_cost, 2), "advisor_recommendations": len(advisor_rows), "advisor_annual_savings_published": round(advisor_savings, 2), "finops_summary": finops_aggregate},
        "domain_aggregates": domains,
        "cross_domain_insights": [{key: item.get(key) for key in ("id", "domain", "severity", "risk", "affected", "title", "priority", "suggested_owner", "effort_band")} for item in data.get("discovery", {}).get("cross_domain_insights", [])],
        "ecosystem_aggregates": {
            "power_platform": {key: value for key, value in (data.get("discovery", {}).get("power_platform_summary", {}) or {}).items() if key not in {"by_environment", "by_kind"}},
            "azure_devops": data.get("discovery", {}).get("azure_devops_summary", {}),
            "analytics": data.get("discovery", {}).get("analytics_summary", {}),
            "licenses": {key: value for key, value in (data.get("discovery", {}).get("license_summary", {}) or {}).items() if key != "skus"},
            "directory_audit": {key: value for key, value in (data.get("discovery", {}).get("directory_audit_summary", {}) or {}).items() if key != "categories"},
            "m365_domain_posture": data.get("discovery", {}).get("m365_summary", {}),
        },
        "limitations": ["Use only aggregated metrics. Do not infer individual identity, blame or incident occurrence from these values."],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera payload agregado e seguro para IA")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    protect_output_parent(args.output)
    result = build(json.loads(args.data.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Payload agregado para IA gravado em {args.output}")


if __name__ == "__main__":
    main()
