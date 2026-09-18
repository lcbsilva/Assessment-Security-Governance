#!/usr/bin/env python3
"""Prepara somente métricas agregadas para uma futura camada Azure OpenAI.

Este módulo é uma barreira explícita: não recebe nem repassa listas de usuários,
UPNs, nomes de recursos, IDs, e-mails ou evidências textuais potencialmente
identificáveis. A chamada ao modelo ainda não é feita por este MVP.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


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
    return {
        "purpose": "Executive summary for security and governance assessment",
        "engine_version": data.get("metadata", {}).get("engine_version", "unknown"),
        "modules": data.get("metadata", {}).get("modules", {}),
        "focus": data.get("metadata", {}).get("focus", {"primary_domains": ["security", "governance"]}),
        "scope_counts": {key: value for key, value in data.get("metadata", {}).get("scope", {}).items() if isinstance(value, (int, float))},
        "severity_counts": severity,
        "finding_count": len(findings),
        "financial_aggregates": {"cost_rows": len(cost_rows), "cost_total_period": round(total_cost, 2), "advisor_recommendations": len(advisor_rows), "advisor_annual_savings_published": round(advisor_savings, 2), "finops_summary": finops_aggregate},
        "domain_aggregates": domains,
        "cross_domain_insights": [{key: item.get(key) for key in ("id", "domain", "severity", "risk", "affected", "title")} for item in data.get("discovery", {}).get("cross_domain_insights", [])],
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
    result = build(json.loads(args.data.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Payload agregado para IA gravado em {args.output}")


if __name__ == "__main__":
    main()
