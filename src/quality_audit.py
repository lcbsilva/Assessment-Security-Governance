"""Auditoria pré-entrega do contrato e da qualidade da evidência.

Este módulo não acessa o tenant. Ele procura sinais de que o relatório pode
induzir uma conclusão indevida antes de ser entregue ao consultor ou cliente.
"""

from __future__ import annotations

from collections import Counter

from contract import EVIDENCE_STATES
from generate_report import calculate


def audit(data: dict, catalog: dict) -> dict:
    controls = data.get("controls", []) or []
    findings = data.get("findings", []) or []
    logs = data.get("discovery", {}).get("collection_log", []) or []
    errors: list[dict] = []
    warnings: list[dict] = []
    control_map = {item.get("id"): item for item in controls}

    for item in controls:
        control_id = item.get("id", "unknown")
        state = item.get("evidence_state")
        status = item.get("status")
        if state is None:
            warnings.append({"code": "LEGACY_EVIDENCE_STATE", "control_id": control_id, "message": "Controle não declara estado formal de evidência."})
        elif state not in EVIDENCE_STATES:
            errors.append({"code": "INVALID_EVIDENCE_STATE", "control_id": control_id, "message": "Estado de evidência inválido."})
        elif state == "CONFORMANT" and status != "pass":
            errors.append({"code": "CONTRADICTORY_EVIDENCE", "control_id": control_id, "message": "CONFORMANT exige status pass."})
        elif state == "NON_CONFORMANT" and status not in {"partial", "fail"}:
            errors.append({"code": "CONTRADICTORY_EVIDENCE", "control_id": control_id, "message": "NON_CONFORMANT exige status partial ou fail."})
        elif state == "INSUFFICIENT_EVIDENCE" and status not in {"not_available", "error"}:
            errors.append({"code": "CONTRADICTORY_EVIDENCE", "control_id": control_id, "message": "INSUFFICIENT_EVIDENCE exige status not_available ou error."})

    for item in findings:
        control_id = item.get("control_id", "unknown")
        evidence = item.get("evidence")
        if not evidence:
            errors.append({"code": "FINDING_WITHOUT_EVIDENCE", "control_id": control_id, "message": "Achado sem evidência textual."})
        linked = control_map.get(control_id, {})
        if linked.get("evidence_state") == "INSUFFICIENT_EVIDENCE":
            warnings.append({"code": "FINDING_LIMITED_EVIDENCE", "control_id": control_id, "message": "Achado relacionado a controle com evidência insuficiente; revisar antes da entrega."})
        if int(item.get("risk_score", 0) or 0) >= 80 and not item.get("limitations"):
            errors.append({"code": "HIGH_RISK_WITHOUT_LIMITATION", "control_id": control_id, "message": "Achado de alto risco sem limitação explícita."})

    failed_modules = [item for item in logs if item.get("status") in {"error", "not_available"}]
    if failed_modules:
        warnings.append({"code": "MODULE_LIMITATIONS", "count": len(failed_modules), "message": "Há módulos indisponíveis ou com erro; ausência não pode ser interpretada como conformidade."})

    domains, overall, coverage = calculate(catalog, data)
    low_coverage = [{"domain": item.get("name"), "coverage": item.get("coverage", 0)} for item in domains.values() if item.get("coverage", 0) < 50]
    for item in low_coverage:
        warnings.append({"code": "LOW_DOMAIN_COVERAGE", **item, "message": "Domínio com cobertura abaixo de 50%; score provisório."})

    statuses = Counter(str(item.get("status", "unknown")) for item in logs)
    return {
        "status": "blocked" if errors else "warning" if warnings else "pass",
        "errors": errors,
        "warnings": warnings,
        "metrics": {
            "controls": len(controls),
            "findings": len(findings),
            "overall_score": round(overall, 2) if overall is not None else None,
            "coverage": round(coverage, 2),
            "low_coverage_domains": len(low_coverage),
            "module_status_counts": dict(statuses),
        },
        "interpretation": "Revisão consultiva necessária antes da entrega." if errors or warnings else "Contrato sem sinais críticos de qualidade na validação local.",
        "read_only": True,
    }
