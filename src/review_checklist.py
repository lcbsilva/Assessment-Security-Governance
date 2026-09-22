"""Checklist automático de revisão antes da entrega do assessment.

Não acessa o tenant. Converte o contrato e os sinais de qualidade em uma
decisão operacional: pronto para revisão, revisar limitações ou bloqueado.
"""

from __future__ import annotations


def _check(name: str, status: str, detail: str, blocking: bool = False) -> dict:
    return {"name": name, "status": status, "detail": detail, "blocking": blocking}


def build(data: dict, contract_errors: list[str] | None = None, ai_warnings: list[str] | None = None, quality: dict | None = None, manifest_validation: dict | None = None) -> dict:
    metadata = data.get("metadata", {}) or {}
    execution = metadata.get("execution", {}) or {}
    health = metadata.get("execution_health", {}) or {}
    quality = quality or {}
    contract_errors = contract_errors or []
    ai_warnings = ai_warnings or []
    checks = [
        _check("read_only", "pass" if execution.get("tenant_mutation") is False else "block", "Execução sem mutação no tenant." if execution.get("tenant_mutation") is False else "metadata.execution.tenant_mutation não é false.", execution.get("tenant_mutation") is not False),
        _check("contract", "pass" if not contract_errors and metadata.get("contract_status") == "valid" else "block", "Contrato validado." if not contract_errors and metadata.get("contract_status") == "valid" else "Contrato ausente, inválido ou não validado.", bool(contract_errors) or metadata.get("contract_status") != "valid"),
        _check("evidence_manifest", "pass" if data.get("discovery", {}).get("collection_log") else "block", "Manifesto de coleta presente." if data.get("discovery", {}).get("collection_log") else "Manifesto de coleta ausente.", not bool(data.get("discovery", {}).get("collection_log"))),
        _check("ai_payload", "pass" if not ai_warnings else "block", "Payload agregado sem padrões proibidos." if not ai_warnings else "Payload de IA contém padrões proibidos.", bool(ai_warnings)),
        _check("coverage", "pass" if float(metadata.get("coverage", 0) or 0) >= 80 else "warning", f"Cobertura de controles: {metadata.get('coverage', 0)}%.", False),
        _check("execution_limitations", "pass" if not health.get("status_counts", {}).get("error") and not health.get("status_counts", {}).get("not_available") else "warning", "Sem indisponibilidades críticas." if not health.get("status_counts", {}).get("error") and not health.get("status_counts", {}).get("not_available") else "Existem módulos indisponíveis ou com erro; revisar impacto no relatório.", False),
    ]
    conditional = sum(1 for item in data.get("findings", []) if item.get("priority_eligibility") == "conditional_review" or str(item.get("evidence_state", "")).upper() == "INSUFFICIENT_EVIDENCE")
    checks.append(_check("conditional_findings", "warning" if conditional else "pass", f"{conditional} achado(s) dependem de validação adicional." if conditional else "Não há achados condicionais.", False))
    if manifest_validation is not None:
        manifest_ok = manifest_validation.get("status") == "valid" and manifest_validation.get("read_only") is True
        checks.append(_check("artifact_integrity", "pass" if manifest_ok else "block", "Hashes do manifesto conferidos." if manifest_ok else "Hashes do manifesto ausentes ou divergentes.", not manifest_ok))
    else:
        checks.append(_check("artifact_integrity", "warning", "Validação de hashes não foi executada nesta chamada.", False))
    blocking = sum(1 for item in checks if item["status"] == "block")
    warnings = sum(1 for item in checks if item["status"] == "warning")
    return {
        "status": "blocked" if blocking else "warning" if warnings else "pass",
        "checks": checks,
        "blocking": blocking,
        "warnings": warnings,
        "recommendation": "Não entregar até corrigir bloqueios." if blocking else "Pronto para revisão consultiva." if warnings else "Pronto para revisão técnica.",
        "read_only": execution.get("tenant_mutation") is False,
    }
