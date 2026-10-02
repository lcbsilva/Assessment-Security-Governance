#!/usr/bin/env python3
"""Valida se uma execução está pronta para revisão de piloto."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from ai_payload import build, privacy_violations
from contract import validate_payload
from quality_audit import audit
from review_checklist import build as build_review_checklist

ROOT = Path(__file__).resolve().parents[1]


def validate(data: dict, catalog: dict, manifest_validation: dict | None = None) -> dict:
    errors = validate_payload(data, catalog)
    warnings: list[str] = []
    metadata = data.get("metadata", {})
    discovery = data.get("discovery", {})
    for path, value in (("metadata.scope", metadata.get("scope")), ("metadata.modules", metadata.get("modules")), ("discovery.collection_log", discovery.get("collection_log"))):
        if value in (None, {}, []):
            warnings.append(f"{path} ausente ou vazio; confirmar cobertura antes da entrega ao cliente")
    execution = data.get("metadata", {}).get("execution", {})
    if execution.get("mode") not in {None, "read-only"}:
        errors.append("execução não está em modo read-only")
    if execution and execution.get("tenant_mutation") is not False:
        errors.append("metadata.execution.tenant_mutation deve ser false")
    logs = discovery.get("collection_log", [])
    unavailable = sum(1 for item in logs if item.get("status") in {"not_available", "error"})
    partial = sum(1 for item in logs if item.get("status") == "partial")
    not_run = sum(1 for item in logs if item.get("status") == "not_run")
    ai_warnings = [f"payload de IA contém {item}" for item in privacy_violations(build(data))]
    if metadata.get("simulation", {}).get("is_simulation") is True:
        warnings.append("execução marcada como sintética; não usar como evidência de cliente")
    if metadata.get("contract_status") == "invalid":
        errors.append("metadata.contract_status não está validado; entrega bloqueada")
    quality = audit(data, catalog)
    errors.extend(item["message"] for item in quality["errors"])
    warnings.extend(item["message"] for item in quality["warnings"])
    if manifest_validation is not None and manifest_validation.get("status") != "valid":
        errors.append("validação de integridade dos artefatos falhou")
    checklist = build_review_checklist(data, errors, ai_warnings, quality, manifest_validation)
    return {
        "status": "blocked" if errors or ai_warnings else "ready_for_pilot_review",
        "contract_status": data.get("metadata", {}).get("contract_status", "unknown"),
        "read_only": execution.get("tenant_mutation") is False if execution else True,
        "modules_unavailable_or_error": unavailable,
        "modules_partial": partial,
        "modules_not_run": not_run,
        "collection_records": len(logs),
        "ai_warnings": sorted(set(ai_warnings)),
        "quality_audit": quality,
        "confidence": {
            "score": data.get("metadata", {}).get("execution_health", {}).get("confidence_score", 0),
            "band": data.get("metadata", {}).get("execution_health", {}).get("confidence_band", "baixa"),
            "basis": data.get("metadata", {}).get("execution_health", {}).get("confidence_basis", "Não informado"),
        },
        "artifact_integrity": manifest_validation or {"status": "not_checked", "read_only": True},
        "review_checklist": checklist,
        "errors": errors,
        "warnings": sorted(set(warnings)),
        "acceptance": {"contract_valid": not any("contract" in item.lower() for item in errors), "read_only": execution.get("tenant_mutation") is False if execution else True, "evidence_manifest_present": bool(logs), "ai_clean": not ai_warnings},
        "limitations": ["Pronto para revisão técnica; não substitui validação do owner do cliente.", "Módulos not_available/partial devem ser apresentados explicitamente no relatório.", "Módulos not_run representam escopo não selecionado e não devem ser interpretados como falha ou conformidade.", "Warnings exigem revisão consultiva, mas não autorizam remediação automática."],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Valida uma execução do assessment antes do piloto")
    parser.add_argument("--data", default="runtime/assessment.json")
    parser.add_argument("--output", default="runtime/pilot-validation.json")
    parser.add_argument("--manifest-validation", default=None, help="JSON produzido por validate_manifest.py")
    options = parser.parse_args()
    catalog = yaml.safe_load((ROOT / "catalog" / "controls.yaml").read_text(encoding="utf-8"))
    manifest_validation = None
    if options.manifest_validation:
        manifest_validation = json.loads(Path(options.manifest_validation).read_text(encoding="utf-8"))
    result = validate(json.loads(Path(options.data).read_text(encoding="utf-8")), catalog, manifest_validation)
    Path(options.output).parent.mkdir(parents=True, exist_ok=True)
    Path(options.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Validação do piloto: {result['status']}")
    if result["status"] == "blocked":
        raise SystemExit(2)


if __name__ == "__main__":
    main()

