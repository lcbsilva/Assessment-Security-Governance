"""Gate final de prontidão para entrega consultiva.

Este gate é local e read-only. Ele não exige 100% de cobertura para considerar
uma execução tecnicamente válida, mas impede chamar de "pronta para entrega"
uma execução com erros de qualidade, integridade, contrato ou sem rastreabilidade
mínima das limitações.
"""

from __future__ import annotations

from collections import Counter
import argparse
import json
from pathlib import Path

import yaml

from executive_intelligence import build as build_executive_intelligence
from insight_engine import prioritize_findings
from quality_audit import audit


def assess(data: dict, catalog: dict, artifact_validation: dict | None = None) -> dict:
    quality = audit(data, catalog)
    metadata = data.get("metadata", {}) or {}
    logs = data.get("discovery", {}).get("collection_log", []) or []
    evidence = metadata.get("evidence_by_control", []) or []
    coverage_map = metadata.get("coverage_map", []) or []
    execution = metadata.get("execution", {}) or {}

    findings = prioritize_findings(
        data.get("findings", []) or [],
        metadata.get("evidence_quality", {}) or {},
        data.get("discovery", {}).get("lifecycle", {}).get("summary", {}).get("Custo mensal potencial", "Não quantificado"),
    )
    executive = build_executive_intelligence(findings)
    blockers: list[str] = []
    warnings: list[str] = []

    if quality.get("errors"):
        blockers.append("auditoria de qualidade contém erros bloqueantes")
    if execution and (execution.get("mode") != "read-only" or execution.get("tenant_mutation") is not False):
        blockers.append("execução não comprova modo read-only")
    if metadata.get("contract_status") != "valid":
        blockers.append("contrato normalizado não está explicitamente válido")
    if artifact_validation is not None and artifact_validation.get("status") != "valid":
        blockers.append("integridade dos artefatos não está válida")
    if not logs:
        blockers.append("manifesto de coleta ausente")
    if not evidence:
        blockers.append("rastreabilidade de evidência por controle ausente")
    if not coverage_map:
        warnings.append("coverage_map ausente; revisar rastreabilidade operacional antes da entrega")

    limited = [item for item in logs if item.get("status") in {"partial", "not_available", "error"}]
    undocumented = [
        item for item in limited
        if not item.get("note") and not item.get("likely_cause") and not item.get("next_step")
    ]
    if undocumented:
        blockers.append("há módulos limitados sem observação, causa provável ou próximo passo")

    conditional = executive["summary"]["conditional_review"]
    if conditional:
        warnings.append(f"{conditional} achado(s) permanecem condicionais e não devem ser apresentados como ação confirmada")

    statuses = Counter(str(item.get("status", "unknown")) for item in logs)
    ready = not blockers
    return {
        "status": "ready_for_client_review" if ready else "blocked",
        "read_only": execution.get("tenant_mutation") is False if execution else True,
        "quality_status": quality.get("status"),
        "artifact_integrity": (artifact_validation or {}).get("status", "not_checked"),
        "collection_status": dict(statuses),
        "controls_with_traceability": len(evidence),
        "coverage_rows": len(coverage_map),
        "executive_summary": executive["summary"],
        "blockers": blockers,
        "warnings": warnings,
        "delivery_principles": [
            "Ausência de evidência não é conformidade.",
            "Revisões condicionais não são ações confirmadas.",
            "Score provisório deve ser apresentado junto da cobertura.",
            "Remediação depende de validação de owner, escopo e mudança aprovada.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Valida prontidão final para revisão com cliente")
    parser.add_argument("--data", default="runtime/assessment.json")
    parser.add_argument("--artifact-validation", default=None)
    parser.add_argument("--output", default="runtime/delivery-gate.json")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    catalog = yaml.safe_load((root / "catalog" / "controls.yaml").read_text(encoding="utf-8"))
    data = json.loads(Path(options.data).read_text(encoding="utf-8"))
    artifact_validation = None
    if options.artifact_validation:
        artifact_validation = json.loads(Path(options.artifact_validation).read_text(encoding="utf-8"))
    result = assess(data, catalog, artifact_validation)
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Delivery gate: {result['status']}")
    if result["status"] == "blocked":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
