#!/usr/bin/env python3
"""Consolida a validação dos perfis de laboratório sem acessar o tenant."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROFILES = ("security", "governance", "full")


def profile_summary(pilot: dict, manifest: dict, preflight: dict | None = None, assessment: dict | None = None, delivery: dict | None = None) -> dict:
    """Reduz um perfil a um contrato operacional sem expor dados do tenant."""
    pilot_status = pilot.get("status", "unknown")
    artifact_status = manifest.get("status", "unknown")
    warnings = list(pilot.get("warnings", []))
    errors = list(pilot.get("errors", []))
    preflight_status = (preflight or {}).get("status", "not_available")
    delivery_status = (delivery or {}).get("status", "not_checked")
    blocked = preflight_status == "blocked" or pilot_status == "blocked" or artifact_status != "valid" or delivery_status == "blocked" or bool(errors)
    collection_log = (assessment or {}).get("discovery", {}).get("collection_log", [])
    collection_counts: dict[str, int] = {}
    collection_issues = []
    for entry in collection_log:
        status = str(entry.get("status", "unknown"))
        collection_counts[status] = collection_counts.get(status, 0) + 1
        if status in {"error", "not_available", "partial"}:
            # Deliberately omit note/details: they can contain tenant identifiers or other sensitive values.
            collection_issues.append({"module": entry.get("module", "unknown"), "status": status,
                                      "records": entry.get("records", 0)})
    if collection_issues:
        warnings.append("Há módulos de coleta indisponíveis, com erro ou parciais; consulte os detalhes localmente.")
    if blocked:
        readiness = "blocked"
    elif warnings or pilot.get("modules_unavailable_or_error", 0) or pilot.get("modules_partial", 0):
        readiness = "warning"
    else:
        readiness = "pass"
    metrics = pilot.get("quality_audit", {}).get("metrics", {})
    provisional = bool(collection_issues or pilot.get("modules_unavailable_or_error", 0) or pilot.get("modules_partial", 0))
    return {
        "readiness": readiness,
        "preflight": preflight_status,
        "pilot_status": pilot_status,
        "artifact_integrity": artifact_status,
        "delivery_gate": delivery_status,
        "coverage": metrics.get("coverage"),
        "control_coverage_percent": metrics.get("coverage"),
        "overall_score": metrics.get("overall_score"),
        "score_is_provisional": provisional,
        "score_interpretation": "Score baseado nas evidências disponíveis; módulos ausentes/parciais podem alterar a leitura." if provisional else "Score baseado nas evidências coletadas; considerar o escopo e limitações do perfil.",
        "collection_status_counts": collection_counts,
        "collection_issues": collection_issues,
        "modules_unavailable_or_error": pilot.get("modules_unavailable_or_error", 0),
        "modules_partial": pilot.get("modules_partial", 0),
        "modules_not_run": pilot.get("modules_not_run", 0),
        "warnings": len(warnings),
        "errors": len(errors),
    }


def summarize(root: Path) -> dict:
    summary = {"summary_version": "1.0", "read_only": True, "overall_status": "pass", "profiles": {}}
    for profile in PROFILES:
        pilot_path = root / profile / "pilot-validation.json"
        manifest_path = root / profile / "manifest-validation.json"
        preflight_path = root / profile / "preflight.json"
        assessment_path = root / profile / "assessment.json"
        delivery_path = root / profile / "delivery-gate.json"
        if not pilot_path.exists() or not manifest_path.exists():
            summary["profiles"][profile] = {"readiness": "not_run", "pilot_status": "not_run", "artifact_integrity": "not_run"}
            continue
        pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        preflight = json.loads(preflight_path.read_text(encoding="utf-8")) if preflight_path.exists() else None
        assessment = json.loads(assessment_path.read_text(encoding="utf-8")) if assessment_path.exists() else None
        delivery = json.loads(delivery_path.read_text(encoding="utf-8")) if delivery_path.exists() else None
        summary["profiles"][profile] = profile_summary(pilot, manifest, preflight, assessment, delivery)
    readiness = [item["readiness"] for item in summary["profiles"].values()]
    if all(status == "not_run" for status in readiness):
        summary["overall_status"] = "not_run"
    elif "blocked" in readiness:
        summary["overall_status"] = "blocked"
    elif "warning" in readiness or "not_run" in readiness:
        summary["overall_status"] = "warning"
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolida validação de laboratório")
    parser.add_argument("--root", type=Path, default=Path("runtime/lab-validation"))
    parser.add_argument("--output", type=Path, default=Path("runtime/lab-validation/summary.json"))
    args = parser.parse_args()
    result = summarize(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Resumo de laboratório gravado em {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
