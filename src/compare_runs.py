#!/usr/bin/env python3
"""Compara duas execuções normalizadas sem acessar ou alterar o tenant."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def compare(previous: dict, current: dict) -> dict:
    previous_controls = {item.get("id"): item for item in previous.get("controls", [])}
    current_controls = {item.get("id"): item for item in current.get("controls", [])}
    controls = []
    comparable_ids = []
    for control_id in sorted(set(previous_controls) | set(current_controls)):
        old = previous_controls.get(control_id, {})
        new = current_controls.get(control_id, {})
        old_score = old.get("score") if old.get("status") not in {"not_available", "error"} else None
        new_score = new.get("score") if new.get("status") not in {"not_available", "error"} else None
        controls.append({"id": control_id, "previous_score": old_score, "current_score": new_score, "delta": round(new_score - old_score, 2) if old_score is not None and new_score is not None else None, "previous_status": old.get("status", "missing"), "current_status": new.get("status", "missing")})
        if old_score is not None and new_score is not None:
            comparable_ids.append(control_id)
    old_findings = {item.get("control_id") for item in previous.get("findings", [])}
    new_findings = {item.get("control_id") for item in current.get("findings", [])}
    old_scope = previous.get("metadata", {}).get("scope", {})
    new_scope = current.get("metadata", {}).get("scope", {})
    previous_coverage = previous.get("metadata", {}).get("coverage")
    current_coverage = current.get("metadata", {}).get("coverage")
    comparable_deltas = [item["delta"] for item in controls if item["id"] in comparable_ids and item["delta"] is not None]
    return {
        "previous_run_id": previous.get("metadata", {}).get("run_id", "unknown"),
        "current_run_id": current.get("metadata", {}).get("run_id", "unknown"),
        "overall_score": {"previous": previous.get("metadata", {}).get("overall_score"), "current": current.get("metadata", {}).get("overall_score")},
        "coverage": {"previous": previous_coverage, "current": current_coverage, "delta": round(current_coverage - previous_coverage, 2) if isinstance(previous_coverage, (int, float)) and isinstance(current_coverage, (int, float)) else None},
        "comparability": {
            "comparable_controls": len(comparable_ids),
            "comparable_control_ids": comparable_ids,
            "average_delta_on_overlap": round(sum(comparable_deltas) / len(comparable_deltas), 2) if comparable_deltas else None,
            "coverage_changed": previous_coverage != current_coverage,
            "status": "comparable_with_coverage_change" if previous_coverage != current_coverage else "comparable",
        },
        "scope_delta": {key: new_scope.get(key, 0) - old_scope.get(key, 0) for key in set(old_scope) | set(new_scope) if isinstance(old_scope.get(key, 0), (int, float)) and isinstance(new_scope.get(key, 0), (int, float))},
        "controls": controls,
        "findings_new": sorted(new_findings - old_findings),
        "findings_resolved": sorted(old_findings - new_findings),
        "limitations": ["A evolução de score deve ser interpretada primeiro pelo conjunto de controles avaliados nas duas execuções.", "Mudança de permissão, licença, escopo ou cobertura pode alterar o score geral sem representar evolução real.", "Ausência de dado não é interpretada automaticamente como melhoria."],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compara duas execuções do assessment")
    parser.add_argument("--previous", required=True)
    parser.add_argument("--current", default="runtime/assessment.json")
    parser.add_argument("--output", default="runtime/run-comparison.json")
    options = parser.parse_args()
    result = compare(json.loads(Path(options.previous).read_text(encoding="utf-8")), json.loads(Path(options.current).read_text(encoding="utf-8")))
    Path(options.output).parent.mkdir(parents=True, exist_ok=True)
    Path(options.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Comparação gravada em {options.output}")


if __name__ == "__main__":
    main()
