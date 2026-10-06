"""Tendências locais e privacy-safe entre execuções do assessment."""

from __future__ import annotations


def build(snapshots: list[dict]) -> dict:
    ordered = sorted(snapshots, key=lambda item: str(item.get("collected_at", "")))
    points = []
    for item in ordered:
        points.append({
            "run_id": item.get("run_id", "unknown"),
            "collected_at": item.get("collected_at"),
            "engine_version": item.get("engine_version"),
            "overall_score": item.get("overall_score"),
            "coverage": item.get("coverage"),
            "finding_count": len(item.get("findings", []) or []),
        })

    comparable = []
    for previous, current in zip(ordered, ordered[1:]):
        old_controls = {x.get("id"): x for x in previous.get("controls", []) or []}
        new_controls = {x.get("id"): x for x in current.get("controls", []) or []}
        overlap = sorted(set(old_controls) & set(new_controls))
        deltas = []
        for control_id in overlap:
            old, new = old_controls[control_id], new_controls[control_id]
            if old.get("status") in {"not_available", "error"} or new.get("status") in {"not_available", "error"}:
                continue
            if isinstance(old.get("score"), (int, float)) and isinstance(new.get("score"), (int, float)):
                deltas.append(new["score"] - old["score"])
        comparable.append({
            "from_run": previous.get("run_id", "unknown"),
            "to_run": current.get("run_id", "unknown"),
            "comparable_controls": len(deltas),
            "average_control_delta": round(sum(deltas) / len(deltas), 2) if deltas else None,
            "coverage_delta": (
                round(current["coverage"] - previous["coverage"], 2)
                if isinstance(previous.get("coverage"), (int, float)) and isinstance(current.get("coverage"), (int, float))
                else None
            ),
        })

    return {
        "runs": len(points),
        "points": points,
        "intervals": comparable,
        "privacy": {
            "raw_identifiers_included": False,
            "scope": "Somente snapshots locais minimizados; sem UPN, nome de recurso, tenant ID ou evidência textual.",
        },
        "limitations": [
            "Tendência de score só é interpretável junto da cobertura e do conjunto de controles comparáveis.",
            "Mudanças de versão do engine podem alterar regras de avaliação.",
            "Este histórico não constitui benchmark externo de mercado.",
        ],
    }
