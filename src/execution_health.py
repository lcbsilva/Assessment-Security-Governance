"""Resumo conservador da saúde da execução e da cobertura da evidência."""

from __future__ import annotations


def coverage_map(logs: list[dict], manifest: list[dict]) -> list[dict]:
    """Cruza escopo esperado e resultado real sem copiar evidência bruta."""
    normalized_logs = [(str(item.get("module", "")).lower(), item) for item in logs or []]
    rows = []
    for expected in manifest or []:
        name = str(expected.get("module", "—"))
        key = name.lower()
        candidates = [item for module, item in normalized_logs if module == key or key in module or module in key]
        selected = next((item for item in candidates if item.get("status") in {"success", "partial"}), candidates[0] if candidates else {})
        status = selected.get("status", expected.get("status", "not_run"))
        rows.append({
            "module": name,
            "domain": expected.get("domain", "—"),
            "expected_read_scope": expected.get("expected_read_scope", "—"),
            "status": status,
            "records": int(selected.get("records", 0) or 0),
            "source": selected.get("source", "Não executado nesta execução"),
            "limitation": selected.get("note", expected.get("detail", "Evidência não disponível")),
            "evidence_confidence": "alta" if status == "success" else ("média" if status == "partial" else "baixa"),
        })
    return rows


def summarize(logs: list[dict]) -> dict:
    """Agrega o manifesto sem copiar PII ou payloads brutos."""
    counts = {"success": 0, "partial": 0, "not_available": 0, "error": 0, "not_run": 0}
    limitations: list[dict] = []
    for item in logs or []:
        status = str(item.get("status", "not_available"))
        counts[status] = counts.get(status, 0) + 1
        if status not in {"success"}:
            limitations.append({
                "module": str(item.get("module", "—")),
                "status": status,
                "category": str(item.get("limitation_category", "unknown")),
                "records": int(item.get("records", 0) or 0),
            })
    total = sum(counts.values())
    completed = counts["success"] + counts["partial"]
    return {
        "total_modules": total,
        "completed_modules": completed,
        "coverage_percent": round(completed / total * 100, 1) if total else 0,
        "status_counts": counts,
        "health": "healthy" if total and not counts["error"] and not counts["not_available"] else "degraded" if completed else "blocked",
        "limitations": limitations,
        "interpretation": "Zero registros só é evidência de ausência quando o módulo terminou com sucesso; not_available/error não permitem concluir ausência.",
    }
