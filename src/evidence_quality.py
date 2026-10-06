"""Classifica a qualidade da evidência sem expor dados do tenant."""

from __future__ import annotations


def classify(status: object, note: object = "") -> str:
    value = str(note or "").lower()
    state = str(status or "").lower()
    if state in {"success", "partial"}:
        return state
    if "429" in value or "throttl" in value or "rate limit" in value:
        return "throttling"
    if any(token in value for token in ("licen", "defender p2", "entitlement", "sku")):
        return "license"
    if "400" in value or "bad request" in value or "endpoint" in value:
        return "availability"
    if any(token in value for token in ("403", "401", "permission", "consent", "permiss", "forbidden", "unauthorized")):
        return "permission"
    if any(token in value for token in ("unsupported", "not supported", "parserfailure", "parser failure")):
        return "unsupported"
    if state == "error":
        return "execution"
    return "availability"


def summarize(logs: list[dict]) -> dict:
    """Score conservador: indisponibilidade nunca vira conformidade."""
    counts = {"success": 0, "partial": 0, "not_available": 0, "error": 0, "not_run": 0}
    categories = {"permission": 0, "license": 0, "throttling": 0, "unsupported": 0, "execution": 0, "availability": 0}
    for item in logs:
        status = str(item.get("status", "unknown")).lower()
        counts[status] = counts.get(status, 0) + 1
        category = classify(status, item.get("note"))
        if category in categories:
            categories[category] += 1
    # `not_run` descreve escopo escolhido, não qualidade da API. Ele deve ser
    # reportado, mas não pode reduzir a qualidade dos módulos que foram de fato
    # executados; a cobertura de escopo permanece em execution_health.
    evaluated = sum(counts.get(key, 0) for key in ("success", "partial", "not_available", "error"))
    score = round(((counts.get("success", 0) * 100) + (counts.get("partial", 0) * 70)) / evaluated) if evaluated else 0
    return {"score": score, "total_modules": len(logs), "evaluated_modules": evaluated, **{key: counts.get(key, 0) for key in counts}, "categories": categories,
            "interpretation": "Evidência suficiente para os módulos executados." if score >= 80 else "Há limitações de evidência; valide a categoria indicada por módulo (permissão, licença/entitlement, throttling, endpoint/configuração ou disponibilidade) antes de comparar tenants ou solicitar novos acessos."}
