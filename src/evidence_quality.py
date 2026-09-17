"""Classifica a qualidade da evidência sem expor dados do tenant."""

from __future__ import annotations


def classify(status: object, note: object = "") -> str:
    value = str(note or "").lower()
    state = str(status or "").lower()
    if state in {"success", "partial"}:
        return state
    if "429" in value or "throttl" in value or "rate limit" in value:
        return "throttling"
    if any(token in value for token in ("403", "401", "permission", "consent", "permiss")):
        return "permission"
    if any(token in value for token in ("licen", "defender p2")):
        return "license"
    if any(token in value for token in ("unsupported", "not supported", "parserfailure", "parser failure")):
        return "unsupported"
    if state == "error":
        return "execution"
    return "availability"


def summarize(logs: list[dict]) -> dict:
    """Score conservador: indisponibilidade nunca vira conformidade."""
    counts = {"success": 0, "partial": 0, "not_available": 0, "error": 0}
    categories = {"permission": 0, "license": 0, "throttling": 0, "unsupported": 0, "execution": 0, "availability": 0}
    for item in logs:
        status = str(item.get("status", "unknown")).lower()
        counts[status] = counts.get(status, 0) + 1
        category = classify(status, item.get("note"))
        if category in categories:
            categories[category] += 1
    total = len(logs)
    score = round(((counts.get("success", 0) * 100) + (counts.get("partial", 0) * 70)) / total) if total else 0
    return {"score": score, "total_modules": total, **{key: counts.get(key, 0) for key in counts}, "categories": categories,
            "interpretation": "Evidência suficiente para os módulos executados." if score >= 80 else "Ampliar permissões, licenças ou disponibilidade antes de comparar tenants."}
