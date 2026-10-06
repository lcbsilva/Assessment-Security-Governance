"""Matriz determinística de cobertura dos coletores para orientar aprofundamento sem inflar compliance."""

from __future__ import annotations


PRIORITY = {
    "pim": 100,
    "defender": 95,
    "secure score": 90,
    "identity risk": 90,
    "conditional access": 85,
    "sign-in": 80,
    "intune": 75,
    "m365": 70,
    "purview": 70,
    "cost": 65,
    "advisor": 60,
}


def _priority(module: str) -> int:
    name = module.lower()
    return max((value for key, value in PRIORITY.items() if key in name), default=50)


def build(collection_log: list[dict]) -> dict:
    rows = []
    for item in collection_log or []:
        status = str(item.get("status", "unknown"))
        if status not in {"partial", "not_available", "error"}:
            continue
        rows.append({
            "module": item.get("module", "unknown"),
            "status": status,
            "records": item.get("records", 0),
            "priority": _priority(str(item.get("module", ""))),
            "limitation_category": item.get("limitation_category", "unclassified"),
            "next_step": item.get("next_step") or "Validar a causa registrada localmente antes de alterar permissões, licença ou configuração.",
        })
    rows.sort(key=lambda row: (-row["priority"], row["module"].lower()))
    return {
        "status": "limited" if rows else "covered",
        "gaps": rows,
        "gap_count": len(rows),
        "guardrails": [
            "Falha ou indisponibilidade de coleta não representa conformidade.",
            "A matriz não concede permissões, não habilita licenças e não altera o tenant.",
            "Prioridade indica valor diagnóstico, não autorização automática para ampliar acesso.",
        ],
    }
