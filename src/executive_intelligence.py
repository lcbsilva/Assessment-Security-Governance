"""Deriva uma visão executiva auditável para orientar a conversa consultiva.

Não altera risco técnico, score de controles ou evidências. A camada organiza
achados já normalizados em decisões, quick wins, frentes e horizonte 30/60/90.
"""

from __future__ import annotations

from collections import Counter, defaultdict


WORKSTREAMS = {
    "ID": "Identity & Access",
    "SEC": "Cloud & M365 Security",
    "GOV": "Cloud Governance",
    "COST": "FinOps & Cloud Optimization",
    "CMP": "Risk & Compliance",
}


def _prefix(item: dict) -> str:
    return str(item.get("control_id", "")).split("-")[0]


def _effort(item: dict) -> int:
    try:
        return max(1, min(5, int(item.get("effort", 3) or 3)))
    except (TypeError, ValueError):
        return 3


def build(findings: list[dict]) -> dict:
    """Resume achados priorizados sem inventar impacto ou benefício."""
    rows = list(findings or [])
    priorities = Counter(str(item.get("priority", "P3")) for item in rows)
    conditional = [item for item in rows if item.get("priority_eligibility") == "conditional_review"]
    confirmed = [item for item in rows if item.get("priority_eligibility") != "conditional_review"]
    quick_wins = [
        item for item in confirmed
        if str(item.get("priority")) in {"P1", "P2"} and _effort(item) <= 2
    ][:5]

    by_workstream: dict[str, list[dict]] = defaultdict(list)
    for item in rows:
        by_workstream[WORKSTREAMS.get(_prefix(item), "Risk & Compliance")].append(item)

    workstreams = []
    for name, items in by_workstream.items():
        eligible = [item for item in items if item.get("priority_eligibility") != "conditional_review"]
        workstreams.append({
            "name": name,
            "findings": len(items),
            "confirmed": len(eligible),
            "conditional": len(items) - len(eligible),
            "max_risk": max((int(item.get("risk_score", 0) or 0) for item in eligible), default=0),
            "top_priority": min((str(item.get("priority", "P3")) for item in eligible), default="P3"),
        })
    workstreams.sort(key=lambda row: (row["top_priority"], -row["max_risk"], row["name"]))

    horizon = {"30": [], "60": [], "90": []}
    for item in confirmed:
        actions = item.get("action_30_60_90", {}) or {}
        for key in horizon:
            action = actions.get(key)
            if action:
                horizon[key].append({
                    "finding": item.get("title", "Achado"),
                    "priority": item.get("priority", "P3"),
                    "owner": item.get("owner", "A definir"),
                    "action": action,
                })

    return {
        "summary": {
            "findings": len(rows),
            "p1": priorities.get("P1", 0),
            "p2": priorities.get("P2", 0),
            "p3": priorities.get("P3", 0),
            "confirmed_for_action": len(confirmed),
            "conditional_review": len(conditional),
            "quick_wins": len(quick_wins),
        },
        "quick_wins": [{
            "title": item.get("title"),
            "priority": item.get("priority"),
            "risk": item.get("risk_score", 0),
            "owner": item.get("owner", "A definir"),
            "effort": item.get("effort_band", "Baixo"),
            "outcome": item.get("user_impact", "Validar resultado esperado com o owner."),
        } for item in quick_wins],
        "workstreams": workstreams,
        "roadmap": horizon,
        "conditional_reviews": [{
            "title": item.get("title"),
            "risk": item.get("risk_score", 0),
            "reason": item.get("priority_rationale", "Evidência insuficiente; validar antes de remediar."),
            "owner": item.get("owner", "A definir"),
        } for item in conditional[:8]],
        "guardrail": "Itens condicionais não entram como P1 nem como ação confirmada até que a evidência necessária seja validada.",
    }
