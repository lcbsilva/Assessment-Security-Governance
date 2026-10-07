"""Consolida sinais de lifecycle e FinOps sem transformar recomendações em comandos."""

from __future__ import annotations


def _money(value):
    try:
        return round(float(value or 0), 2)
    except (TypeError, ValueError):
        return 0.0


def build(discovery: dict) -> dict:
    """Produz uma camada consultiva conservadora a partir de evidência já coletada."""
    advisor = discovery.get("advisor_recommendations", []) or []
    service_health = discovery.get("service_health", []) or []
    retirement = discovery.get("retirement", []) or discovery.get("retirement_signals", []) or []
    orphans = discovery.get("orphan_resources", []) or []
    finops = discovery.get("finops_summary", {}) or {}

    savings = []
    for item in advisor:
        raw = item.get("potential_savings") or item.get("annual_savings") or item.get("savings")
        amount = _money(raw)
        if amount > 0:
            savings.append({"amount": amount, "currency": item.get("currency") or finops.get("currency") or "—", "key": str(item.get("recommendation_id") or item.get("id") or item.get("resource_id") or item.get("recommendation") or "").strip().lower()})

    # Advisor pode conter recomendações sobrepostas. Somar é útil apenas como
    # teto de investigação, nunca como economia realizável ou business case.
    # A deduplicação é conservadora: só colapsa linhas que fornecem a mesma chave
    # explícita. Itens sem chave continuam no teto bruto para não inventar equivalência.
    keyed: dict[str, dict] = {}
    unkeyed = []
    for item in savings:
        if item["key"]:
            current = keyed.get(item["key"])
            if current is None or item["amount"] > current["amount"]:
                keyed[item["key"]] = item
        else:
            unkeyed.append(item)
    deduplicated = list(keyed.values()) + unkeyed
    savings_upper_bound = round(sum(item["amount"] for item in savings), 2)
    deduplicated_upper_bound = round(sum(item["amount"] for item in deduplicated), 2)
    currency = next((item["currency"] for item in savings if item["currency"] != "—"), finops.get("currency", "—"))
    anomaly = finops.get("anomalies", {}) or {}
    reservation_signal = finops.get("reservations", "Não quantificado")
    savings_plan_signal = finops.get("savings_plans", "Não quantificado")
    optimization = {
        "anomaly_days": len(anomaly.get("anomaly_days", []) or []),
        "daily_median": anomaly.get("daily_median"),
        "daily_peak": anomaly.get("daily_peak"),
        "reservations": reservation_signal,
        "savings_plans": savings_plan_signal,
        "rightsizing_candidates": sum(1 for item in advisor if "right" in str(item.get("category", "")).lower() or "right" in str(item.get("recommendation", "")).lower()),
        "interpretation": "Sinais para investigação FinOps; não constituem compromisso de economia, compra de benefício ou alteração de SKU.",
    }

    return {
        "signals": {
            "advisor_recommendations": len(advisor),
            "service_health_items": len(service_health),
            "retirement_items": len(retirement),
            "orphan_resources": len(orphans),
        },
        "savings": {
            "upper_bound": savings_upper_bound,
            "deduplicated_upper_bound": deduplicated_upper_bound,
            "raw_signal_count": len(savings),
            "deduplicated_signal_count": len(deduplicated),
            "currency": currency,
            "method": "upper_bound é soma bruta e recomendações podem se sobrepor; deduplicated_upper_bound remove apenas duplicatas com a mesma chave explícita e continua sendo teto de investigação.",
            "realizable_savings": None,
            "guardrail": "Não apresentar como economia comprometida sem deduplicação, owner, dependências e validação financeira.",
        },
        "optimization": optimization,
        "decision_guardrails": [
            "Sinais de retirement exigem confirmação em fonte oficial e validação de dependências antes de qualquer plano de mudança.",
            "Recursos órfãos são candidatos à investigação, não candidatos automáticos à exclusão.",
            "Service Health contextualiza risco operacional; não prova causalidade de incidentes do cliente.",
            "Toda ação requer owner, criticidade, dependências, backup/rollback e janela de mudança aprovados.",
        ],
        "review_queue": {
            "retirement": retirement[:10],
            "orphans": orphans[:10],
            "service_health": service_health[:10],
        },
    }
