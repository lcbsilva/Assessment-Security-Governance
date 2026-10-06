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
            savings.append({"amount": amount, "currency": item.get("currency") or finops.get("currency") or "—"})

    # Advisor pode conter recomendações sobrepostas. Somar é útil apenas como
    # teto de investigação, nunca como economia realizável ou business case.
    savings_upper_bound = round(sum(item["amount"] for item in savings), 2)
    currency = next((item["currency"] for item in savings if item["currency"] != "—"), finops.get("currency", "—"))

    return {
        "signals": {
            "advisor_recommendations": len(advisor),
            "service_health_items": len(service_health),
            "retirement_items": len(retirement),
            "orphan_resources": len(orphans),
        },
        "savings": {
            "upper_bound": savings_upper_bound,
            "currency": currency,
            "method": "Soma bruta de sinais monetários disponíveis; recomendações podem se sobrepor.",
            "realizable_savings": None,
            "guardrail": "Não apresentar como economia comprometida sem deduplicação, owner, dependências e validação financeira.",
        },
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
