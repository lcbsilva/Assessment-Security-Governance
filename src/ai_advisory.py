"""Execução opcional e segura da camada consultiva de IA.

Nenhuma chamada externa ocorre sem opt-in explícito e aprovação do gate.
O transporte é injetável para permitir testes sem rede e sem segredos.
"""

from __future__ import annotations

from typing import Callable

from ai_security_gate import evaluate


def run(payload: dict, enabled: bool = False, transport: Callable[[dict], str] | None = None) -> dict:
    gate = evaluate(payload, enabled=enabled)
    base = {
        "status": "not_configured" if not enabled else "blocked",
        "advisory_only": True,
        "score_mutation_allowed": False,
        "gate": gate,
        "summary": None,
    }
    if not gate["approved_for_external_model"]:
        return base
    if transport is None:
        return {**base, "status": "not_configured", "gate": gate}
    try:
        summary = transport(payload)
    except Exception as exc:
        return {
            **base,
            "status": "error",
            "error_type": type(exc).__name__,
            "error": "AI transport failed; deterministic assessment remains authoritative.",
        }
    if not isinstance(summary, str) or not summary.strip():
        return {**base, "status": "error", "error": "AI transport returned no advisory content."}
    return {**base, "status": "completed", "summary": summary.strip()}
