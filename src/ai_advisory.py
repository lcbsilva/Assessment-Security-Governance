"""Execução opcional e segura da camada consultiva de IA.

Nenhuma chamada externa ocorre sem opt-in explícito e aprovação do gate.
O transporte é injetável para permitir testes sem rede e sem segredos.
"""

from __future__ import annotations

from typing import Callable
import json

from ai_security_gate import evaluate


def _normalize_advisory(raw: str) -> dict:
    """Aceita JSON estruturado; texto livre permanece somente como resumo."""
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"executive_summary": str(raw).strip(), "attention_points": [], "consultant_questions": []}
    if not isinstance(parsed, dict):
        return {"executive_summary": str(raw).strip(), "attention_points": [], "consultant_questions": []}
    return {
        "executive_summary": str(parsed.get("executive_summary") or parsed.get("summary") or "").strip(),
        "attention_points": [str(x).strip() for x in (parsed.get("attention_points") or []) if str(x).strip()][:8],
        "consultant_questions": [str(x).strip() for x in (parsed.get("consultant_questions") or []) if str(x).strip()][:8],
    }


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
    advisory = _normalize_advisory(summary)
    return {**base, "status": "completed", "summary": advisory["executive_summary"], "advisory": advisory}
