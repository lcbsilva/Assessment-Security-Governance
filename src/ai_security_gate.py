"""Gate local para qualquer futura integração de IA.

A integração permanece opt-in e só pode consumir o payload agregado aprovado.
Este módulo não chama nenhum modelo nem endpoint externo.
"""

from __future__ import annotations

from ai_payload import privacy_violations


def evaluate(payload: dict, enabled: bool = False) -> dict:
    violations = privacy_violations(payload)
    limitations = payload.get("limitations", []) if isinstance(payload, dict) else []
    reasons = []
    if not enabled:
        reasons.append("AI integration disabled by default")
    if violations:
        reasons.append("Aggregated payload failed privacy validation")
    if not isinstance(payload, dict) or payload.get("purpose") != "Executive summary for security and governance assessment":
        reasons.append("Payload is not the approved aggregated assessment contract")
    if not limitations:
        reasons.append("Payload must preserve interpretation limitations")

    return {
        "enabled": bool(enabled),
        "approved_for_external_model": bool(enabled and not reasons),
        "privacy_violations": violations,
        "reasons": reasons,
        "guardrails": [
            "Nunca enviar assessment.json bruto, evidências textuais, UPNs, IDs de tenant/subscription ou nomes de recursos.",
            "A IA pode resumir e priorizar métricas agregadas; não pode declarar causa raiz, incidente ou conformidade sem evidência determinística.",
            "Saída de IA é conteúdo consultivo e deve permanecer separada do score e do estado dos controles.",
        ],
    }
