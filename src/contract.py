#!/usr/bin/env python3
"""Validação mínima do contrato de assessment.

O contrato é deliberadamente simples e compatível com JSON para permitir
coletores PowerShell, Python e ferramentas externas sem acoplamento.
"""

from __future__ import annotations


STATUSES = {"pass", "partial", "fail", "not_available", "error"}
CONFIDENCES = {"high", "medium", "low"}


def validate_payload(payload: dict, catalog: dict | None = None) -> list[str]:
    errors: list[str] = []
    for key in ("metadata", "controls", "findings", "discovery"):
        if key not in payload:
            errors.append(f"campo obrigatório ausente: {key}")
    if not isinstance(payload.get("metadata"), dict):
        errors.append("metadata deve ser objeto")
    if not isinstance(payload.get("controls"), list):
        errors.append("controls deve ser lista")
    if not isinstance(payload.get("findings"), list):
        errors.append("findings deve ser lista")
    if not isinstance(payload.get("discovery"), dict):
        errors.append("discovery deve ser objeto")
    control_ids = set()
    for index, item in enumerate(payload.get("controls", [])):
        if not isinstance(item, dict):
            errors.append(f"controls[{index}] deve ser objeto")
            continue
        control_id = item.get("id")
        if not control_id:
            errors.append(f"controls[{index}].id ausente")
        elif control_id in control_ids:
            errors.append(f"controle duplicado: {control_id}")
        control_ids.add(control_id)
        if item.get("status") not in STATUSES:
            errors.append(f"controls[{index}].status inválido")
        if item.get("confidence") not in CONFIDENCES:
            errors.append(f"controls[{index}].confidence inválido")
        if item.get("status") not in {"not_available", "error"} and not isinstance(item.get("score"), (int, float)):
            errors.append(f"controls[{index}].score ausente para controle avaliado")
    finding_ids = set()
    for index, item in enumerate(payload.get("findings", [])):
        if not isinstance(item, dict):
            errors.append(f"findings[{index}] deve ser objeto")
            continue
        finding_id = item.get("id")
        if not finding_id:
            errors.append(f"findings[{index}].id ausente")
        elif finding_id in finding_ids:
            errors.append(f"achado duplicado: {finding_id}")
        finding_ids.add(finding_id)
        for key in ("control_id", "title", "severity", "evidence", "recommendation"):
            if key not in item:
                errors.append(f"findings[{index}].{key} ausente")
        if item.get("risk_score") is not None and not isinstance(item.get("risk_score"), (int, float)):
            errors.append(f"findings[{index}].risk_score inválido")
    if catalog:
        catalog_ids = {item.get("id") for item in catalog.get("controls", [])}
        unknown = control_ids - catalog_ids
        errors.extend(f"controle fora do catálogo: {item}" for item in sorted(unknown))
    return errors
