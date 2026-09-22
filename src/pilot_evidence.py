#!/usr/bin/env python3
"""Cruza evidências locais para autorizar um piloto controlado.

Este módulo não autentica, concede permissões nem consulta o tenant. Ele apenas
valida os contratos produzidos pelo readiness gate, pela coleta e pela revisão
de piloto, além de um manifesto local de aprovação humana.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = re.compile(
    r"(?:token|access_token|client_secret|password|private_key|certificate|pat)",
    re.IGNORECASE,
)
REQUIRED_APPROVAL_FIELDS = ("consent_status", "approved_profile", "approved_subscriptions", "approved_read_scopes")
VALID_CONSENT_STATUS = {"confirmed", "not_confirmed", "not_applicable"}


def _contains_sensitive_key(value: Any, path: str = "") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            current = f"{path}.{key}" if path else key
            if SENSITIVE_KEYS.search(str(key)):
                return current
            found = _contains_sensitive_key(child, current)
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _contains_sensitive_key(child, f"{path}[{index}]")
            if found:
                return found
    return None


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def validate_approval(approval: dict, preflight: dict, assessment: dict, pilot: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    sensitive_key = _contains_sensitive_key(approval)
    if sensitive_key:
        errors.append(f"manifesto de aprovação contém campo sensível: {sensitive_key}")

    missing = [field for field in REQUIRED_APPROVAL_FIELDS if field not in approval]
    errors.extend(f"manifesto de aprovação sem {field}" for field in missing)
    consent = approval.get("consent_status")
    if consent not in VALID_CONSENT_STATUS:
        errors.append("consent_status deve ser confirmed, not_confirmed ou not_applicable")
    elif consent != "confirmed":
        errors.append("consentimento administrativo do piloto não está confirmado")

    profile = approval.get("approved_profile")
    if profile not in {"security", "governance", "full"}:
        errors.append("approved_profile inválido")
    preflight_profile = preflight.get("profile")
    if profile and preflight_profile and profile != preflight_profile:
        errors.append("perfil aprovado difere do perfil do preflight")

    approved_subscriptions = set(_as_list(approval.get("approved_subscriptions")))
    requested_subscriptions = set(_as_list(preflight.get("subscriptions_requested")))
    if not approved_subscriptions:
        errors.append("nenhuma subscription foi aprovada")
    elif requested_subscriptions - approved_subscriptions:
        errors.append("preflight solicita subscription fora do escopo aprovado")

    if not _as_list(approval.get("approved_read_scopes")):
        errors.append("nenhum escopo somente leitura foi aprovado")
    forbidden = [scope for scope in _as_list(approval.get("approved_read_scopes")) if re.search(r"readwrite|owner|contributor|delete|remediat", scope, re.IGNORECASE)]
    if forbidden:
        errors.append("manifesto contém escopo incompatível com read-only: " + ", ".join(forbidden[:3]))

    if preflight.get("status") != "ready":
        errors.append("preflight não está pronto")
    if pilot.get("status") != "ready_for_pilot_review":
        errors.append("validação do piloto não está pronta para revisão")
    execution = assessment.get("metadata", {}).get("execution", {})
    if execution.get("tenant_mutation") is not False or execution.get("mode") not in {None, "read-only"}:
        errors.append("assessment não comprova execução read-only")
    if assessment.get("metadata", {}).get("simulation", {}).get("is_simulation") is True:
        warnings.append("a execução é sintética; não pode ser usada como evidência de cliente")
    if preflight.get("summary", {}).get("warning", 0):
        warnings.append("preflight possui warnings de cobertura ou permissões opcionais")
    return sorted(set(errors)), sorted(set(warnings))


def build(preflight: dict, assessment: dict, pilot: dict, approval: dict) -> dict:
    errors, warnings = validate_approval(approval, preflight, assessment, pilot)
    return {
        "version": "1.0",
        "status": "blocked" if errors else "ready_for_controlled_pilot",
        "decision": "Não executar coleta no tenant" if errors else "Pode executar o piloto dentro do escopo aprovado",
        "read_only": True,
        "consent_status": approval.get("consent_status", "unknown"),
        "approved_profile": approval.get("approved_profile"),
        "approved_subscriptions_count": len(_as_list(approval.get("approved_subscriptions"))),
        "approved_read_scopes_count": len(_as_list(approval.get("approved_read_scopes"))),
        "errors": errors,
        "warnings": warnings,
        "limitations": [
            "Este gate não verifica consentimento no tenant; depende do registro humano aprovado.",
            "Aprovação não amplia permissões, escopo ou perfil durante a execução.",
            "Warnings de licença, retenção, throttling e módulos opcionais continuam válidos.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Valida evidências locais para piloto controlado")
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--assessment", required=True, type=Path)
    parser.add_argument("--pilot-validation", required=True, type=Path)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = build(
        json.loads(args.preflight.read_text(encoding="utf-8")),
        json.loads(args.assessment.read_text(encoding="utf-8")),
        json.loads(args.pilot_validation.read_text(encoding="utf-8")),
        json.loads(args.approval.read_text(encoding="utf-8")),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Pilot Evidence Gate: {result['status']}")
    if result["status"] == "blocked":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
