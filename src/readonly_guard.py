#!/usr/bin/env python3
"""Barreira de execução: o engine não possui caminho de escrita no tenant."""

from __future__ import annotations


def assert_read_only(config: dict) -> None:
    """Interrompe a execução se a configuração permitir qualquer remediação."""
    guardrails = config.get("guardrails", {})
    if guardrails.get("allow_write") is not False or guardrails.get("allow_delete") is not False:
        raise RuntimeError("Configuração insegura: o assessment deve permanecer somente leitura")


def execution_metadata() -> dict:
    return {
        "mode": "read-only",
        "tenant_mutation": False,
        "allowed_operations": ["GET", "consulta", "normalização", "scoring", "renderização"],
        "blocked_operations": ["POST", "PATCH", "PUT", "DELETE", "criação", "alteração", "remoção"],
    }
