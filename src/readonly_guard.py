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
        "allowed_operations": ["consultas de leitura", "normalização", "scoring", "renderização"],
        "allowed_read_query_methods": [
            {"method": "GET", "purpose": "Leitura de recursos e metadados"},
            {"method": "POST", "operation": "Microsoft.CostManagement/query", "purpose": "Consulta de custo sem alteração de estado"},
            {"method": "POST", "operation": "Azure Resource Graph resources query", "purpose": "Consulta de inventário sem alteração de estado"},
        ],
        "blocked_operations": ["POST/PATCH/PUT/DELETE de mutação", "criação", "alteração", "remoção", "remediação"],
        "forbidden_sensitive_reads": ["Microsoft.Storage/storageAccounts/listKeys/action", "leitura de segredos, chaves ou connection strings"],
    }
