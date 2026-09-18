"""Validação estrutural mínima do schema versionado sem dependência externa."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_schema() -> dict:
    return json.loads((ROOT / "schemas" / "assessment.schema.json").read_text(encoding="utf-8"))


def validate_schema(payload: dict) -> list[str]:
    errors: list[str] = []
    for key in ("metadata", "controls", "findings", "discovery"):
        if key not in payload:
            errors.append(f"schema: campo ausente {key}")
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        return errors + ["schema: metadata deve ser objeto"]
    schema_version = metadata.get("schema_version")
    if not isinstance(schema_version, str) or len(schema_version.split(".")) != 2:
        errors.append("schema: metadata.schema_version deve seguir major.minor")
    execution = metadata.get("execution", {})
    if not isinstance(execution, dict) or not {"mode", "tenant_mutation"}.issubset(execution):
        errors.append("schema: metadata.execution deve declarar mode e tenant_mutation")
    if not isinstance(payload.get("controls"), list):
        errors.append("schema: controls deve ser lista")
    if not isinstance(payload.get("findings"), list):
        errors.append("schema: findings deve ser lista")
    if not isinstance(payload.get("discovery"), dict):
        errors.append("schema: discovery deve ser objeto")
    return errors
