#!/usr/bin/env python3
"""Registra histórico mínimo e não sensível de execuções locais.

O histórico serve para tendência e comparação. Não copia usuários, UPNs,
nomes de recursos, IDs, evidências textuais ou payloads brutos.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def snapshot(data: dict) -> dict:
    metadata = data.get("metadata", {})
    return {
        "run_id": metadata.get("run_id", "unknown"),
        "collected_at": metadata.get("collected_at", datetime.now(timezone.utc).isoformat()),
        "engine_version": metadata.get("engine_version", "unknown"),
        "overall_score": metadata.get("overall_score"),
        "coverage": metadata.get("coverage"),
        "scope": {key: value for key, value in metadata.get("scope", {}).items() if isinstance(value, (int, float))},
        "modules": metadata.get("modules", {}),
        "controls": [{"id": item.get("id"), "score": item.get("score"), "status": item.get("status"), "confidence": item.get("confidence")} for item in data.get("controls", [])],
        "findings": [{"id": item.get("id"), "control_id": item.get("control_id"), "severity": item.get("severity"), "risk_score": item.get("risk_score")} for item in data.get("findings", [])],
    }


def record(data: dict, history_dir: Path) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(data.get("metadata", {}).get("run_id", "run"))
    path = history_dir / f"{run_id}.json"
    path.write_text(json.dumps(snapshot(data), ensure_ascii=False, indent=2), encoding="utf-8")
    return path
