"""Checkpoint local por coletor para retomada segura de execuções longas."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def scope_key(subscription_ids: list[str], profile: str) -> str:
    value = f"{profile}|{','.join(sorted(subscription_ids))}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def checkpoint_path(root: Path, module: str) -> Path:
    safe = "".join(character if character.isalnum() or character in {"-", "_"} else "_" for character in module)
    return root / f"{safe}.json"


def write(root: Path, module: str, key: str, result: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = checkpoint_path(root, module)
    # Escrita atômica: uma interrupção do Cloud Shell não pode deixar um JSON
    # parcialmente gravado que pareça um checkpoint válido na próxima execução.
    temporary = path.with_suffix(".tmp")
    envelope = {
        "module": module,
        "scope_key": key,
        "written_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "resume_eligible": _resume_eligible(result),
        "result": result,
    }
    temporary.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
    return path


def load(root: Path, module: str, key: str) -> dict | None:
    path = checkpoint_path(root, module)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        valid_scope = data.get("module") == module and data.get("scope_key") == key
        return data.get("result") if valid_scope and data.get("resume_eligible") is True and isinstance(data.get("result"), dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _resume_eligible(result: dict) -> bool:
    """Só reutiliza coleta que não terminou em erro ou indisponibilidade total."""
    metadata = result.get("metadata", {}) if isinstance(result, dict) else {}
    modules = metadata.get("modules", {}) if isinstance(metadata, dict) else {}
    if any(str(status).lower() in {"error", "failed"} for status in modules.values()):
        return False
    logs = result.get("discovery", {}).get("collection_log", []) if isinstance(result, dict) else []
    if logs and all(str(item.get("status", "")).lower() in {"error", "not_available", "not_run"} for item in logs):
        return False
    return bool(logs or modules)
