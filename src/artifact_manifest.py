"""Gera um manifesto de integridade dos artefatos locais da execução."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from local_privacy import protect_output_parent
from report_context import build as build_report_context


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(output_dir: Path, assessment: dict, input_files: list[Path] | None = None) -> dict:
    metadata = assessment.get("metadata", {}) or {}
    context = build_report_context(assessment)
    files = []
    for path in sorted(output_dir.iterdir() if output_dir.exists() else []):
        if path.is_file() and path.name != "artifact-manifest.json":
            files.append({"name": path.name, "size_bytes": path.stat().st_size, "sha256": sha256(path)})
    inputs = []
    for path in input_files or []:
        if path.exists() and path.is_file():
            inputs.append({"name": path.name, "size_bytes": path.stat().st_size, "sha256": sha256(path)})
    return {
        "manifest_version": "1.1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "classification": "Confidencial — Security & Governance Assessment",
        "read_only": metadata.get("execution", {}).get("tenant_mutation") is False,
        "engine_version": metadata.get("engine_version", "unknown"),
        "schema_version": metadata.get("schema_version", "unknown"),
        "profile": metadata.get("profile", "unknown"),
        "run_id": metadata.get("run_id", "unknown"),
        "execution_window": {"started_at": context["started_at"], "finished_at": context["finished_at"], "wall_duration_seconds": metadata.get("execution", {}).get("wall_duration_seconds")},
        "scope_counts": {key: value for key, value in (metadata.get("scope", {}) or {}).items() if isinstance(value, (int, float))},
        "limitation_counts": {key: value for key, value in context["status_counts"].items() if key in {"partial", "not_available", "error", "not_run"}},
        "local_handling": "Artefatos contêm dados confidenciais derivados do tenant; permissões POSIX são restringidas quando aplicável. O operador define retenção e remoção.",
        "inputs": inputs,
        "files": files,
        "integrity_rule": "Os hashes SHA-256 permitem verificar alteração dos dados de entrada e artefatos após a geração local.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera manifesto SHA-256 dos artefatos")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--assessment", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", default=[], help="Arquivo de entrada adicional para registrar; pode ser repetido")
    parser.add_argument("--output", type=Path, default=Path("runtime/artifact-manifest.json"))
    args = parser.parse_args()
    protect_output_parent(args.output)
    assessment = json.loads(args.assessment.read_text(encoding="utf-8"))
    result = build(args.output_dir, assessment, [args.assessment, *args.input])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Manifesto de artefatos gravado em {args.output}")


if __name__ == "__main__":
    main()
