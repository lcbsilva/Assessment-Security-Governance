#!/usr/bin/env python3
"""Recalcula hashes do manifesto sem acessar o tenant."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_entries(root: Path, entries: list[dict], label: str) -> list[str]:
    errors = []
    for entry in entries:
        name = str(entry.get("name", ""))
        if not name or Path(name).name != name:
            errors.append(f"{label}: caminho inválido no manifesto: {name}")
            continue
        path = root / name
        if not path.is_file():
            errors.append(f"{label}: arquivo ausente: {name}")
            continue
        actual = sha256(path)
        if actual != entry.get("sha256"):
            errors.append(f"{label}: hash divergente: {name}")
    return errors


def validate(manifest_path: Path, output_dir: Path, input_dir: Path) -> dict:
    errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "invalid", "errors": [f"Manifesto inválido: {type(exc).__name__}"], "read_only": True}
    if manifest.get("read_only") is not True:
        errors.append("Manifesto não confirma execução read-only")
    errors.extend(check_entries(output_dir, manifest.get("files", []), "artefato"))
    errors.extend(check_entries(input_dir, manifest.get("inputs", []), "entrada"))
    return {"status": "valid" if not errors else "invalid", "errors": errors, "read_only": True, "manifest_version": manifest.get("manifest_version", "unknown"), "note": "Validação local; nenhum tenant foi acessado ou alterado."}


def main() -> int:
    parser = argparse.ArgumentParser(description="Valida hashes do manifesto de artefatos")
    parser.add_argument("--manifest", type=Path, default=Path("runtime/artifact-manifest.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--input-dir", type=Path, default=Path("runtime"))
    parser.add_argument("--output", type=Path, default=Path("runtime/manifest-validation.json"))
    args = parser.parse_args()
    result = validate(args.manifest, args.output_dir, args.input_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Manifest Validation: {result['status']}")
    if result["errors"]:
        print(json.dumps(result["errors"], ensure_ascii=False, indent=2))
    return 0 if result["status"] == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
