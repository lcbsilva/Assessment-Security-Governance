#!/usr/bin/env python3
"""Consolida a validação dos perfis de laboratório sem acessar o tenant."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PROFILES = ("security", "governance", "full")


def profile_summary(pilot: dict, manifest: dict) -> dict:
    """Reduz um perfil a um contrato operacional sem expor dados do tenant."""
    pilot_status = pilot.get("status", "unknown")
    artifact_status = manifest.get("status", "unknown")
    warnings = list(pilot.get("warnings", []))
    errors = list(pilot.get("errors", []))
    if pilot_status == "blocked" or artifact_status != "valid" or errors:
        readiness = "blocked"
    elif warnings or pilot.get("modules_unavailable_or_error", 0) or pilot.get("modules_partial", 0):
        readiness = "warning"
    else:
        readiness = "pass"
    metrics = pilot.get("quality_audit", {}).get("metrics", {})
    return {
        "readiness": readiness,
        "pilot_status": pilot_status,
        "artifact_integrity": artifact_status,
        "coverage": metrics.get("coverage"),
        "overall_score": metrics.get("overall_score"),
        "modules_unavailable_or_error": pilot.get("modules_unavailable_or_error", 0),
        "modules_partial": pilot.get("modules_partial", 0),
        "modules_not_run": pilot.get("modules_not_run", 0),
        "warnings": len(warnings),
        "errors": len(errors),
    }


def summarize(root: Path) -> dict:
    summary = {"summary_version": "1.0", "read_only": True, "overall_status": "pass", "profiles": {}}
    for profile in PROFILES:
        pilot_path = root / profile / "pilot-validation.json"
        manifest_path = root / profile / "manifest-validation.json"
        if not pilot_path.exists() or not manifest_path.exists():
            summary["profiles"][profile] = {"readiness": "not_run", "pilot_status": "not_run", "artifact_integrity": "not_run"}
            continue
        pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        summary["profiles"][profile] = profile_summary(pilot, manifest)
    readiness = [item["readiness"] for item in summary["profiles"].values()]
    if all(status == "not_run" for status in readiness):
        summary["overall_status"] = "not_run"
    elif "blocked" in readiness:
        summary["overall_status"] = "blocked"
    elif "warning" in readiness or "not_run" in readiness:
        summary["overall_status"] = "warning"
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolida validação de laboratório")
    parser.add_argument("--root", type=Path, default=Path("runtime/lab-validation"))
    parser.add_argument("--output", type=Path, default=Path("runtime/lab-validation/summary.json"))
    args = parser.parse_args()
    result = summarize(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Resumo de laboratório gravado em {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
