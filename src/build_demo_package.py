#!/usr/bin/env python3
"""Gera um pacote demonstrável completo sem autenticar ou acessar um tenant."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from simulate_tenant import simulate


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-1200:]
        raise RuntimeError(f"Falha em {' '.join(command)}: {detail}")


def build_demo(output_root: Path, scenario: str = "full", scale: int = 1) -> dict:
    """Executa a cadeia completa de artefatos sintéticos para uma apresentação."""
    runtime = output_root / "runtime"
    dist = output_root / "dist"
    runtime.mkdir(parents=True, exist_ok=True)
    dist.mkdir(parents=True, exist_ok=True)
    assessment_path = runtime / "assessment.json"
    html_path = dist / "assessment.html"
    base = json.loads((ROOT / "mock" / "assessment.json").read_text(encoding="utf-8"))
    assessment_path.write_text(json.dumps(simulate(base, scenario, scale), ensure_ascii=False, indent=2), encoding="utf-8")

    run([sys.executable, "src/generate_report.py", "--data", str(assessment_path), "--output", str(html_path)])
    run([sys.executable, "src/export_artifacts.py", "--data", str(assessment_path), "--output-dir", str(dist)])
    ai_path = runtime / "ai-payload.json"
    run([sys.executable, "src/ai_payload.py", "--data", str(assessment_path), "--output", str(ai_path)])
    artifact_validation = runtime / "artifact-validation.json"
    run([sys.executable, "src/validate_artifacts.py", "--output-dir", str(dist), "--ai-payload", str(ai_path), "--output", str(artifact_validation)])
    manifest = runtime / "artifact-manifest.json"
    run([sys.executable, "src/artifact_manifest.py", "--output-dir", str(dist), "--assessment", str(assessment_path), "--input", str(ai_path), "--output", str(manifest)])
    manifest_validation = runtime / "manifest-validation.json"
    run([sys.executable, "src/validate_manifest.py", "--manifest", str(manifest), "--output-dir", str(dist), "--input-dir", str(runtime), "--output", str(manifest_validation)])
    pilot = runtime / "pilot-validation.json"
    run([sys.executable, "src/validate_pilot.py", "--data", str(assessment_path), "--manifest-validation", str(manifest_validation), "--output", str(pilot)])

    pilot_data = json.loads(pilot.read_text(encoding="utf-8"))
    manifest_data = json.loads(manifest_validation.read_text(encoding="utf-8"))
    outputs = sorted(path.name for path in dist.iterdir() if path.is_file())
    summary = {
        "demo_version": "1.0",
        "status": "ready_for_internal_demo" if manifest_data.get("status") == "valid" else "blocked",
        "read_only": True,
        "synthetic": True,
        "scenario": scenario,
        "scale": scale,
        "pilot_status": pilot_data.get("status"),
        "artifact_integrity": manifest_data.get("status"),
        "coverage": pilot_data.get("quality_audit", {}).get("metrics", {}).get("coverage"),
        "overall_score": pilot_data.get("quality_audit", {}).get("metrics", {}).get("overall_score"),
        "outputs": outputs,
        "limitations": [
            "Dados sintéticos; não representam evidência de cliente.",
            "A execução real substitui este contrato após o Readiness Gate.",
            "Nenhuma chamada de autenticação, leitura ou escrita em tenant foi realizada.",
        ],
    }
    (runtime / "demo-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera pacote demonstrável offline")
    parser.add_argument("--output-root", type=Path, default=ROOT / "runtime" / "demo-package")
    parser.add_argument("--scenario", choices=("small", "limited", "full", "large"), default="full")
    parser.add_argument("--scale", type=int, default=1)
    args = parser.parse_args()
    summary = build_demo(args.output_root, args.scenario, args.scale)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"] == "ready_for_internal_demo" else 2


if __name__ == "__main__":
    raise SystemExit(main())
