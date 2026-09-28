#!/usr/bin/env python3
"""Gate reproduzível para declarar uma execução pronta para beta."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from simulate_tenant import SCENARIOS, simulate

ROOT = Path(__file__).resolve().parents[1]


def run_gate(data_path: Path, include_tests: bool = True, scenarios: tuple[str, ...] = tuple(SCENARIOS)) -> dict:
    checks: list[dict] = []

    def check(name: str, command: list[str]) -> None:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        checks.append({"name": name, "status": "pass" if result.returncode == 0 else "fail", "detail": (result.stdout or result.stderr).strip()[-500:]})

    check("source_compile", [sys.executable, "-m", "py_compile", *[str(path) for path in (ROOT / "src").glob("*.py")]])
    if include_tests:
        check("contract_and_tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"])
    with tempfile.TemporaryDirectory(prefix="assessment-beta-") as temporary:
        output_dir = Path(temporary) / "artifacts"
        html_path = Path(temporary) / "assessment.html"
        ai_path = Path(temporary) / "ai-payload.json"
        pilot_path = Path(temporary) / "pilot-validation.json"
        check("html_report", [sys.executable, "src/generate_report.py", "--data", str(data_path), "--output", str(html_path)])
        check("exports", [sys.executable, "src/export_artifacts.py", "--data", str(data_path), "--output-dir", str(output_dir)])
        check("ai_guardrails", [sys.executable, "src/ai_payload.py", "--data", str(data_path), "--output", str(ai_path)])
        check("pilot_validation", [sys.executable, "src/validate_pilot.py", "--data", str(data_path), "--output", str(pilot_path)])
        for name, path in (("html_non_empty", html_path), ("xlsx_exists", output_dir / "assessment-action-plan.xlsx"), ("pptx_exists", output_dir / "assessment-executive-summary.pptx"), ("pdf_exists", output_dir / "assessment-executive-summary.pdf"), ("one_page_brief_exists", output_dir / "assessment-one-page-brief.pdf"), ("ai_payload_exists", ai_path)):
            checks.append({"name": name, "status": "pass" if path.exists() and path.stat().st_size > 0 else "fail", "detail": str(path.name)})
        base = json.loads(data_path.read_text(encoding="utf-8"))
        for scenario in scenarios:
            scenario_path = Path(temporary) / f"scenario-{scenario}.json"
            scenario_html = Path(temporary) / f"scenario-{scenario}.html"
            try:
                scenario_path.write_text(json.dumps(simulate(base, scenario), ensure_ascii=False), encoding="utf-8")
                result = subprocess.run([sys.executable, "src/generate_report.py", "--data", str(scenario_path), "--output", str(scenario_html)], cwd=ROOT, capture_output=True, text=True)
                checks.append({"name": f"scenario_{scenario}", "status": "pass" if result.returncode == 0 and scenario_html.exists() and scenario_html.stat().st_size > 0 else "fail", "detail": "Cenário sintético offline; não acessa tenant."})
            except (OSError, ValueError) as exc:
                checks.append({"name": f"scenario_{scenario}", "status": "fail", "detail": f"{type(exc).__name__}: {exc}"})
        if "large" in scenarios:
            stress_path = Path(temporary) / "scenario-large-scale5.json"
            stress_output = Path(temporary) / "scenario-large-scale5-artifacts"
            stress_html = stress_output / "assessment.html"
            stress_ai = Path(temporary) / "scenario-large-scale5-ai.json"
            stress_validation = Path(temporary) / "scenario-large-scale5-validation.json"
            stress_manifest = Path(temporary) / "scenario-large-scale5-manifest.json"
            stress_manifest_validation = Path(temporary) / "scenario-large-scale5-manifest-validation.json"
            try:
                stress_path.write_text(json.dumps(simulate(base, "large", scale=5), ensure_ascii=False), encoding="utf-8")
                stress_output.mkdir(parents=True, exist_ok=True)
                result = subprocess.run([sys.executable, "src/generate_report.py", "--data", str(stress_path), "--output", str(stress_html)], cwd=ROOT, capture_output=True, text=True)
                export = subprocess.run([sys.executable, "src/export_artifacts.py", "--data", str(stress_path), "--output-dir", str(stress_output)], cwd=ROOT, capture_output=True, text=True)
                ai = subprocess.run([sys.executable, "src/ai_payload.py", "--data", str(stress_path), "--output", str(stress_ai)], cwd=ROOT, capture_output=True, text=True)
                validation = subprocess.run([sys.executable, "src/validate_artifacts.py", "--output-dir", str(stress_output), "--ai-payload", str(stress_ai), "--assessment", str(stress_path), "--output", str(stress_validation)], cwd=ROOT, capture_output=True, text=True)
                manifest = subprocess.run([sys.executable, "src/artifact_manifest.py", "--output-dir", str(stress_output), "--assessment", str(stress_path), "--input", str(stress_ai), "--output", str(stress_manifest)], cwd=ROOT, capture_output=True, text=True)
                manifest_validation = subprocess.run([sys.executable, "src/validate_manifest.py", "--manifest", str(stress_manifest), "--output-dir", str(stress_output), "--input-dir", str(temporary), "--output", str(stress_manifest_validation)], cwd=ROOT, capture_output=True, text=True)
                artifacts_ready = all((stress_output / name).exists() and (stress_output / name).stat().st_size > 0 for name in ("assessment-action-plan.xlsx", "assessment-executive-summary.pptx", "assessment-executive-summary.pdf", "assessment-one-page-brief.pdf"))
                status = "pass" if result.returncode == 0 and export.returncode == 0 and ai.returncode == 0 and validation.returncode == 0 and manifest.returncode == 0 and manifest_validation.returncode == 0 and stress_html.exists() and stress_html.stat().st_size > 100000 and artifacts_ready else "fail"
                checks.append({"name": "scenario_large_scale5", "status": status, "detail": "Pipeline completo em stress sintético: HTML, PDF, PPTX, XLSX, payload IA, hashes e validação; aproximadamente 10 mil usuários e 12,5 mil recursos; não representa evidência de cliente."})
            except (OSError, ValueError) as exc:
                checks.append({"name": "scenario_large_scale5", "status": "fail", "detail": f"{type(exc).__name__}: {exc}"})
            try:
                first = simulate(base, "large", scale=5)
                second = simulate(base, "large", scale=5)
                deterministic = json.dumps(first, ensure_ascii=False, sort_keys=True) == json.dumps(second, ensure_ascii=False, sort_keys=True)
                checks.append({"name": "scenario_large_determinism", "status": "pass" if deterministic else "fail", "detail": "Duas gerações sintéticas grandes produziram contratos idênticos; não representa evidência de cliente."})
            except (OSError, ValueError, TypeError) as exc:
                checks.append({"name": "scenario_large_determinism", "status": "fail", "detail": f"{type(exc).__name__}: {exc}"})
    passed = sum(item["status"] == "pass" for item in checks)
    return {"status": "beta_ready" if passed == len(checks) else "blocked", "checks": checks, "passed": passed, "total": len(checks), "read_only": True, "note": "Gate executa somente mock/local; não autentica nem acessa tenant."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Valida prontidão do Assessment para beta")
    parser.add_argument("--data", type=Path, default=ROOT / "mock" / "assessment.json")
    parser.add_argument("--output", type=Path, default=ROOT / "runtime" / "beta-gate.json")
    parser.add_argument("--scenarios", default=",".join(SCENARIOS), help="Cenários sintéticos separados por vírgula; use vazio para não executar")
    args = parser.parse_args()
    scenarios = tuple(item.strip() for item in args.scenarios.split(",") if item.strip())
    invalid = set(scenarios) - set(SCENARIOS)
    if invalid:
        parser.error(f"cenários inválidos: {', '.join(sorted(invalid))}")
    result = run_gate(args.data, scenarios=scenarios)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Beta gate: {result['status']} ({result['passed']}/{result['total']})")
    if result["status"] != "beta_ready":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
