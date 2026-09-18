#!/usr/bin/env python3
"""Gate final da Beta: qualidade local, guardrails e documentação mínima."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from beta_gate import run_gate

ROOT = Path(__file__).resolve().parents[1]


def release_checks() -> list[dict]:
    config = yaml.safe_load((ROOT / "config" / "assessment.yaml").read_text(encoding="utf-8")) or {}
    guards = config.get("guardrails", {})
    required_docs = ("docs/PILOT-RUNBOOK.md", "docs/PERMISSIONS-MATRIX.md", "docs/SIMULATION-RUNBOOK.md", "docs/BETA-RELEASE-CHECKLIST.md", "docs/PRODUCT-TOUR.md", "docs/INTERNAL-DOGFOODING-PLAN.md", "docs/RUN-LOG-TEMPLATE.md")
    checks = [{"name": "version", "status": "pass" if (ROOT / "VERSION").read_text(encoding="utf-8").strip() else "fail", "detail": (ROOT / "VERSION").read_text(encoding="utf-8").strip()}]
    checks.append({"name": "readonly_config", "status": "pass" if guards.get("read_only") is True and guards.get("allow_write") is False and guards.get("allow_delete") is False and guards.get("allow_remediation") is False else "fail", "detail": "read_only=true; escrita, exclusão e remediação desabilitadas"})
    for document in required_docs:
        path = ROOT / document
        checks.append({"name": f"doc_{path.stem}", "status": "pass" if path.exists() and path.stat().st_size > 0 else "fail", "detail": document})
    return checks


def run_release_gate(data_path: Path) -> dict:
    checks = release_checks()
    beta = run_gate(data_path)
    checks.extend({"name": f"beta_{item['name']}", "status": item["status"], "detail": item.get("detail", "")} for item in beta["checks"])
    passed = sum(item["status"] == "pass" for item in checks)
    return {"status": "beta_release_ready" if passed == len(checks) else "blocked", "checks": checks, "passed": passed, "total": len(checks), "read_only": True, "note": "Gate local; não acessa nem altera tenant."}


def main() -> None:
    parser = argparse.ArgumentParser(description="Gate final de release Beta")
    parser.add_argument("--data", type=Path, default=ROOT / "mock" / "assessment.json")
    parser.add_argument("--output", type=Path, default=ROOT / "runtime" / "release-gate.json")
    args = parser.parse_args()
    result = run_release_gate(args.data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Release Gate: {result['status']} ({result['passed']}/{result['total']})")
    if result["status"] != "beta_release_ready":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
