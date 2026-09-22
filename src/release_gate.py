#!/usr/bin/env python3
"""Gate final da Beta: qualidade local, guardrails e documentação mínima."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

import yaml

from beta_gate import run_gate

ROOT = Path(__file__).resolve().parents[1]


def read_only_source_scan() -> dict:
    """Procura padrões de mutação no caminho de execução do assessment."""
    forbidden = re.compile(
        r"(?:az\s+[^\n]*(?:delete|create|update|deployment)|"
        r"(?:New|Set|Update|Remove)-Az\w+|"
        r"Invoke-MgGraphRequest[^\n]*(?:POST|PATCH|DELETE)|"
        r"(?:requests|client)\.(?:post|put|patch|delete)\s*\(|"
        r"Microsoft\.Storage/storageAccounts/listKeys/action|listKeys\s*\()",
        re.IGNORECASE,
    )
    targets = [
        *sorted((ROOT / "src").glob("collect*.py")),
        ROOT / "src" / "run_assessment.py",
        *sorted((ROOT / "scripts").glob("*.ps1")),
        *sorted((ROOT / "scripts").glob("*.sh")),
    ]
    findings = []
    for path in targets:
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(source.splitlines(), 1):
            if forbidden.search(line):
                findings.append(f"{path.relative_to(ROOT)}:{line_number}")
        if path.suffix == ".py":
            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                findings.append(f"{path.relative_to(ROOT)}:{exc.lineno or 1}: syntax error")
                continue
            function_stack: list[str] = []

            class QueryMethodVisitor(ast.NodeVisitor):
                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    function_stack.append(node.name)
                    self.generic_visit(node)
                    function_stack.pop()

                visit_AsyncFunctionDef = visit_FunctionDef

                def visit_Call(self, node: ast.Call) -> None:
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "Request":
                        method = next((item.value for item in node.keywords if item.arg == "method"), None)
                        if isinstance(method, ast.Constant) and str(method.value).upper() in {"POST", "PUT", "PATCH", "DELETE"}:
                            allowed_query = (
                                path.relative_to(ROOT).as_posix() == "src/collect_cost.py"
                                and function_stack[-1:] == ["query_cost"]
                                and "if not is_readonly_cost_query_url(url):" in source
                            )
                            if not allowed_query:
                                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: urllib Request {method.value} sem allowlist de consulta")
                    self.generic_visit(node)

            QueryMethodVisitor().visit(tree)
    return {
        "name": "source_read_only_scan",
        "status": "pass" if not findings else "fail",
        "detail": "Nenhuma chamada explícita de mutação detectada." if not findings else "; ".join(findings),
    }


def release_checks() -> list[dict]:
    config = yaml.safe_load((ROOT / "config" / "assessment.yaml").read_text(encoding="utf-8")) or {}
    guards = config.get("guardrails", {})
    required_docs = ("docs/PILOT-RUNBOOK.md", "docs/PERMISSIONS-MATRIX.md", "docs/SIMULATION-RUNBOOK.md", "docs/BETA-RELEASE-CHECKLIST.md", "docs/PRODUCT-TOUR.md", "docs/INTERNAL-DOGFOODING-PLAN.md", "docs/RUN-LOG-TEMPLATE.md", "docs/BETA-SCOPE-REVIEW.md", "docs/ENGAGEMENT-CONFIG.md", "docs/LAB-VALIDATION-RUNBOOK.md", "docs/SCORE-METHODOLOGY.md", "docs/SPRINT-DELIVERY-BETA61.md", "docs/SPRINT-DELIVERY-BETA62.md", "docs/SPRINT-DELIVERY-BETA63.md", "docs/SPRINT-DELIVERY-BETA64.md", "docs/SPRINT-DELIVERY-BETA65.md", "docs/SPRINT-DELIVERY-BETA66.md", "docs/SPRINT-DELIVERY-BETA67.md", "docs/ZERO-TRUST-IMPORT.md")
    checks = [{"name": "version", "status": "pass" if (ROOT / "VERSION").read_text(encoding="utf-8").strip() else "fail", "detail": (ROOT / "VERSION").read_text(encoding="utf-8").strip()}]
    checks.append({"name": "readonly_config", "status": "pass" if guards.get("read_only") is True and guards.get("allow_write") is False and guards.get("allow_delete") is False and guards.get("allow_remediation") is False else "fail", "detail": "read_only=true; escrita, exclusão e remediação desabilitadas"})
    checks.append(read_only_source_scan())
    cost_source = (ROOT / "src" / "collect_cost.py").read_text(encoding="utf-8")
    checks.append({
        "name": "readonly_cost_query_allowlist",
        "status": "pass" if "def is_readonly_cost_query_url" in cost_source and "if not is_readonly_cost_query_url(url):" in cost_source and "Microsoft.CostManagement/query" in cost_source else "fail",
        "detail": "POST permitido somente no endpoint HTTPS de consulta Cost Management com allowlist local.",
    })
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
