#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
OUTPUT_ROOT="${ASSESSMENT_MATRIX_OUTPUT:-runtime/synthetic-matrix}"

declare -a CASES=(small medium limited full large)

for scenario in "${CASES[@]}"; do
  scale=1
  if [[ "$scenario" == "large" ]]; then
    scale="${ASSESSMENT_MATRIX_LARGE_SCALE:-3}"
  fi
  target="$OUTPUT_ROOT/$scenario"
  "$PYTHON_BIN" src/build_demo_package.py \
    --output-root "$target" \
    --scenario "$scenario" \
    --scale "$scale" >/dev/null
  "$PYTHON_BIN" - "$target/runtime/demo-summary.json" <<'PY'
import json
import sys
from pathlib import Path

summary = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {
    "status": "ready_for_internal_demo",
    "read_only": True,
    "synthetic": True,
    "pilot_status": "ready_for_pilot_review",
    "artifact_integrity": "valid",
}
errors = [f"{key}={summary.get(key)!r}" for key, value in required.items() if summary.get(key) != value]
if errors:
    raise SystemExit("Matriz sintética inválida: " + ", ".join(errors))
if summary.get("scenario") == "large":
    assessment_path = Path(sys.argv[1]).parent / "assessment.json"
    assessment = json.loads(assessment_path.read_text(encoding="utf-8"))
    resource_count = len(assessment.get("discovery", {}).get("resources", []))
    if resource_count <= 5000:
        raise SystemExit(f"Cenário large precisa exceder o limite de página do ARG: {resource_count} recursos")
    print(f"[matrix] large excedeu 5000 recursos; inventário sintético={resource_count}")
print(f"[matrix] {summary['scenario']} validado; coverage={summary.get('coverage')}; score={summary.get('overall_score')}")
PY
done

echo "Matriz sintética concluída: ${#CASES[@]} cenários válidos."
