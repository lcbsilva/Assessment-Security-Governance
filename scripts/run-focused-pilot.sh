#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Uso: ./scripts/run-focused-pilot.sh <subscription-id-1,subscription-id-2>"
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Piloto de Segurança: menor superfície, menor paralelismo e retomada segura.
export ASSESSMENT_MAX_WORKERS="${ASSESSMENT_MAX_WORKERS:-1}"
export ASSESSMENT_RESUME="${ASSESSMENT_RESUME:-1}"

./scripts/run-assessment.sh "$1" security
if ! python3 src/release_gate.py --data runtime/assessment.json --output runtime/release-gate.json; then
  echo "Checks que falharam:" >&2
  python3 - <<'PY'
import json
for item in json.load(open("runtime/release-gate.json", encoding="utf-8")).get("checks", []):
    if item.get("status") != "pass":
        print(f"- {item.get('name')}: {item.get('detail', '')}")
PY
  exit 1
fi

echo ""
echo "Piloto de Segurança concluído."
echo "HTML: $ROOT/dist/assessment.html"
echo "Validação: $ROOT/runtime/pilot-validation.json"
echo "Manifesto: $ROOT/runtime/assessment.json"
