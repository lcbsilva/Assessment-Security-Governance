#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "Uso: ./scripts/run-doctor.sh <subscription-id-1,subscription-id-2> [security|governance|full]"
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python3 src/doctor.py --subscriptions "$1" --profile "${2:-full}" --output runtime/doctor.json
echo "Diagnóstico concluído. Consulte runtime/doctor.json antes da coleta."
