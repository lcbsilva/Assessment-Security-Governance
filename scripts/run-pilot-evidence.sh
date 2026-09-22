#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python3 src/pilot_evidence.py \
  --preflight "${1:-runtime/preflight.json}" \
  --assessment "${2:-runtime/assessment.json}" \
  --pilot-validation "${3:-runtime/pilot-validation.json}" \
  --approval "${4:-config/pilot-approval.json}" \
  --output "${5:-runtime/pilot-evidence.json}"
