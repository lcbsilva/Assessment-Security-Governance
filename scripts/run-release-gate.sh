#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python3 src/release_gate.py --data "${1:-mock/assessment.json}" --output "${2:-runtime/release-gate.json}"
