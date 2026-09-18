#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v npx >/dev/null 2>&1; then
  echo "Node.js/npm não encontrados. Instale Node 18+ para executar os testes Playwright." >&2
  exit 2
fi
if [[ ! -d node_modules/@playwright/test ]]; then
  npm install --no-audit --no-fund
fi
PLAYWRIGHT_CACHE_DIR="${PLAYWRIGHT_BROWSERS_PATH:-${XDG_CACHE_HOME:-/tmp}/ms-playwright}"
if [[ ! -d "$PLAYWRIGHT_CACHE_DIR" ]]; then
  npx playwright install chromium
fi
python3 src/generate_report.py --data mock/assessment.json --output dist/assessment.html
npx playwright test
