#!/usr/bin/env python3
"""Gera um dashboard offline a partir de snapshots históricos locais.

O módulo não acessa Azure, Microsoft Graph ou qualquer serviço externo. Ele lê
somente snapshots já produzidos por ``src/history.py`` e inclui no HTML apenas
métricas agregadas, sem usuários, recursos, IDs ou texto de evidência.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path

from trend_intelligence import build as build_trend_intelligence


def _number(value: object) -> float | int | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def load_history(history_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(history_dir.glob("*.json"), key=lambda item: item.stat().st_mtime):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        scope = {key: value for key, value in (raw.get("scope") or {}).items() if _number(value) is not None}
        modules = raw.get("modules") or {}
        module_statuses: dict[str, int] = {}
        if isinstance(modules, dict):
            for value in modules.values():
                status = str(value.get("status", "unknown")) if isinstance(value, dict) else str(value)
                module_statuses[status] = module_statuses.get(status, 0) + 1
        rows.append({
            "run_id": str(raw.get("run_id", path.stem)),
            "collected_at": str(raw.get("collected_at", "")),
            "engine_version": str(raw.get("engine_version", "unknown")),
            "overall_score": _number(raw.get("overall_score")),
            "coverage": _number(raw.get("coverage")),
            "scope": scope,
            "module_statuses": module_statuses,
        })
    return rows


def render(history_dir: Path) -> str:
    rows = load_history(history_dir)
    latest = rows[-1] if rows else {}
    snapshots = []
    for path in sorted(history_dir.glob("*.json"), key=lambda item: item.stat().st_mtime):
        try:
            snapshots.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    trends = build_trend_intelligence(snapshots)
    latest_interval = trends.get("intervals", [])[-1] if trends.get("intervals") else {}
    payload = json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    latest_score = latest.get("overall_score", "N/D")
    latest_coverage = latest.get("coverage", "N/D")
    table_rows = "".join(
        f"<tr><td>{html.escape(row['collected_at'])}</td>"
        f"<td>{html.escape(row['engine_version'])}</td>"
        f"<td>{html.escape(str(row['overall_score'] if row['overall_score'] is not None else 'N/D'))}</td>"
        f"<td>{html.escape(str(row['coverage'] if row['coverage'] is not None else 'N/D'))}</td>"
        f"<td>{html.escape(', '.join(f'{key}: {value}' for key, value in sorted(row['module_statuses'].items())) or 'N/D')}</td></tr>"
        for row in reversed(rows)
    )
    empty = "<p class='notice'>Nenhum snapshot disponível. Execute um assessment autorizado para iniciar o histórico local.</p>" if not rows else ""
    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SoftwareOne · Histórico do Assessment</title>
<style>
:root {{ color-scheme: light; --blue:#005a8d; --navy:#172033; --ink:#233247; --line:#d9e2ec; --soft:#f4f8fb; }}
* {{ box-sizing:border-box; }} body {{ margin:0; background:#f6f8fb; color:var(--ink); font:15px/1.5 Segoe UI,Arial,sans-serif; }}
main {{ max-width:1180px; margin:32px auto; padding:0 20px; }} header {{ background:var(--navy); color:#fff; border-radius:16px; padding:28px 30px; }}
h1 {{ margin:0 0 6px; font-size:28px; }} header p {{ margin:0; color:#b9c9dc; }} .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:18px 0; }}
.card,.panel {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:20px; box-shadow:0 3px 12px #1720330d; }} .label {{ color:#61738a; font-size:13px; }} .value {{ color:var(--blue); font-size:30px; font-weight:700; margin-top:4px; }}
table {{ border-collapse:collapse; width:100%; }} th,td {{ border-bottom:1px solid var(--line); padding:12px 10px; text-align:left; vertical-align:top; }} th {{ background:var(--soft); color:#4c6178; font-size:13px; }}
.notice {{ background:#fff8e6; border-left:4px solid #d98b00; padding:12px 14px; border-radius:8px; }} footer {{ color:#61738a; margin-top:18px; font-size:13px; }}
@media(max-width:720px) {{ .cards {{ grid-template-columns:1fr; }} main {{ margin:16px auto; padding:0 12px; }} table {{ display:block; overflow-x:auto; white-space:nowrap; }} }}
</style></head><body><main>
<header><h1>Histórico do Assessment</h1><p>SoftwareOne Security &amp; Governance · visão local de tendências</p></header>
<section class="cards"><div class="card"><div class="label">Execuções registradas</div><div class="value">{len(rows)}</div></div>
<div class="card"><div class="label">Score mais recente</div><div class="value">{html.escape(str(latest_score))}</div></div>
<div class="card"><div class="label">Cobertura mais recente</div><div class="value">{html.escape(str(latest_coverage))}</div></div>
<div class="card"><div class="label">Δ controles comparáveis</div><div class="value">{html.escape(str(latest_interval.get("average_control_delta", "N/D")))}</div></div></section>
<section class="panel"><h2>Leitura de tendência</h2><p>O delta considera somente controles comparáveis com evidência válida. Mudanças de cobertura são exibidas separadamente e não significam melhoria automática de postura.</p><p><strong>Δ cobertura mais recente:</strong> {html.escape(str(latest_interval.get("coverage_delta", "N/D")))}</p></section>
<section class="panel"><h2>Evolução por execução</h2>{empty}<table><thead><tr><th>Coleta</th><th>Engine</th><th>Score</th><th>Cobertura</th><th>Status dos módulos</th></tr></thead><tbody>{table_rows}</tbody></table></section>
<footer>Somente leitura · dados agregados locais · nenhum tenant foi acessado para gerar esta página.</footer>
<script>window.historySnapshots={payload};</script>
</main></body></html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera dashboard offline do histórico local")
    parser.add_argument("--history-dir", type=Path, default=Path("runtime/history"))
    parser.add_argument("--output", type=Path, default=Path("dist/history-dashboard.html"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(args.history_dir), encoding="utf-8")
    print(f"Dashboard histórico gravado em {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
