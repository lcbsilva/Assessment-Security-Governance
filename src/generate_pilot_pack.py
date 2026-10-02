#!/usr/bin/env python3
"""Gera um handoff local de pré-requisitos para um piloto read-only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def build(preflight: dict) -> str:
    profile = preflight.get("profile", "não informado")
    status = preflight.get("status", "unknown")
    required = preflight.get("required_read_scopes", [])
    optional = preflight.get("optional_read_scopes", [])
    modules = preflight.get("module_readiness", [])
    limitations = preflight.get("limitations", [])
    subscriptions = preflight.get("subscriptions_requested", [])
    lines = [
        "# Handoff do piloto — Assessment read-only",
        "",
        "> Documento gerado localmente. Não concede permissões, não autentica e não altera o tenant.",
        "",
        "## Decisão do readiness gate",
        "",
        f"- Perfil: `{profile}`",
        f"- Status: `{status}`",
        f"- Subscriptions no escopo: `{', '.join(subscriptions) if subscriptions else 'não informadas'}`",
        "- Modo: `read-only`",
        "",
        "## Permissões obrigatórias de leitura",
        "",
    ]
    lines.extend(f"- `{item}`" for item in required or ["Nenhuma listada"])
    lines.extend(["", "## Permissões e integrações opcionais", ""])
    lines.extend(f"- `{item}`" for item in optional or ["Nenhuma listada"])
    lines.extend(["", "## Módulos e escopo esperado", "", "| Módulo | Domínio | Escopo esperado | Estado |", "|---|---|---|---|"])
    for item in modules:
        lines.append(f"| {item.get('module', '—')} | {item.get('domain', '—')} | {item.get('expected_read_scope', '—')} | {item.get('status', 'not_checked')} |")
    lines.extend(["", "## Procedimento", "", "1. Confirmar o tenant e as subscriptions com o responsável.", "2. Conceder somente as permissões de leitura aprovadas.", "3. Executar o preflight e confirmar `status=ready` ou revisar warnings.", "4. Executar o perfil aprovado e guardar os artefatos técnicos como confidenciais.", "5. Conferir `pilot-validation.json`, cobertura, confiança e limitações antes de compartilhar.", "", "## Limitações registradas", ""])
    lines.extend(f"- {item}" for item in limitations or ["Nenhuma limitação registrada pelo preflight."])
    lines.extend(["", "## Regra de segurança", "", "O engine não cria, altera, exclui ou remedia objetos no tenant. Ausência de licença, permissão, retenção ou resposta de API permanece como limitação e não como conformidade.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Gera handoff local de pré-requisitos do piloto")
    parser.add_argument("--preflight", type=Path, default=Path("runtime/preflight.json"))
    parser.add_argument("--output", type=Path, default=Path("runtime/pilot-readiness-pack.md"))
    args = parser.parse_args()
    data = json.loads(args.preflight.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(build(data), encoding="utf-8")
    print(f"Handoff do piloto gravado em {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

