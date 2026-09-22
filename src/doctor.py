#!/usr/bin/env python3
"""Diagnóstico operacional local antes de uma execução longa.

O doctor valida executor, sessão e espaço local. Ele não concede permissões,
não lista inventário completo e não altera o tenant.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from preflight import check, check_command, graph_session_check, module_readiness, permission_check, run_cli
from local_privacy import protect_output_parent


def local_checks(output: Path) -> list[dict]:
    checks = [check_command("python"), check_command("az")]
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        usage = shutil.disk_usage(output.parent)
        free_gb = usage.free / (1024 ** 3)
        checks.append(check("local_disk", "Espaço local", "local", "pass" if free_gb >= 1 else "warning",
                            f"{free_gb:.2f} GB livres", "O relatório e os checkpoints precisam de espaço local.",
                            "Use um Cloud Shell com clouddrive persistente ou libere espaço."))
        probe = output.parent / ".assessment-doctor-probe"
        probe.write_text("read-only-local-probe", encoding="utf-8")
        probe.unlink()
        checks.append(check("output_path", "Diretório de saída", "local", "pass",
                            str(output.parent), "Os artefatos poderão ser gravados localmente.", "Nenhuma ação necessária."))
    except OSError as exc:
        checks.append(check("output_path", "Diretório de saída", "local", "blocked", f"{type(exc).__name__}: {exc}",
                            "Os artefatos não poderão ser persistidos.", "Use um caminho gravável e persistente.", True))
    return checks


def diagnose(subscriptions: list[str], profile: str, output: Path) -> dict:
    checks = local_checks(output)
    account_code, account_output = run_cli(["az", "account", "show", "--output", "json"])
    if account_code == 0:
        try:
            account = json.loads(account_output)
            checks.append(check("tenant_context", "Tenant selecionado", "azure", "pass",
                                f"tenant={account.get('tenantId', 'não informado')}; subscription={account.get('id', 'não informado')}",
                                "A coleta será executada no contexto autenticado.", "Confirme visualmente o tenant antes de continuar."))
        except json.JSONDecodeError:
            checks.append(check("tenant_context", "Tenant selecionado", "azure", "blocked", "Resposta Azure inválida",
                                "O escopo não pode ser confirmado com segurança.", "Execute az account show novamente.", True))
    else:
        checks.append(check("tenant_context", "Tenant selecionado", "azure", "blocked", "Sessão Azure não encontrada",
                            "A coleta não pode começar.", "Execute az login --tenant <tenant-id>.", True))
    checks.append(permission_check(subscriptions))
    checks.append(graph_session_check())
    checks.append(check("read_only_contract", "Contrato read-only", "safety", "pass",
                        "Doctor não possui operações de criação, alteração ou exclusão.",
                        "Protege o escopo de execução.", "Nenhuma ação necessária."))
    blocking = [item for item in checks if item.get("blocking") and item.get("status") == "blocked"]
    warnings = [item for item in checks if item.get("status") == "warning"]
    return {
        "version": "1.0",
        "status": "blocked" if blocking else "ready_with_warnings" if warnings else "ready",
        "read_only": True,
        "profile": profile,
        "subscriptions_requested": subscriptions,
        "checks": checks,
        "module_readiness": module_readiness(profile),
        "summary": {"total": len(checks), "pass": sum(i["status"] == "pass" for i in checks), "warning": len(warnings), "blocked": len(blocking)},
        "next_step": "Execute o runner do assessment" if not blocking else "Corrija os checks bloqueados antes da coleta",
        "limitations": ["Permissões opcionais e licenças são confirmadas pelos coletores.", "Nenhuma alteração foi realizada no tenant."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnóstico operacional read-only")
    parser.add_argument("--subscriptions", required=True, help="IDs separados por vírgula")
    parser.add_argument("--profile", choices=("security", "governance", "full"), default="full")
    parser.add_argument("--output", type=Path, default=Path("runtime/doctor.json"))
    args = parser.parse_args()
    protect_output_parent(args.output)
    result = diagnose([item.strip() for item in args.subscriptions.split(",") if item.strip()], args.profile, args.output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
