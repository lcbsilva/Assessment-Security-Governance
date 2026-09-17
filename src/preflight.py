#!/usr/bin/env python3
"""Valida requisitos locais antes de iniciar uma execução read-only."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def check_command(name: str) -> dict:
    try:
        result = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=15)
        return {"name": name, "status": "success" if result.returncode == 0 else "error", "detail": (result.stdout or result.stderr).strip()[:200]}
    except FileNotFoundError:
        return {"name": name, "status": "not_available", "detail": "Comando não encontrado"}
    except Exception as exc:
        return {"name": name, "status": "error", "detail": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Pré-flight do assessment read-only")
    parser.add_argument("--subscriptions", required=True, help="IDs separados por vírgula")
    parser.add_argument("--profile", choices=("security", "governance", "full"), default="full")
    parser.add_argument("--output", type=Path, default=Path("runtime/preflight.json"))
    options = parser.parse_args()
    subscription_ids = [item.strip() for item in options.subscriptions.split(",") if item.strip()]
    checks = [
        {"name": "python", "status": "success" if sys.version_info >= (3, 10) else "error", "detail": sys.version.split()[0]},
        check_command("az"),
    ]
    credential_mode = "service_principal" if os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_TENANT_ID") else "azure_cli"
    checks.append({"name": "credential_mode", "status": "configured", "detail": credential_mode})
    try:
        import azure.identity  # noqa: F401
        import azure.mgmt.resourcegraph  # noqa: F401
        checks.append({"name": "azure_sdk", "status": "success", "detail": "azure-identity + azure-mgmt-resourcegraph disponíveis"})
    except ImportError as exc:
        checks.append({"name": "azure_sdk", "status": "error", "detail": f"Dependência ausente: {exc}"})
    try:
        result = subprocess.run(["az", "account", "show", "--output", "json"], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            account = json.loads(result.stdout)
            checks.append({"name": "azure_session", "status": "success", "detail": f"Tenant {account.get('tenantId', 'não informado')}"})
        else:
            checks.append({"name": "azure_session", "status": "not_available", "detail": "Execute az login ou use credenciais de service principal."})
    except FileNotFoundError:
        checks.append({"name": "azure_session", "status": "not_available", "detail": "Azure CLI não instalado; use service principal configurado por ambiente."})
    except Exception as exc:
        checks.append({"name": "azure_session", "status": "error", "detail": f"{type(exc).__name__}: {exc}"})
    blocking = [item for item in checks if item["status"] == "error"]
    required = {"security": ["User.Read.All", "Reports.Read.All", "Policy.Read.All", "AuditLog.Read.All", "SecurityIncident.Read.All", "Reader"], "governance": ["Reader", "RoleManagement.Read.Directory", "Directory.Read.All"], "full": ["Reader", "Cost Management Reader", "User.Read.All", "Reports.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All"]}[options.profile]
    result = {"profile": options.profile, "subscriptions_requested": subscription_ids, "credential_mode": credential_mode, "checks": checks, "required_read_scopes": required, "status": "blocked" if blocking else "ready", "limitations": ["O pré-flight não concede permissões e não altera o tenant.", "Cada API ainda pode retornar not_available por licença ou escopo insuficiente."]}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
