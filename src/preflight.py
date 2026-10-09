#!/usr/bin/env python3
"""Assessment Readiness Gate: valida o ambiente antes da coleta read-only.
O gate não altera o tenant e não concede permissões.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from local_privacy import protect_output_parent

CLI_TIMEOUT = -2


def check(name: str, label: str, category: str, status: str, detail: str,
          impact: str, remediation: str, blocking: bool = False) -> dict:
    return {"name": name, "label": label, "category": category, "status": status,
            "detail": detail, "impact": impact, "remediation": remediation,
            "blocking": blocking}


def check_command(name: str) -> dict:
    try:
        result = subprocess.run(command_line([name, "--version"]), capture_output=True, text=True, timeout=15)
        status = "pass" if result.returncode == 0 else "blocked"
        return check(name, name, "local", status,
                     (result.stdout or result.stderr).strip()[:200],
                     "Sem este comando a coleta não inicia.",
                     f"Instale {name} e repita o readiness check.", True)
    except FileNotFoundError:
        return check(name, name, "local", "blocked", "Comando não encontrado",
                     "Sem este comando a coleta não inicia.",
                     f"Instale {name} e repita o readiness check.", True)
    except Exception as exc:
        return check(name, name, "local", "blocked", f"{type(exc).__name__}: {exc}",
                     "Não foi possível validar o executor.",
                     f"Corrija a execução de {name} antes de continuar.", True)


def run_cli(arguments: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        result = subprocess.run(command_line(arguments), capture_output=True, text=True, timeout=timeout)
        return result.returncode, (result.stdout or result.stderr).strip()
    except subprocess.TimeoutExpired:
        return CLI_TIMEOUT, "TimeoutExpired"
    except FileNotFoundError:
        return 1, "FileNotFoundError"


def command_line(arguments: list[str]) -> list[str]:
    """Resolve Azure CLI launcher on Windows, where it is commonly az.cmd."""
    if not arguments:
        return arguments
    executable = shutil.which(arguments[0])
    if executable and os.name == "nt" and Path(executable).suffix.lower() in {".cmd", ".bat"}:
        # Ask cmd.exe to resolve the launcher through PATH instead of passing
        # its absolute path (usually under "Program Files") through another
        # layer of Windows command-line quoting.
        launcher = Path(executable).name
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", launcher, *arguments[1:]]
    return [executable or arguments[0], *arguments[1:]]


def permission_check(subscription_ids: list[str]) -> dict:
    """Faz uma leitura mínima; não lista todo o inventário nem altera o tenant."""
    if not subscription_ids:
        return check("subscription_scope", "Escopo de subscriptions", "azure", "blocked",
                     "Nenhuma subscription informada", "Não há escopo Azure para avaliar.",
                     "Informe uma ou mais subscription IDs.", True)
    results = []
    for subscription_id in subscription_ids:
        code, output = run_cli(["az", "group", "list", "--subscription", subscription_id, "--query", "[0].name", "--output", "tsv"])
        results.append((subscription_id, code, output))
    accessible = [item for item in results if item[1] == 0]
    timed_out = [item for item in results if item[1] == CLI_TIMEOUT]
    real_failures = [item for item in results if item[1] != 0 and item[1] != CLI_TIMEOUT]
    if len(accessible) == len(results):
        return check("azure_reader", "Leitura Azure", "azure", "pass",
                     f"Subscription acessível ({len(subscription_ids)} no escopo)",
                     "O inventário e as consultas ARG podem ser executados.",
                     "Nenhuma ação necessária.")
    if timed_out and not (real_failures and not accessible):
        scope = ", ".join(item[0] for item in timed_out[:5])
        detail = f"Sonda inconclusiva por tempo em: {scope}; os coletores revalidam acesso por módulo."
        return check("azure_reader", "Leitura Azure", "azure", "warning", detail,
                     "A sonda não confirmou todo o escopo dentro do tempo limite.",
                     "Revise o resultado por módulo; não é necessário bloquear a coleta por esta sonda.")
    inaccessible = [item[0] for item in results if item[1] != 0]
    detail = f"{len(accessible)}/{len(results)} subscriptions acessíveis; inacessíveis: {', '.join(inaccessible[:5])}"
    if accessible:
        return check("azure_reader", "Leitura Azure", "azure", "warning", detail,
                     "A coleta continua, mas o resultado não representa todo o escopo informado.",
                     "Conceda Reader nas subscriptions pendentes ou remova-as do escopo aprovado.")
    error = next((item[2] for item in results if item[2]), "Subscriptions inacessíveis")
    return check("azure_reader", "Leitura Azure", "azure", "blocked", error[:240],
                 "Coletores Azure não terão evidência confiável.",
                 "Conceda Reader no escopo aprovado e repita o readiness check.", True)


def graph_session_check() -> dict:
    """Valida apenas a emissão do token Graph; nunca persiste ou imprime o token."""
    code, output = run_cli(["az", "account", "get-access-token", "--resource-type", "ms-graph",
                            "--query", "accessToken", "--output", "tsv"], timeout=30)
    if code == 0 and output:
        return check("graph_token", "Sessão Microsoft Graph", "graph", "pass",
                     "Token Graph emitido (valor não persistido)",
                     "A autenticação base para os coletores Graph está disponível.",
                     "Nenhuma ação necessária.")
    return check("graph_token", "Sessão Microsoft Graph", "graph", "warning",
                 "Token Graph não pôde ser validado pelo Azure CLI",
                 "Módulos Graph podem aparecer como não disponíveis.",
                 "Use az login novamente ou credencial de service principal com escopos aprovados.")


def estimate(subscription_count: int, profile: str, resource_probe: str = "unknown") -> dict:
    """Estimativa transparente; não é SLA e não influencia a coleta."""
    base = {"security": 12, "governance": 10, "full": 18}[profile]
    multiplier = max(1, subscription_count)
    if resource_probe == "large":
        multiplier += 2
    elif resource_probe == "medium":
        multiplier += 1
    low = base * multiplier
    high = low + (12 if profile == "full" else 8)
    return {"low_minutes": low, "high_minutes": high,
            "basis": "Estimativa baseada no perfil, número de subscriptions e volume aproximado; pode variar por paginação, throttling, licenças e retenção de logs."}


def module_readiness(profile: str) -> list[dict]:
    """Manifesto de cobertura: escopo esperado, sem alegar consentimento não verificado."""
    # Keep this matrix aligned with the collector dispatch in run_assessment.
    # ``not_checked`` means the profile invokes a collector for the module;
    # ``not_run`` means it is out of profile or has no implemented collector.
    modules = [
        ("Azure inventory", "Governança", ["Reader"], {"security", "governance", "full"}),
        ("Azure Policy / hierarchy", "Governança", ["Reader"], {"security", "governance", "full"}),
        ("RBAC / PIM", "Governança", ["Reader", "RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory", "Directory.Read.All"], {"governance", "full"}),
        ("Identity / users", "Identidade", ["User.Read.All"], {"security", "governance", "full"}),
        ("MFA / registration", "Identidade", ["Reports.Read.All"], {"security", "governance", "full"}),
        ("Conditional Access", "Segurança", ["Policy.Read.All"], {"security", "governance", "full"}),
        ("Sign-ins / legacy auth", "Segurança", ["AuditLog.Read.All"], {"security", "governance", "full"}),
        ("Secure Score", "Segurança", ["SecurityEvents.Read.All"], {"security", "governance", "full"}),
        ("Defender", "Segurança", ["SecurityIncident.Read.All", "Vulnerability.Read.All"], {"security", "governance", "full"}),
        ("Intune", "Segurança", ["DeviceManagementManagedDevices.Read.All"], {"security", "governance", "full"}),
        ("Cost Management", "FinOps", ["Cost Management Reader"], {"full"}),
        ("Power Platform", "Ecossistema", ["Reader / inventário ARG"], {"security", "governance", "full"}),
        ("Azure DevOps", "Ecossistema", ["AZDO_ORG_URL + PAT somente leitura"], {"full"}),
        ("Purview / Synapse / Databricks", "Dados", ["Reader / Resource Graph"], {"full"}),
        ("Directory audit", "Compliance", ["AuditLog.Read.All"], {"security", "governance", "full"}),
        ("Purview DLP / retention", "Compliance", ["Integração Purview específica / licenciamento"], set()),
        ("Power BI / Fabric", "Dados", ["Fabric admin ou Tenant.Read.All read-only"], {"full"}),
        ("M365 domain posture", "Segurança", ["DNS read-only; Domain.Read.All somente se os domínios forem descobertos pelo Graph"], {"security", "full"}),
    ]
    return [{"module": name, "domain": domain, "expected_read_scope": ", ".join(scopes),
             "status": "not_checked" if profile in active_profiles else "not_run",
             "detail": ("Perfil inclui o coletor; o status será confirmado pelo resultado, sem representar consentimento concedido." if profile in active_profiles
                        else "Fora do perfil ou sem coletor implementado; não será consultado nesta execução.")}
            for name, domain, scopes, active_profiles in modules]


def main() -> int:
    parser = argparse.ArgumentParser(description="Readiness Gate do assessment read-only")
    parser.add_argument("--subscriptions", required=True, help="IDs separados por vírgula")
    parser.add_argument("--profile", choices=("security", "governance", "full"), default="full")
    parser.add_argument("--output", type=Path, default=Path("runtime/preflight.json"))
    options = parser.parse_args()
    protect_output_parent(options.output)
    subscription_ids = [item.strip() for item in options.subscriptions.split(",") if item.strip()]
    checks: list[dict] = []
    python_supported = sys.version_info >= (3, 11)
    checks.append(check("python", "Python", "local", "pass" if python_supported else "blocked",
                        sys.version.split()[0], "O renderer e os coletores precisam de Python 3.11+.",
                        "Instale Python 3.11 ou superior.", not python_supported))
    checks.append(check_command("az"))
    credential_mode = "service_principal" if os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_TENANT_ID") else "azure_cli"
    checks.append(check("credential_mode", "Modo de credencial", "local", "pass",
                        credential_mode, "Define como a sessão será autenticada.", "Use Azure CLI ou service principal aprovado."))
    try:
        import azure.identity  # noqa: F401
        import azure.mgmt.resourcegraph  # noqa: F401
        checks.append(check("azure_sdk", "SDK Azure", "local", "pass",
                            "azure-identity + azure-mgmt-resourcegraph disponíveis",
                            "Necessário para consultas ARG e identidade.", "Nenhuma ação necessária."))
    except ImportError as exc:
        checks.append(check("azure_sdk", "SDK Azure", "local", "blocked", f"Dependência ausente: {exc}",
                            "Os coletores Azure não podem iniciar.", "Execute pip install -r requirements.txt.", True))

    code, output = run_cli(["az", "account", "show", "--output", "json"])
    if code == 0:
        try:
            account = json.loads(output)
            tenant = account.get("tenantId", "não informado")
            checks.append(check("azure_session", "Sessão Azure", "azure", "pass", f"Tenant {tenant}",
                                "A sessão Azure está ativa.", "Nenhuma ação necessária."))
        except json.JSONDecodeError:
            checks.append(check("azure_session", "Sessão Azure", "azure", "warning", "Resposta da sessão não é JSON",
                                "O tenant não pôde ser identificado com segurança.", "Execute az account show e repita."))
    else:
        checks.append(check("azure_session", "Sessão Azure", "azure", "blocked", "Execute az login ou configure service principal.",
                            "Sem sessão não há coleta confiável.", "Autentique no tenant aprovado e repita.", True))
    checks.append(permission_check(subscription_ids))
    checks.append(graph_session_check())
    config_path = Path(__file__).resolve().parents[1] / "config" / "assessment.yaml"
    config_ok = False
    try:
        import yaml
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        guards = config.get("guardrails", {})
        config_ok = guards.get("read_only") is True and not any(guards.get(key, False) for key in ("allow_write", "allow_delete", "allow_remediation"))
    except Exception:
        pass
    checks.append(check("read_only_guard", "Guardrail somente leitura", "safety", "pass" if config_ok else "blocked",
                        "read_only=true; escrita, exclusão e remediação desabilitadas" if config_ok else "Configuração de segurança ausente ou permissiva",
                        "Protege contra efeitos colaterais no tenant.", "Corrija config/assessment.yaml antes de executar.", not config_ok))
    checks.append(check("optional_modules", "Licenças e permissões opcionais", "coverage", "warning",
                        "Validação detalhada ocorre durante cada coletor",
                        "Módulos sem licença/consentimento serão marcados como não disponíveis, sem dados inventados.",
                        "Conceda somente os escopos aprovados se quiser ampliar a cobertura."))
    pim_read = ["RoleAssignmentSchedule.Read.Directory", "RoleEligibilitySchedule.Read.Directory", "RoleManagement.Read.Directory", "Directory.Read.All"]
    required = {"security": ["User.Read.All", "Reports.Read.All", "Policy.Read.All", "AuditLog.Read.All", "Reader"],
                "governance": ["Reader", *pim_read],
                "full": ["Reader", "Cost Management Reader", "User.Read.All", "Reports.Read.All", "Policy.Read.All", "AuditLog.Read.All", *pim_read]}[options.profile]
    optional = ["Group.Read.All", "Application.Read.All", "DelegatedPermissionGrant.Read.All", "LicenseAssignment.Read.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All", "SecurityEvents.Read.All", "SecurityIncident.Read.All", "Vulnerability.Read.All", "Fabric admin/Tenant.Read.All", "Azure DevOps PAT read-only", "Purview-specific read integration"]
    blocking = [item for item in checks if item.get("blocking") and item["status"] == "blocked"]
    warnings = [item for item in checks if item["status"] == "warning"]
    result = {"version": "1.0", "profile": options.profile, "subscriptions_requested": subscription_ids,
              "credential_mode": credential_mode, "checks": checks, "required_read_scopes": required, "optional_read_scopes": optional,
              "module_readiness": module_readiness(options.profile),
              "execution_decision": "blocked" if blocking else "run_full_with_limitations" if warnings else "run_full",
              "status": "blocked" if blocking else "ready",
              "summary": {"total": len(checks), "pass": sum(i["status"] == "pass" for i in checks),
                          "warning": len(warnings), "blocked": len(blocking)},
              "estimated_duration": estimate(len(subscription_ids), options.profile),
              "limitations": ["O readiness gate somente consulta e não concede permissões.",
                              "O assessment nunca altera, exclui, cria ou remedia objetos no tenant.",
                              "Cada API ainda pode retornar not_available por licença, consentimento, retenção ou throttling."]}
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
