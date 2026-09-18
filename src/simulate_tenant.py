#!/usr/bin/env python3
"""Gera cenários offline para testar cobertura e falhas sem acessar tenant."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

SCENARIOS = {
    "small": "Tenant pequeno com poucos recursos e cobertura básica",
    "limited": "Tenant com módulos opcionais sem licença ou consentimento",
    "full": "Tenant demonstrativo com cobertura ampla e módulos disponíveis",
    "large": "Tenant sintético de escala para validar paginação, renderer e priorização",
}

DEFAULT_LARGE_SCALE = 1


def _set_log_status(data: dict, module: str, status: str, note: str) -> None:
    for item in data.get("discovery", {}).get("collection_log", []):
        if str(item.get("module", "")).lower() == module.lower():
            item.update({"status": status, "records": 0 if status != "success" else item.get("records", 1), "note": note})


def _large_inventory(discovery: dict, scale: int = DEFAULT_LARGE_SCALE) -> None:
    """Cria volume determinístico sem nomes, UPNs ou IDs de cliente reais."""
    size = max(1, int(scale))
    users = 2000 * size
    resources = 2500 * size
    devices = 1000 * size
    apps = 500 * size
    discovery["users"] = [{"id": f"synthetic-user-{index}", "account_type": "Member" if index % 12 else "Guest", "account_enabled": index % 31 != 0, "last_sign_in": "Never" if index % 17 == 0 else "2026-09-01", "mfa_status": "Registered" if index % 5 else "Not registered", "privileged": index % 47 == 0, "risk": "None"} for index in range(users)]
    discovery["resources"] = [{"id": f"synthetic-resource-{index}", "name": f"resource-{index}", "type": "Microsoft.Compute/virtualMachines" if index % 3 else "Microsoft.Storage/storageAccounts", "subscriptionId": "synthetic-subscription", "resourceGroup": f"rg-{index % 50}", "location": "synthetic", "tags": "owner, env" if index % 4 else "env", "exposure": "Public" if index % 19 == 0 else "Private"} for index in range(resources)]
    discovery["devices"] = [{"id": f"synthetic-device-{index}", "managed": index % 11 != 0, "compliant": index % 13 != 0, "platform": "Windows"} for index in range(devices)]
    discovery["enterprise_applications"] = [{"id": f"synthetic-enterprise-{index}", "name": f"enterprise-app-{index}"} for index in range(apps)]
    discovery["app_registrations"] = [{"id": f"synthetic-app-{index}", "credentials": 1 if index % 4 == 0 else 0, "expired_credentials": 1 if index % 29 == 0 else 0, "expiring_30d": 1 if index % 23 == 0 else 0} for index in range(apps // 2)]
    discovery["rbac"] = [{"role": "Owner" if index % 37 == 0 else "Reader", "scope_kind": "Subscription", "principal": f"synthetic-principal-{index}"} for index in range(800 * size)]
    discovery["policy_compliance"] = [{"policy": f"synthetic-policy-{index % 20}", "assignment": "synthetic-baseline", "subscription": "synthetic-subscription", "compliance_state": "NonCompliant" if index % 17 == 0 else "Compliant"} for index in range(1800 * size)]
    discovery["collection_log"] = [{"module": "Azure inventory", "source": "synthetic", "status": "success", "records": resources, "note": "Volume sintético; não representa evidência de cliente."}, {"module": "Identity", "source": "synthetic", "status": "success", "records": users, "note": "Volume sintético; não representa evidência de cliente."}, {"module": "Cost / lifecycle", "source": "synthetic", "status": "partial", "records": 0, "note": "HTTP 429 simulado; resultado não representa custo completo."}, {"module": "Defender", "source": "synthetic", "status": "not_available", "records": 0, "note": "HTTP 403 simulado; licença ou consentimento não disponível."}]


def simulate(data: dict, scenario: str, scale: int = DEFAULT_LARGE_SCALE) -> dict:
    """Aplica um perfil sintético sem modificar o objeto de entrada."""
    if scenario not in SCENARIOS:
        raise ValueError(f"Cenário inválido: {scenario}")
    result = copy.deepcopy(data)
    metadata = result.setdefault("metadata", {})
    discovery = result.setdefault("discovery", {})
    metadata["customer_name"] = f"SoftwareOne DEMO — {scenario.title()} tenant"
    metadata["run_id"] = f"simulation-{scenario}-offline"
    metadata["simulation"] = {"is_simulation": True, "scenario": scenario, "description": SCENARIOS[scenario], "evidence_status": "synthetic_not_customer_evidence"}

    if scenario == "small":
        metadata["scope"] = {"subscriptions": 1, "users_assessed": 12, "resources_assessed": 18}
        for key in ("users", "devices", "resources", "rbac", "policy_compliance", "enterprise_applications", "app_registrations", "pim_assignments"):
            if isinstance(discovery.get(key), list):
                discovery[key] = discovery[key][:2]
        metadata["modules"].update({"identity": "success", "security": "partial", "governance": "success", "cost": "not_available", "compliance": "partial"})
        _set_log_status(result, "Defender", "not_available", "Tenant DEMO sem Defender licenciado; comportamento esperado para módulo opcional.")
        _set_log_status(result, "Cost / lifecycle", "not_available", "Cost Management Reader não disponível no cenário DEMO.")
    elif scenario == "limited":
        metadata["modules"].update({"security": "partial", "cost": "not_available", "compliance": "partial"})
        _set_log_status(result, "Defender", "not_available", "HTTP 403 simulado; licença ou consentimento não disponível.")
        _set_log_status(result, "Cost / lifecycle", "partial", "HTTP 429 simulado; resultado não deve ser tratado como custo completo.")
        _set_log_status(result, "RBAC", "partial", "HTTP 403 simulado; herança e PIM exigem escopo adicional.")
    elif scenario == "large":
        _large_inventory(discovery, scale)
        metadata["scope"] = {"subscriptions": 1, "users_assessed": 2000 * max(1, scale), "resources_assessed": 2500 * max(1, scale), "devices_assessed": 1000 * max(1, scale)}
        metadata["modules"].update({"identity": "success", "security": "partial", "governance": "success", "cost": "partial", "compliance": "partial"})
    else:
        metadata["modules"].update({"identity": "success", "security": "success", "governance": "success", "cost": "success", "compliance": "success"})
        for item in discovery.get("collection_log", []):
            if item.get("status") in {"not_available", "partial"}:
                item["status"] = "success"
                item["note"] = "Disponível somente neste cenário sintético; não representa licença ou consentimento real."
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera tenant sintético offline para testes do assessment")
    parser.add_argument("--scenario", choices=tuple(SCENARIOS), default="small")
    parser.add_argument("--base", type=Path, default=Path("mock/assessment.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scale", type=int, default=DEFAULT_LARGE_SCALE, help="Multiplicador do cenário large; somente dados sintéticos")
    args = parser.parse_args()
    result = simulate(json.loads(args.base.read_text(encoding="utf-8")), args.scenario, args.scale)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Cenário sintético '{args.scenario}' gravado em {args.output}; nenhum tenant foi acessado.")


if __name__ == "__main__":
    main()
