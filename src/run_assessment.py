#!/usr/bin/env python3
"""Executa os coletores reais e grava um contrato agregado para o renderer."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from collect_arg import collect as collect_arg
from collect_graph import collect as collect_graph
from collect_cost import collect as collect_cost
from collect_rbac import collect as collect_rbac
from score_normalized import derive
from contract import validate_payload
from readonly_guard import assert_read_only, execution_metadata
from generate_report import calculate
from history import record
from compare_runs import compare
from evidence_quality import classify, summarize
from insight_engine import risk_intersections, control_evidence


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assessment read-only Azure + Microsoft Graph")
    parser.add_argument("--subscriptions", default=os.getenv("AZURE_SUBSCRIPTION_IDS", ""))
    parser.add_argument("--output", default="runtime/assessment.json")
    parser.add_argument("--profile", choices=("security", "governance", "full"), default="full")
    return parser.parse_args()


def skipped_module(name: str, source: str) -> dict:
    return {"metadata": {"modules": {name: "not_run"}}, "discovery": {"collection_log": [{"module": name.title(), "source": source, "status": "not_available", "records": 0, "note": "Módulo não selecionado no perfil de execução."}]}}


def account_context() -> dict:
    """Obtém somente contexto da sessão Azure; não consulta nem altera recursos."""
    try:
        result = subprocess.run(["az", "account", "show", "--output", "json"], capture_output=True, text=True, timeout=15, check=True)
        account = json.loads(result.stdout)
        tenant_id = account.get("tenantId", "")
        return {"tenant_label": account.get("name", "Tenant não identificado"), "tenant_id_masked": f"{tenant_id[:8]}…" if tenant_id else "não informado"}
    except Exception:
        return {"tenant_label": "Tenant não identificado", "tenant_id_masked": "não informado"}


def main() -> None:
    options = args()
    config_path = Path(__file__).resolve().parents[1] / "config" / "assessment.yaml"
    import yaml
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert_read_only(config)
    subscription_ids = [item.strip() for item in options.subscriptions.split(",") if item.strip()]
    payload = {
        "metadata": {"engine_version": "0.1.8", "run_id": f"assessment-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}", "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "scope": {}, "modules": {}, "execution": execution_metadata(), "profile": options.profile, **account_context()},
        "controls": [], "findings": [], "discovery": {"collection_log": []},
    }

    try:
        arg = collect_arg(subscription_ids) if options.profile in {"security", "governance", "full"} else skipped_module("governance", "Azure Resource Graph")
    except Exception as exc:
        arg = {"metadata": {"modules": {"governance": "error"}}, "discovery": {"collection_log": [{"module": "Azure inventory", "source": "Azure Resource Graph", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"}]}}
    try:
        graph = collect_graph() if options.profile in {"security", "governance", "full"} else skipped_module("identity", "Microsoft Graph")
    except Exception as exc:
        graph = {"metadata": {"modules": {"identity": "error"}}, "discovery": {"collection_log": [{"module": "Identity", "source": "Microsoft Graph", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"}]}}
    try:
        cost = collect_cost(subscription_ids) if options.profile == "full" else skipped_module("cost", "Azure Cost Management API")
    except Exception as exc:
        cost = {"metadata": {"modules": {"cost": "error"}}, "discovery": {"collection_log": [{"module": "Cost Management", "source": "Azure Cost Management API", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"}]}}
    try:
        rbac = collect_rbac(subscription_ids) if options.profile in {"governance", "full"} else skipped_module("governance", "AuthorizationResources")
    except Exception as exc:
        rbac = {"metadata": {"modules": {"governance": "error"}}, "discovery": {"collection_log": [{"module": "RBAC", "source": "AuthorizationResources / Azure Resource Graph", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"}]}}

    for module in (arg, graph, cost, rbac):
        payload["metadata"]["modules"].update(module.get("metadata", {}).get("modules", {}))
        payload["metadata"]["scope"].update(module.get("metadata", {}).get("scope", {}))
        payload["discovery"].update({key: value for key, value in module.get("discovery", {}).items() if key != "collection_log"})
        payload["discovery"]["collection_log"].extend(module.get("discovery", {}).get("collection_log", []))
    payload["metadata"]["scope"]["subscriptions"] = len(subscription_ids)
    payload["metadata"]["modules"].setdefault("security", "not_available")
    payload["metadata"]["modules"].setdefault("compliance", "not_available")
    payload["metadata"]["modules"].setdefault("cost", "not_available")
    payload["metadata"]["evidence_quality"] = summarize(payload["discovery"]["collection_log"])
    for item in payload["discovery"]["collection_log"]:
        item["limitation_category"] = classify(item.get("status"), item.get("note"))
    catalog_path = Path(__file__).resolve().parents[1] / "catalog" / "controls.yaml"
    catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    payload = derive(payload, catalog)
    payload["discovery"]["risk_intersections"] = risk_intersections(payload["discovery"])
    payload["metadata"]["evidence_by_control"] = control_evidence(payload, catalog)
    _, overall_score, coverage = calculate(catalog, payload)
    payload["metadata"]["overall_score"] = round(overall_score, 2)
    payload["metadata"]["coverage"] = round(coverage, 2)
    contract_errors = validate_payload(payload, catalog)
    payload["metadata"]["contract_status"] = "valid" if not contract_errors else "invalid"
    if contract_errors:
        payload["metadata"]["contract_errors"] = contract_errors
    payload["metadata"]["config_version"] = config.get("config_version", "unknown")
    payload["metadata"]["focus"] = config.get("focus", {})
    payload["metadata"]["guardrails"] = config.get("guardrails", {})
    Path(options.output).parent.mkdir(parents=True, exist_ok=True)
    Path(options.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    history_path = record(payload, Path(options.output).parent / "history")
    payload["metadata"]["history_path"] = str(history_path)
    previous_runs = sorted((Path(options.output).parent / "history").glob("*.json"), key=lambda item: item.stat().st_mtime)
    if len(previous_runs) > 1:
        previous_data = json.loads(previous_runs[-2].read_text(encoding="utf-8"))
        current_history = json.loads(history_path.read_text(encoding="utf-8"))
        comparison_path = Path(options.output).parent / "run-comparison.json"
        comparison = compare(previous_data, current_history)
        comparison_path.write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
        payload["comparison"] = comparison
        payload["metadata"]["comparison_path"] = str(comparison_path)
    Path(options.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Assessment agregado gravado em {options.output}")


if __name__ == "__main__":
    main()
