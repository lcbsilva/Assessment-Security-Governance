#!/usr/bin/env python3
"""Executa os coletores reais e grava um contrato agregado para o renderer."""

from __future__ import annotations

import argparse
import os
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from collect_arg import collect as collect_arg
from collect_graph import collect as collect_graph
from collect_cost import collect as collect_cost
from collect_rbac import collect as collect_rbac
from collect_azure_devops import collect as collect_azure_devops
from collect_analytics import collect as collect_analytics
from collect_m365_posture import collect as collect_m365_posture
from score_normalized import derive
from contract import validate_payload, SCHEMA_VERSION
from readonly_guard import assert_read_only, execution_metadata
from generate_report import calculate
from history import record
from compare_runs import compare
from evidence_quality import classify, summarize
from insight_engine import risk_intersections, control_evidence, attach_finding_lineage, enrich_rbac_identity, cross_domain_insights, prioritize_findings
from version import engine_version
from execution_health import summarize as summarize_execution, coverage_map, build_execution_manifest
from checkpoint import load as load_checkpoint, scope_key, write as write_checkpoint
from local_privacy import protect_output_directory
from module_diagnostics import diagnose


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Assessment read-only Azure + Microsoft Graph")
    parser.add_argument("--subscriptions", default=os.getenv("AZURE_SUBSCRIPTION_IDS", ""))
    parser.add_argument("--output", default="runtime/assessment.json")
    parser.add_argument("--profile", choices=("security", "governance", "full"), default="full")
    parser.add_argument("--resume", action="store_true", default=os.getenv("ASSESSMENT_RESUME", "0") == "1", help="Retoma coletores concluídos a partir de checkpoints locais compatíveis")
    parser.add_argument("--engagement", default=os.getenv("ASSESSMENT_ENGAGEMENT", ""), help="YAML local opcional com branding e metadados do engagement")
    return parser.parse_args()


def load_engagement(path: Path) -> dict:
    """Carrega somente metadados locais; não amplia escopo nem permissões."""
    if not path.exists():
        return {}
    import yaml
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Arquivo de engagement deve conter um objeto YAML")
    allowed = {"customer_name", "engagement_name", "consultant_name", "classification"}
    return {key: str(value)[:200] for key, value in raw.items() if key in allowed and value not in (None, "")}


def skipped_module(name: str, source: str) -> dict:
    # Fora do perfil não é falha de API nem ausência de licença. Manter esse
    # estado explícito evita degradar artificialmente a qualidade da evidência.
    return {"metadata": {"modules": {name: "not_run"}}, "discovery": {"collection_log": [{"module": name.title(), "source": source, "status": "not_run", "records": 0, "note": "Módulo fora do perfil selecionado; não foi chamado."}]}}


def account_context() -> dict:
    """Obtém somente contexto da sessão Azure; não consulta nem altera recursos."""
    try:
        result = subprocess.run(["az", "account", "show", "--output", "json"], capture_output=True, text=True, timeout=15, check=True)
        account = json.loads(result.stdout)
        tenant_id = account.get("tenantId", "")
        return {"tenant_label": account.get("name", "Tenant não identificado"), "tenant_id_masked": f"{tenant_id[:8]}…" if tenant_id else "não informado"}
    except Exception:
        return {"tenant_label": "Tenant não identificado", "tenant_id_masked": "não informado"}


def safe_collect(name: str, collector, fallback: dict) -> tuple[str, dict]:
    """Executa um coletor isolado; falha de um módulo não derruba os demais."""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        result = collector()
        finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        duration = round(time.monotonic() - started, 2)
        result.setdefault("metadata", {}).setdefault("execution", {})
        result["metadata"]["execution"].update({"duration_seconds": duration, "attempted": True, "started_at": started_at, "finished_at": finished_at})
        for item in result.get("discovery", {}).get("collection_log", []):
            item.update({"started_at": started_at, "finished_at": finished_at, "duration_seconds": duration, "attempt": 1})
        return name, result
    except Exception as exc:
        finished_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        duration = round(time.monotonic() - started, 2)
        return name, {"metadata": {"modules": {name: "error"}, "execution": {"duration_seconds": duration, "attempted": True, "started_at": started_at, "finished_at": finished_at}}, "discovery": {"collection_log": [{"module": name, "source": "collector", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}", "started_at": started_at, "finished_at": finished_at, "duration_seconds": duration, "attempt": 1}]}}


def collector_status(name: str, result: dict) -> str:
    modules = result.get("metadata", {}).get("modules", {})
    if name in modules:
        return str(modules[name])
    logs = result.get("discovery", {}).get("collection_log", [])
    statuses = [str(item.get("status", "unknown")) for item in logs]
    if "error" in statuses:
        return "error"
    if "partial" in statuses:
        return "partial"
    if "success" in statuses:
        return "success"
    return statuses[0] if statuses else "unknown"


def print_progress(message: str) -> None:
    """Emite progresso em linhas simples, compatíveis com Cloud Shell e logs."""
    print(f"[Assessment] {message}", flush=True)


def main() -> None:
    options = args()
    protect_output_directory(Path(options.output).parent)
    config_path = Path(__file__).resolve().parents[1] / "config" / "assessment.yaml"
    import yaml
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert_read_only(config)
    engagement_path = Path(options.engagement) if options.engagement else Path(__file__).resolve().parents[1] / "config" / "engagement.yaml"
    engagement = load_engagement(engagement_path)
    subscription_ids = [item.strip() for item in options.subscriptions.split(",") if item.strip()]
    payload = {
        "metadata": {"engine_version": engine_version(), "schema_version": SCHEMA_VERSION, "run_id": f"assessment-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}", "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "scope": {}, "modules": {}, "execution": execution_metadata(), "profile": options.profile, "engagement": engagement, **engagement, **account_context()},
        "controls": [], "findings": [], "discovery": {"collection_log": []},
    }
    preflight_path = Path(options.output).parent / "preflight.json"
    if preflight_path.exists():
        try:
            payload["metadata"]["preflight"] = json.loads(preflight_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload["metadata"]["preflight"] = {"status": "not_available", "limitations": ["Readiness Gate não pôde ser lido."]}

    collectors = {
        "arg": (lambda: collect_arg(subscription_ids)) if options.profile in {"security", "governance", "full"} else (lambda: skipped_module("governance", "Azure Resource Graph")),
        "graph": (collect_graph) if options.profile in {"security", "governance", "full"} else (lambda: skipped_module("identity", "Microsoft Graph")),
        "cost": (lambda: collect_cost(subscription_ids)) if options.profile == "full" else (lambda: skipped_module("cost", "Azure Cost Management API")),
        "rbac": (lambda: collect_rbac(subscription_ids)) if options.profile in {"governance", "full"} else (lambda: skipped_module("governance", "AuthorizationResources")),
        # Integrações opcionais não devem ser chamadas em perfis focados.
        # Isso reduz permissões, duração e ruído no piloto de Segurança/Governança.
        "azure_devops": collect_azure_devops if options.profile == "full" else (lambda: skipped_module("azure_devops", "Azure DevOps")),
        "analytics": (lambda: collect_analytics(subscription_ids)) if options.profile == "full" else (lambda: skipped_module("analytics", "Purview / Fabric / Synapse / Databricks")),
        "m365": collect_m365_posture if options.profile in {"security", "full"} else (lambda: skipped_module("m365", "M365 domain posture")),
    }
    try:
        max_workers = min(3, max(1, int(os.getenv("ASSESSMENT_MAX_WORKERS", "2"))))
    except ValueError:
        max_workers = 2
    results: dict[str, dict] = {}
    checkpoint_root = Path(options.output).parent / "checkpoints"
    checkpoint_scope = scope_key(subscription_ids, options.profile)
    run_started = time.monotonic()
    run_started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload["metadata"]["execution"]["started_at"] = run_started_at
    print_progress(f"Perfil {options.profile} · somente leitura · preparando coletores")
    if options.resume:
        results = {name: cached for name, collector in collectors.items() if (cached := load_checkpoint(checkpoint_root, name, checkpoint_scope)) is not None}
    reused_collectors = sorted(results)
    if reused_collectors:
        print_progress("Retomados dos checkpoints: " + ", ".join(reused_collectors))
    pending_collectors = [name for name in collectors if name not in results]
    print_progress(f"Etapa 1/5 · coleta · {len(reused_collectors)} retomados, {len(pending_collectors)} a executar")
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="assessment") as pool:
        futures = {pool.submit(safe_collect, name, collectors[name], {}): name for name in pending_collectors}
        for future in as_completed(futures):
            name, result = future.result()
            results[name] = result
            write_checkpoint(checkpoint_root, name, checkpoint_scope, result)
            elapsed = result.get("metadata", {}).get("execution", {}).get("duration_seconds", 0)
            print_progress(f"Coletor {name}: {collector_status(name, result)} · {elapsed}s · checkpoint gravado")
    payload["metadata"]["execution"]["resumed_collectors"] = reused_collectors
    print_progress("Etapa 2/5 · consolidando evidências e normalizando controles")
    arg, graph, cost, rbac, devops, analytics, m365 = (results[key] for key in ("arg", "graph", "cost", "rbac", "azure_devops", "analytics", "m365"))
    payload["metadata"]["execution"]["collector_parallelism"] = max_workers
    payload["metadata"]["execution"]["resume_requested"] = options.resume
    payload["metadata"]["execution"]["checkpoint_scope"] = checkpoint_scope

    for module in (arg, graph, cost, rbac, devops, analytics, m365):
        payload["metadata"]["modules"].update(module.get("metadata", {}).get("modules", {}))
        payload["metadata"]["scope"].update(module.get("metadata", {}).get("scope", {}))
        payload["discovery"].update({key: value for key, value in module.get("discovery", {}).items() if key != "collection_log"})
        payload["discovery"]["collection_log"].extend(module.get("discovery", {}).get("collection_log", []))
    payload["metadata"]["scope"]["subscriptions"] = len(subscription_ids)
    for item in payload["discovery"]["collection_log"]:
        item.update(diagnose(str(item.get("module", "—")), str(item.get("status", "unknown")), str(item.get("note", ""))))
    payload["metadata"]["modules"].setdefault("security", "not_available")
    payload["metadata"]["modules"].setdefault("compliance", "not_available")
    payload["metadata"]["modules"].setdefault("cost", "not_available")
    payload["metadata"]["modules"].setdefault("azure_devops", "not_available")
    payload["metadata"]["modules"].setdefault("analytics", "not_available")
    payload["metadata"]["modules"].setdefault("m365", "not_available")
    payload["metadata"]["evidence_quality"] = summarize(payload["discovery"]["collection_log"])
    enrich_rbac_identity(payload["discovery"])
    for item in payload["discovery"]["collection_log"]:
        item["limitation_category"] = classify(item.get("status"), item.get("note"))
    payload["metadata"]["execution_health"] = summarize_execution(payload["discovery"]["collection_log"])
    payload["metadata"]["execution_manifest"] = build_execution_manifest(
        payload["discovery"]["collection_log"], options.profile, payload["metadata"]["execution"].get("tenant_mutation") is False
    )
    payload["metadata"]["coverage_map"] = coverage_map(payload["discovery"]["collection_log"], (payload["metadata"].get("preflight") or {}).get("module_readiness", []))
    catalog_path = Path(__file__).resolve().parents[1] / "catalog" / "controls.yaml"
    catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    payload = derive(payload, catalog)
    control_index = {item.get("id"): item for item in payload.get("controls", [])}
    for item in payload.get("findings", []):
        control = control_index.get(item.get("control_id"), {})
        item["evidence_state"] = control.get("evidence_state", "INSUFFICIENT_EVIDENCE")
        item["control_confidence"] = control.get("confidence", "low")
        item["license_gate_status"] = control.get("license_gate_status", "not_declared")
    cost_signal = payload["discovery"].get("lifecycle", {}).get("summary", {}).get("Custo mensal potencial", "Não quantificado")
    payload["discovery"]["risk_intersections"] = risk_intersections(payload["discovery"])
    payload["discovery"]["cross_domain_insights"] = cross_domain_insights(payload["discovery"])
    payload["metadata"]["evidence_by_control"] = control_evidence(payload, catalog)
    payload["findings"] = attach_finding_lineage(payload.get("findings", []), payload["metadata"]["evidence_by_control"])
    payload["findings"] = prioritize_findings(payload.get("findings", []), payload["metadata"].get("evidence_quality", {}), cost_signal)
    _, overall_score, coverage = calculate(catalog, payload)
    payload["metadata"]["overall_score"] = round(overall_score, 2) if overall_score is not None else None
    payload["metadata"]["coverage"] = round(coverage, 2)
    payload["metadata"]["score_methodology"] = {
        "name": "Score ponderado por controles disponíveis",
        "coverage_rule": "Controles not_available/error/not_run ou com evidência insuficiente são excluídos do denominador do score, mas reduzem a cobertura exibida.",
        "evidence_rule": "Ausência de evidência não é interpretada como conformidade.",
        "version": payload["metadata"].get("rules_version", "unknown"),
    }
    print_progress("Etapa 3/5 · score, cobertura e achados calculados")
    contract_errors = validate_payload(payload, catalog)
    payload["metadata"]["contract_status"] = "valid" if not contract_errors else "invalid"
    if contract_errors:
        payload["metadata"]["contract_errors"] = contract_errors
    print_progress(f"Etapa 4/5 · contrato {payload['metadata']['contract_status']}")
    payload["metadata"]["config_version"] = config.get("config_version", "unknown")
    payload["metadata"]["rules_version"] = catalog.get("catalog_version", "unknown")
    payload["metadata"]["focus"] = config.get("focus", {})
    payload["metadata"]["guardrails"] = config.get("guardrails", {})
    Path(options.output).parent.mkdir(parents=True, exist_ok=True)
    Path(options.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print_progress("Etapa 5/5 · assessment salvo; registrando histórico")
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
    payload["metadata"]["execution"]["finished_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload["metadata"]["execution"]["wall_duration_seconds"] = round(time.monotonic() - run_started, 1)
    payload["metadata"]["execution"]["started_at"] = run_started_at
    Path(options.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print_progress(f"Concluído · duração {payload['metadata']['execution']['wall_duration_seconds']}s · contrato {payload['metadata']['contract_status']}")
    print(f"Assessment agregado gravado em {options.output}")


if __name__ == "__main__":
    main()
