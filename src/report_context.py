"""Resumo compartilhado de escopo, execução e limitações sem granularidade de recurso."""

from __future__ import annotations

from collections import Counter
from module_diagnostics import diagnose


SCOPE_LABELS = {
    "subscriptions": "Subscriptions no escopo",
    "users_assessed": "Usuários avaliados",
    "resources_assessed": "Recursos avaliados",
    "devices_assessed": "Dispositivos avaliados",
    "enterprise_applications": "Enterprise applications",
    "app_registrations": "App registrations",
    "groups_assessed": "Grupos avaliados",
    "licenses_assessed": "Licenças avaliadas",
    "signins_reviewed": "Sign-ins revisados",
    "legacy_auth_signins": "Sign-ins legados observados",
    "privileged_users_identified": "Contas privilegiadas identificadas",
}


def build(data: dict) -> dict:
    metadata = data.get("metadata", {}) or {}
    execution = metadata.get("execution", {}) or {}
    scope = metadata.get("scope", {}) or {}
    logs = data.get("discovery", {}).get("collection_log", []) or []
    counts = Counter(str(item.get("status", "unknown")) for item in logs)
    scope_rows = [
        {"label": label, "value": scope[key]}
        for key, label in SCOPE_LABELS.items()
        if isinstance(scope.get(key), (int, float))
    ]
    status_limitations = {
        "partial": "Coleta parcial; cobertura e paginação precisam ser consideradas.",
        "not_available": "Fonte indisponível nesta execução; use a causa provável do módulo antes de solicitar licença ou acesso.",
        "error": "Falha controlada; consultar causa provável e próximo passo antes de interpretar o domínio.",
        "not_run": "Módulo fora do perfil selecionado; não representa conformidade.",
    }
    limitations = []
    for item in logs:
        status = str(item.get("status"))
        if status not in status_limitations:
            continue
        diagnosis = diagnose(
            str(item.get("module", "")),
            status or "unknown",
            str(item.get("note", "")),
        )
        limitations.append({
            "module": item.get("module", "Módulo não identificado"),
            "status": item.get("status", "unknown"),
            "records": item.get("records", 0),
            "summary": status_limitations.get(status, "Validar observações no manifesto técnico."),
            "limitation_category": item.get("limitation_category") or diagnosis["limitation_category"],
            "likely_cause": item.get("likely_cause") or diagnosis["likely_cause"],
            "next_step": item.get("next_step") or diagnosis["next_step"],
        })
    return {
        "profile": metadata.get("profile", "não informado"),
        "run_id": metadata.get("run_id", "não informado"),
        "engine_version": metadata.get("engine_version", "não informado"),
        "classification": metadata.get("classification", "Confidencial — Security & Governance Assessment"),
        "started_at": execution.get("started_at", metadata.get("collected_at", "Não informado")),
        "finished_at": execution.get("finished_at", "Não informado"),
        "duration_seconds": execution.get("wall_duration_seconds"),
        "contract_status": metadata.get("contract_status", "não informado"),
        "scope_rows": scope_rows,
        "module_count": len(logs),
        "status_counts": dict(counts),
        "limitations": limitations,
    }
