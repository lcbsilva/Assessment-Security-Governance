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
    scope_notes = []
    license_log = next((item for item in logs if str(item.get("module", "")).lower() == "m365 licenses"), None)
    if scope.get("licenses_assessed") == 0 and license_log and license_log.get("status") != "success":
        scope_notes.append("Licenças não foram validadas nesta execução; zero não significa ausência de licenças.")
    status_limitations = {
        "partial": "Coleta parcial; cobertura e paginação precisam ser consideradas.",
        "not_available": "Fonte indisponível nesta execução; validar licença, permissão e disponibilidade.",
        "error": "Falha controlada; consultar o manifesto técnico confidencial.",
        "not_run": "Módulo fora do perfil selecionado; não representa conformidade.",
    }
    limitations = [
        {
            "module": item.get("module", "Módulo não identificado"),
            "status": item.get("status", "unknown"),
            "records": item.get("records", 0),
            "summary": status_limitations.get(str(item.get("status")), "Validar observações no manifesto técnico."),
            "limitation_category": item.get("limitation_category", diagnose(str(item.get("module", "")), str(item.get("status", "unknown")), str(item.get("note", "")))["limitation_category"]),
            "likely_cause": item.get("likely_cause", diagnose(str(item.get("module", "")), str(item.get("status", "unknown")), str(item.get("note", "")))["likely_cause"]),
            "next_step": item.get("next_step", diagnose(str(item.get("module", "")), str(item.get("status", "unknown")), str(item.get("note", "")))["next_step"]),
        }
        for item in logs if str(item.get("status")) in status_limitations
    ]
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
        "scope_notes": scope_notes,
        "module_count": len(logs),
        "status_counts": dict(counts),
        "limitations": limitations,
    }
