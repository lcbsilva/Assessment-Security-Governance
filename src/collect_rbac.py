#!/usr/bin/env python3
"""Coleta atribuições RBAC Azure via Azure Resource Graph, somente leitura."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone


ASSIGNMENTS_QUERY = """
AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleDefinitionId=tostring(properties.roleDefinitionId), assignmentScope=tostring(properties.scope)
| order by id asc
| project id, subscriptionId, principalId, principalType, roleDefinitionId, assignmentScope
""".strip()

ROLES_QUERY = """
AuthorizationResources
| where type =~ 'microsoft.authorization/roledefinitions'
| extend roleDefinitionId=tostring(properties.name), roleName=tostring(properties.roleName)
| order by id asc
| project roleDefinitionId, roleName
""".strip()


def scope_details(scope: str) -> tuple[str, str, str]:
    """Classifica o escopo sem presumir herança efetiva."""
    value = str(scope or "")
    lowered = value.lower()
    if lowered.startswith("/providers/microsoft.management/managementgroups"):
        return "Management Group", "Management group", "Definido neste escopo"
    if "/resourcegroups/" in lowered:
        return "Resource Group", "Resource group", "Definido neste escopo"
    if "/subscriptions/" in lowered and "/resourcegroups/" not in lowered:
        return "Subscription", "Subscription", "Definido neste escopo"
    if value.startswith("/"):
        return "Resource", "Recurso", "Definido neste escopo"
    return "Unknown", "Desconhecido", "Herança não determinável pelo ARG"


def access_risk(role: str, scope_kind: str) -> tuple[str, str]:
    """Classifica risco de uma atribuição sem inferir uso efetivo da conta."""
    name = str(role or "").lower()
    privileged_roles = {"owner", "contributor", "user access administrator", "role based access control administrator"}
    if name in privileged_roles:
        level = "Crítico" if scope_kind in {"Management Group", "Subscription"} else "Alto"
        return level, "Função com capacidade ampla; confirmar necessidade, owner e revisão/PIM"
    if "administrator" in name or "security" in name:
        return "Alto", "Função administrativa; validar menor privilégio e elegibilidade"
    return "Moderado", "Validar necessidade, owner e periodicidade da revisão"


def summarize_rbac_posture(rows: list[dict]) -> dict:
    """Agrega blast radius de RBAC sem afirmar uso efetivo ou herança completa."""
    by_scope: dict[str, int] = {}
    by_role: dict[str, int] = {}
    for row in rows:
        scope = str(row.get("scope_kind") or "Unknown")
        role = str(row.get("role") or "Unknown")
        by_scope[scope] = by_scope.get(scope, 0) + 1
        by_role[role] = by_role.get(role, 0) + 1
    high_risk = sum(1 for row in rows if row.get("access_risk") in {"Crítico", "Alto"})
    critical = sum(1 for row in rows if row.get("access_risk") == "Crítico")
    permanent_unknown = sum(1 for row in rows if str(row.get("assignment_type", "")).lower() in {"permanent/unknown", "permanent", "unknown", ""})
    return {
        "assignments": len(rows),
        "high_risk_assignments": high_risk,
        "critical_assignments": critical,
        "permanent_or_unknown_assignments": permanent_unknown,
        "inheritance_note": "O escopo declarado é reportado; herança efetiva depende de enriquecimento e não é presumida.",
        "by_scope": [{"scope_kind": key, "assignments": value} for key, value in sorted(by_scope.items(), key=lambda item: (-item[1], item[0]))],
        "by_role": [{"role": key, "assignments": value} for key, value in sorted(by_role.items(), key=lambda item: (-item[1], item[0]))],
    }


def retryable_arg_error(error: Exception) -> bool:
    """Recognize Resource Graph throttling and transient service failures."""
    code = getattr(error, "status_code", None) or getattr(error, "status", None)
    return code in {429, 500, 502, 503, 504}


def query_arg_with_retry(client: object, request: object, attempts: int | None = None) -> object:
    """Retry only read-only Azure Resource Graph queries after transient errors."""
    if attempts is None:
        try:
            attempts = min(6, max(1, int(os.getenv("ASSESSMENT_ARG_MAX_ATTEMPTS", "3"))))
        except ValueError:
            attempts = 3
    for attempt in range(attempts):
        try:
            return client.resources(request)
        except Exception as error:
            if not retryable_arg_error(error) or attempt == attempts - 1:
                raise
            time.sleep(min(8, 2 ** attempt))
    raise RuntimeError("Azure Resource Graph did not return a response")


def query_all_pages(client: object, query: str, subscription_ids: list[str], QueryRequest: object, QueryRequestOptions: object) -> tuple[list[dict], str | None]:
    """Fetch every ARG page; return rows and an error note when coverage is incomplete."""
    rows: list[dict] = []
    skip_token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        options = QueryRequestOptions(result_format="objectArray", top=1000, skip_token=skip_token)
        request = QueryRequest(subscriptions=subscription_ids, query=query, options=options)
        try:
            response = query_arg_with_retry(client, request)
        except Exception as exc:
            note = f"{type(exc).__name__}: {exc}"
            return rows, note
        rows.extend(response.data or [])
        next_token = getattr(response, "skip_token", None)
        if not next_token:
            truncated = getattr(response, "result_truncated", False)
            if str(truncated).strip().casefold() in {"true", "1", "yes"}:
                return rows, "Azure Resource Graph informou resultado truncado sem skip_token; a coleta RBAC não pode ser declarada completa."
            return rows, None
        next_token = str(next_token)
        if next_token in seen_tokens:
            return rows, "Azure Resource Graph repetiu o skip_token; a paginação foi interrompida para evitar loop."
        seen_tokens.add(next_token)
        skip_token = next_token


def _collection_result(started: str, rows: list[dict], status: str, note: str) -> dict:
    return {
        "metadata": {"collected_at": started, "modules": {"governance": status}},
        "discovery": {
            "rbac": rows,
            "rbac_summary": summarize_rbac_posture(rows),
            "collection_log": [{
                "module": "RBAC",
                "source": "AuthorizationResources / Azure Resource Graph",
                "status": status,
                "records": len(rows),
                "note": note,
            }],
        },
    }


def collect(subscription_ids: list[str]) -> dict:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if not subscription_ids:
        return _collection_result(started, [], "not_available", "Nenhuma subscription foi informada; não é possível validar RBAC.")

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    client = ResourceGraphClient(credential)
    assignments, assignment_error = query_all_pages(
        client, ASSIGNMENTS_QUERY, subscription_ids, QueryRequest, QueryRequestOptions
    )
    if assignment_error and not assignments:
        return _collection_result(
            started, [], "not_available",
            f"Falha ao coletar atribuições RBAC: {assignment_error}",
        )

    roles, role_error = query_all_pages(
        client, ROLES_QUERY, subscription_ids, QueryRequest, QueryRequestOptions
    )
    role_map = {}
    for item in roles:
        role_id = str(item.get("roleDefinitionId", ""))
        role_map[role_id.lower()] = item.get("roleName", "Unknown")
        role_map[role_id.rsplit("/", 1)[-1].lower()] = item.get("roleName", "Unknown")
    rows = []
    unresolved_roles = 0
    for item in assignments:
        role_id = str(item.get("roleDefinitionId", ""))
        scope_kind, scope_level, inheritance = scope_details(item.get("assignmentScope", ""))
        resolved_role = role_map.get(role_id.lower(), role_map.get(role_id.rsplit("/", 1)[-1].lower()))
        if str(resolved_role or "").strip().lower() == "unknown":
            resolved_role = None
        role_name = resolved_role or role_id.rsplit("/", 1)[-1] or "Unknown"
        if resolved_role:
            risk_level, review_reason = access_risk(role_name, scope_kind)
        else:
            unresolved_roles += 1
            risk_level = "Não classificado"
            review_reason = "A definição desta função não foi resolvida; confirmar a função antes de avaliar privilégios."
        rows.append({
            "principal": item.get("principalId", "—"),
            "principal_type": item.get("principalType", "—"),
            "role": role_name,
            "scope": item.get("assignmentScope", "—"),
            "scope_kind": scope_kind,
            "scope_level": scope_level,
            "inheritance": inheritance,
            "role_id": role_id,
            "assignment_type": "Permanent/unknown",
            "pim": "Not collected",
            "review": "Requires review",
            "access_risk": risk_level,
            "review_reason": review_reason,
            "subscription": item.get("subscriptionId", "—"),
        })

    if assignment_error:
        status = "partial"
        note = f"Atribuições RBAC parcialmente coletadas: {assignment_error}"
    elif rows and (role_error or not roles or unresolved_roles):
        status = "partial"
        details = []
        if role_error:
            details.append(role_error)
        if not roles:
            details.append("nenhuma definição de função foi retornada para enriquecer as atribuições")
        if unresolved_roles:
            details.append(f"{unresolved_roles} atribuições usam uma definição de função não resolvida")
        note = "Atribuições coletadas, mas nomes/classificação de funções incompletos: " + "; ".join(details)
    else:
        status = "success"
        note = "Atribuições e definições de função paginadas e resolvidas no escopo informado; PIM e revisão de acesso exigem enriquecimento adicional."
    return _collection_result(started, rows, status, note)
