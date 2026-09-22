#!/usr/bin/env python3
"""Coleta atribuições RBAC Azure via Azure Resource Graph, somente leitura."""

from __future__ import annotations

from datetime import datetime, timezone


ASSIGNMENTS_QUERY = """
AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| extend principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleDefinitionId=tostring(properties.roleDefinitionId), assignmentScope=tostring(properties.scope)
| project id, subscriptionId, principalId, principalType, roleDefinitionId, assignmentScope
""".strip()

ROLES_QUERY = """
AuthorizationResources
| where type =~ 'microsoft.authorization/roledefinitions'
| extend roleDefinitionId=tostring(properties.name), roleName=tostring(properties.roleName)
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


def collect(subscription_ids: list[str]) -> dict:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    client = ResourceGraphClient(credential)
    options = QueryRequestOptions(result_format="objectArray", top=5000)
    assignments = client.resources(QueryRequest(subscriptions=subscription_ids, query=ASSIGNMENTS_QUERY, options=options)).data or []
    roles = client.resources(QueryRequest(subscriptions=subscription_ids, query=ROLES_QUERY, options=options)).data or []
    role_map = {}
    for item in roles:
        role_id = str(item.get("roleDefinitionId", ""))
        role_map[role_id.lower()] = item.get("roleName", "Unknown")
        role_map[role_id.rsplit("/", 1)[-1].lower()] = item.get("roleName", "Unknown")
    rows = []
    for item in assignments:
        role_id = str(item.get("roleDefinitionId", ""))
        scope_kind, scope_level, inheritance = scope_details(item.get("assignmentScope", ""))
        role_name = role_map.get(role_id.lower(), role_map.get(role_id.rsplit("/", 1)[-1].lower(), role_id.rsplit("/", 1)[-1] or "Unknown"))
        risk_level, review_reason = access_risk(role_name, scope_kind)
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
    return {
        "metadata": {"collected_at": started, "modules": {"governance": "success"}},
        "discovery": {"rbac": rows, "rbac_summary": summarize_rbac_posture(rows), "collection_log": [{"module": "RBAC", "source": "AuthorizationResources / Azure Resource Graph", "status": "success", "records": len(rows), "note": "Atribuições e funções; PIM e revisão de acesso exigem enriquecimento adicional."}]},
    }
