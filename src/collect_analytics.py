#!/usr/bin/env python3
"""Inventário read-only de dados/analytics Azure e Power BI/Fabric.

Coleta somente metadados de existência, tipo, região, estado e capacidade.
Não acessa modelos, relatórios, datasets, notebooks, consultas, documentos,
usuários, permissões detalhadas, segredos ou dados de negócio.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from version import engine_version


ANALYTICS_QUERY = """
Resources
| where type has_any ('microsoft.purview', 'microsoft.synapse', 'microsoft.databricks', 'microsoft.fabric')
| project id, name, type, subscriptionId, resourceGroup, location, properties, sku
| order by type asc, name asc
""".strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def category(resource_type: str) -> str:
    value = resource_type.lower()
    if "purview" in value:
        return "Purview"
    if "synapse" in value:
        return "Synapse"
    if "databricks" in value:
        return "Databricks"
    if "fabric" in value:
        return "Fabric"
    return "Analytics"


def resource_row(item: dict) -> dict:
    properties = item.get("properties") or {}
    sku = item.get("sku") or {}
    return {
        "name": item.get("name", "—"),
        "type": item.get("type", "—"),
        "category": category(str(item.get("type", ""))),
        "subscription": item.get("subscriptionId", "—"),
        "resource_group": item.get("resourceGroup", "—"),
        "region": item.get("location", "—"),
        "state": properties.get("provisioningState") or properties.get("status") or "—",
        "sku": sku.get("name") or sku.get("tier") or "—",
    }


def powerbi_row(item: dict) -> dict:
    return {
        "name": item.get("name", "—"),
        "type": "Power BI/Fabric workspace",
        "category": "Power BI/Fabric SaaS",
        "state": item.get("state", "—"),
        "capacity_id_present": bool(item.get("capacityId")),
        "is_on_dedicated_capacity": bool(item.get("capacityId")),
    }


def collect(subscription_ids: list[str]) -> dict:
    started = utc_now()
    logs: list[dict] = []
    rows: list[dict] = []
    powerbi_rows: list[dict] = []

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        client = ResourceGraphClient(credential)
        response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=ANALYTICS_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        rows = [resource_row(item) for item in (response.data or [])]
        by_category = {name: sum(1 for row in rows if row["category"] == name) for name in ("Purview", "Synapse", "Databricks", "Fabric")}
        for name, count in by_category.items():
            logs.append({"module": name, "source": "Azure Resource Graph", "status": "success", "records": count,
                         "note": "Metadados de recursos Azure; conteúdo e dados de negócio não coletados."})
    except Exception as exc:
        for name in ("Purview", "Synapse", "Databricks", "Fabric"):
            logs.append({"module": name, "source": "Azure Resource Graph", "status": "not_available", "records": 0,
                         "note": f"Inventário indisponível: {type(exc).__name__}: {exc}"})

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        token = credential.get_token("https://analysis.windows.net/powerbi/api/.default").token
        request = urllib.request.Request(
            "https://api.powerbi.com/v1.0/myorg/admin/groups?$top=5000",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
        powerbi_rows = [powerbi_row(item) for item in payload.get("value", [])]
        logs.append({"module": "Power BI / Fabric workspaces", "source": "Power BI Admin REST API", "status": "success",
                     "records": len(powerbi_rows), "note": "Metadados de workspaces; requer Fabric admin ou escopo Tenant.Read.All."})
    except urllib.error.HTTPError as exc:
        logs.append({"module": "Power BI / Fabric workspaces", "source": "Power BI Admin REST API", "status": "not_available",
                     "records": 0, "note": f"HTTP {exc.code}; requer Fabric admin, configuração de API ou Tenant.Read.All."})
    except Exception as exc:
        logs.append({"module": "Power BI / Fabric workspaces", "source": "Power BI Admin REST API", "status": "not_available",
                     "records": 0, "note": f"API opcional indisponível: {type(exc).__name__}: {exc}"})

    summary = {
        "azure_resources": len(rows),
        "purview": sum(1 for row in rows if row["category"] == "Purview"),
        "synapse": sum(1 for row in rows if row["category"] == "Synapse"),
        "databricks": sum(1 for row in rows if row["category"] == "Databricks"),
        "fabric_azure": sum(1 for row in rows if row["category"] == "Fabric"),
        "powerbi_fabric_workspaces": len(powerbi_rows),
    }
    return {
        "metadata": {"engine_version": engine_version(), "run_id": f"analytics-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
                     "collected_at": started, "scope": summary, "modules": {"analytics": "success" if any(item.get("status") == "success" for item in logs) else "not_available"}},
        "discovery": {"analytics_resources": rows, "powerbi_workspaces": powerbi_rows, "analytics_summary": summary, "collection_log": logs},
    }
