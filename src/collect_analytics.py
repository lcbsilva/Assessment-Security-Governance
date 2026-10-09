#!/usr/bin/env python3
"""Inventário read-only de dados/analytics Azure e Power BI/Fabric.

Coleta somente metadados de existência, tipo, região, estado e capacidade.
Não acessa modelos, relatórios, datasets, notebooks, consultas, documentos,
usuários, permissões detalhadas, segredos ou dados de negócio.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from collect_arg import arg_result_note, arg_result_status, query_arg_all_pages
from version import engine_version


ANALYTICS_QUERY = """
Resources
| where type has_any ('microsoft.purview', 'microsoft.synapse', 'microsoft.databricks', 'microsoft.fabric')
| project id, name, type, subscriptionId, resourceGroup, location, properties, sku
| order by id asc
""".strip()

POWERBI_GROUPS_ENDPOINT = "https://api.powerbi.com/v1.0/myorg/admin/groups"
POWERBI_PAGE_SIZE = 5000


def aggregate_status(statuses: list[str]) -> str:
    normalized = [str(status).casefold() for status in statuses]
    if normalized and all(status == "success" for status in normalized):
        return "success"
    if any(status in {"success", "partial"} for status in normalized):
        return "partial"
    return "not_available"


def powerbi_page_limit() -> int:
    try:
        return min(10, max(1, int(os.getenv("ASSESSMENT_POWERBI_MAX_PAGES", "10"))))
    except ValueError:
        return 10


def collect_analytics_resources(client: object, subscription_ids: list[str], QueryRequest: object, QueryRequestOptions: object) -> tuple[list[dict], str, str]:
    result = query_arg_all_pages(client, subscription_ids, ANALYTICS_QUERY, QueryRequest, QueryRequestOptions)
    status = arg_result_status(result)
    note = arg_result_note(
        "Inventário de Analytics",
        result,
        "Metadados de recursos Azure; conteúdo e dados de negócio não coletados.",
    )
    normalized = [resource_row(item) for item in result if isinstance(item, dict)]
    malformed = len(result) - len(normalized)
    if malformed:
        if status == "success":
            status = "partial"
        note = f"{note}; {malformed} registro(s) com formato inválido foram excluídos da normalização."
    return normalized, status, note


def collect_powerbi_workspaces(token: str, opener=urllib.request.urlopen, sleep=time.sleep) -> tuple[list[dict], str, str, int]:
    """Paginates Power BI admin workspaces with a conservative request budget."""
    rows: list[dict] = []
    page_size = POWERBI_PAGE_SIZE
    max_pages = powerbi_page_limit()
    skip = 0
    pages = 0
    while pages < max_pages:
        if pages:
            # The admin endpoint is rate limited; keep each page request below
            # the documented 15 requests/minute limit.
            sleep(4)
        query = urllib.parse.urlencode({"$top": page_size, "$skip": skip})
        url = f"{POWERBI_GROUPS_ENDPOINT}?{query}"
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            method="GET",
        )
        payload = None
        for attempt in range(3):
            try:
                with opener(request, timeout=30) as response:
                    payload = json.load(response)
                break
            except urllib.error.HTTPError as exc:
                if exc.code != 429 or attempt == 2:
                    status = "partial" if rows else "not_available"
                    return rows, status, f"HTTP {exc.code}; paginação Power BI interrompida após {len(rows)} workspaces.", pages
                retry_after = (exc.headers or {}).get("Retry-After", "4")
                try:
                    delay = min(300, max(4, int(retry_after)))
                except (TypeError, ValueError):
                    delay = 4 * (attempt + 1)
                sleep(delay)
            except Exception as exc:
                status = "partial" if rows else "not_available"
                return rows, status, f"{type(exc).__name__}: {exc}; paginação Power BI interrompida após {len(rows)} workspaces.", pages

        if payload is None:
            status = "partial" if rows else "not_available"
            return rows, status, f"Power BI não retornou payload após {len(rows)} workspaces.", pages
        values = payload.get("value")
        if not isinstance(values, list):
            status = "partial" if rows else "not_available"
            return rows, status, f"Resposta Power BI sem lista 'value'; {len(rows)} workspaces preservados.", pages
        if any(not isinstance(item, dict) for item in values):
            status = "partial" if rows or values else "not_available"
            return rows, status, f"Resposta Power BI contém item fora do formato esperado; {len(rows)} workspaces preservados.", pages
        rows.extend(powerbi_row(item) for item in values)
        pages += 1
        skip += len(values)
        if len(values) < page_size:
            return rows, "success", f"Metadados de workspaces; paginação concluída em {pages} página(s). Requer Fabric admin ou escopo Tenant.Read.All.", pages

    return rows, "partial", f"Limite de {max_pages} páginas Power BI atingido; {len(rows)} workspaces preservados e a fonte ficou parcial.", pages


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
    properties = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    sku = item.get("sku") if isinstance(item.get("sku"), dict) else {}
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
        rows, inventory_status, inventory_note = collect_analytics_resources(
            client, subscription_ids, QueryRequest, QueryRequestOptions
        )
        by_category = {name: sum(1 for row in rows if row["category"] == name) for name in ("Purview", "Synapse", "Databricks", "Fabric")}
        for name, count in by_category.items():
            logs.append({"module": name, "source": "Azure Resource Graph", "status": inventory_status, "records": count,
                         "note": inventory_note})
    except Exception as exc:
        for name in ("Purview", "Synapse", "Databricks", "Fabric"):
            logs.append({"module": name, "source": "Azure Resource Graph", "status": "not_available", "records": 0,
                         "note": f"Inventário indisponível: {type(exc).__name__}: {exc}"})

    try:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        token = credential.get_token("https://analysis.windows.net/powerbi/api/.default").token
        powerbi_rows, powerbi_status, powerbi_note, powerbi_pages = collect_powerbi_workspaces(token)
        logs.append({"module": "Power BI / Fabric workspaces", "source": "Power BI Admin REST API", "status": powerbi_status,
                     "records": len(powerbi_rows), "pages": powerbi_pages, "note": powerbi_note})
    except Exception as exc:
        powerbi_status = "not_available"
        logs.append({"module": "Power BI / Fabric workspaces", "source": "Power BI Admin REST API", "status": powerbi_status,
                     "records": len(powerbi_rows), "pages": 0, "note": f"API opcional indisponível: {type(exc).__name__}: {exc}"})

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
                     "collected_at": started, "scope": summary, "modules": {"analytics": aggregate_status([item.get("status", "unknown") for item in logs])}},
        "discovery": {"analytics_resources": rows, "powerbi_workspaces": powerbi_rows, "analytics_summary": summary, "collection_log": logs},
    }
