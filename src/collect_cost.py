#!/usr/bin/env python3
"""Consulta agregada de custo do Azure Cost Management, sem alterar dados."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import time
from datetime import datetime, timezone


def collect(subscription_ids: list[str]) -> dict:
    from azure.identity import DefaultAzureCredential

    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = credential.get_token("https://management.azure.com/.default").token
    rows: list[dict] = []
    logs: list[dict] = []
    body = {
        "type": "ActualCost",
        "timeframe": "BillingMonthToDate",
        "dataset": {"granularity": "None", "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}}, "grouping": [{"type": "Dimension", "name": "ResourceId"}, {"type": "Dimension", "name": "ResourceGroupName"}]},
    }
    for subscription_id in subscription_ids:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
        try:
            payload = None
            for attempt in range(2):
                try:
                    with urllib.request.urlopen(request, timeout=60) as response:
                        payload = json.load(response)
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code != 429 or attempt == 1:
                        raise
                    retry_after = min(10, max(1, int(exc.headers.get("Retry-After", "3"))))
                    time.sleep(retry_after)
            if payload is None:
                raise RuntimeError("Cost Management não retornou payload")
            columns = [item.get("name") for item in payload.get("properties", {}).get("columns", [])]
            for values in payload.get("properties", {}).get("rows", []):
                rows.append(dict(zip(columns, values)))
            logs.append({"module": "Cost Management", "source": "Azure Cost Management API", "status": "success", "records": len(payload.get("properties", {}).get("rows", [])), "note": "Custo agregado do mês corrente; sem detalhamento de PII."})
        except urllib.error.HTTPError as exc:
            status = "partial" if exc.code == 429 else "not_available"
            logs.append({"module": "Cost Management", "source": "Azure Cost Management API", "status": status, "records": 0, "note": f"HTTP {exc.code}; valide Cost Management Reader e throttling no escopo da subscription."})
        except Exception as exc:
            logs.append({"module": "Cost Management", "source": "Azure Cost Management API", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"})
    return {"metadata": {"collected_at": started, "modules": {"cost": "success" if rows else "not_available"}}, "discovery": {"cost_summary": rows, "collection_log": logs}}
