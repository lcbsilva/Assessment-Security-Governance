#!/usr/bin/env python3
"""Consulta agregada de custo do Azure Cost Management, sem alterar dados."""

from __future__ import annotations

import json
import statistics
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, parse_qs


def is_readonly_cost_query_url(url: str) -> bool:
    """Aceita somente o endpoint de consulta Cost Management por HTTPS."""
    parsed = urlsplit(str(url))
    parts = parsed.path.strip("/").split("/")
    return bool(
        parsed.scheme == "https"
        and parsed.hostname == "management.azure.com"
        and not parsed.username and not parsed.password
        and len(parts) == 5
        and parts[0].lower() == "subscriptions"
        and len(parts[1]) == 36
        and parts[2].lower() == "providers"
        and parts[3].lower() == "microsoft.costmanagement"
        and parts[4].lower() == "query"
        and "api-version" in parse_qs(parsed.query)
        and not parsed.fragment
    )


def query_cost(url: str, token: str, body: dict, attempts: int = 3) -> tuple[list[dict], str | None]:
    if not is_readonly_cost_query_url(url):
        return [], "Refused non-allowlisted read-only Cost Management query endpoint"
    if not isinstance(body, dict) or not {"type", "timeframe", "dataset"}.issubset(body):
        return [], "Refused Cost Management request without the read-only query contract"
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.load(response)
            columns = [item.get("name") for item in payload.get("properties", {}).get("columns", [])]
            return [dict(zip(columns, values)) for values in payload.get("properties", {}).get("rows", [])], None
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == attempts - 1:
                return [], f"HTTP {exc.code}"
            try:
                delay = min(15, max(1, int(exc.headers.get("Retry-After", "3"))))
            except (ValueError, AttributeError):
                delay = min(15, 2 ** attempt)
            time.sleep(delay)
        except Exception as exc:
            return [], f"{type(exc).__name__}: {exc}"
    return [], "Cost Management não retornou payload"


def amount(row: dict) -> float:
    try:
        return float(row.get("PreTaxCost", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def anomaly_summary(rows: list[dict]) -> dict:
    daily = defaultdict(float)
    for row in rows:
        date = row.get("UsageDate") or row.get("Date") or row.get("UsageStartDate")
        if date:
            daily[str(date)[:10]] += amount(row)
    values = list(daily.values())
    median = statistics.median(values) if values else 0.0
    threshold = max(median * 2.0, median + 1.0)
    anomalies = [{"date": date, "cost": round(value, 2), "baseline": round(median, 2), "signal": "Acima de 2x a mediana"} for date, value in sorted(daily.items()) if median and value > threshold]
    return {"days_observed": len(daily), "daily_median": round(median, 2), "daily_peak": round(max(values), 2) if values else 0.0, "anomaly_days": anomalies, "method": "Heurística conservadora; não é alerta oficial de anomalia."}


def collect(subscription_ids: list[str]) -> dict:
    from azure.identity import DefaultAzureCredential

    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = credential.get_token("https://management.azure.com/.default").token
    rows: list[dict] = []
    history_rows: list[dict] = []
    logs: list[dict] = []
    total_url = "https://management.azure.com/subscriptions/{}/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
    now = datetime.now(timezone.utc)
    for subscription_id in subscription_ids:
        url = total_url.format(subscription_id)
        current_body = {"type": "ActualCost", "timeframe": "BillingMonthToDate", "dataset": {"granularity": "None", "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}}, "grouping": [{"type": "Dimension", "name": "ResourceId"}, {"type": "Dimension", "name": "ResourceGroupName"}, {"type": "Dimension", "name": "ResourceType"}]}}
        current, error = query_cost(url, token, current_body)
        if error:
            logs.append({"module": "Cost Management", "source": "Azure Cost Management API", "status": "partial" if "429" in error else "not_available", "records": 0, "note": f"{error}; valide Cost Management Reader e throttling no escopo da subscription."})
            continue
        rows.extend(current)
        logs.append({"module": "Cost Management", "source": "Azure Cost Management API", "status": "success", "records": len(current), "note": "Custo agregado do mês corrente; sem detalhamento de PII."})
        history_body = {"type": "ActualCost", "timeframe": "Custom", "timePeriod": {"from": (now - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00Z"), "to": now.strftime("%Y-%m-%dT00:00:00Z")}, "dataset": {"granularity": "Daily", "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}}, "grouping": [{"type": "Dimension", "name": "ServiceName"}]}}
        history, history_error = query_cost(url, token, history_body)
        if not history_error:
            history_rows.extend(history)

    by_group = defaultdict(float)
    by_type = defaultdict(float)
    for row in rows:
        by_group[str(row.get("ResourceGroupName", "—"))] += amount(row)
        by_type[str(row.get("ResourceType", "—"))] += amount(row)
    total = sum(amount(row) for row in rows)
    finops_summary = {"cost_total_period": round(total, 2), "currency": next((row.get("Currency") for row in rows if row.get("Currency")), "—"), "resource_groups": len(by_group), "resource_types": len(by_type), "cost_by_resource_group": [{"resource_group": key, "cost": round(value, 2)} for key, value in sorted(by_group.items(), key=lambda item: item[1], reverse=True)], "cost_by_resource_type": [{"resource_type": key, "cost": round(value, 2)} for key, value in sorted(by_type.items(), key=lambda item: item[1], reverse=True)], "anomalies": anomaly_summary(history_rows), "reservations": "Não quantificado nesta API; exige inventário de benefícios/reservas autorizado.", "savings_plans": "Não quantificado nesta API; exige inventário de benefícios autorizado."}
    status = "success" if rows else ("partial" if logs and any(item["status"] == "partial" for item in logs) else "not_available")
    return {"metadata": {"collected_at": started, "modules": {"cost": status}}, "discovery": {"cost_summary": rows, "finops_summary": finops_summary, "cost_history": history_rows, "collection_log": logs}}
