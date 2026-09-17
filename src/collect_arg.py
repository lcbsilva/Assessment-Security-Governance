#!/usr/bin/env python3
"""Coleta inventário Azure via Resource Graph, somente leitura.

Exemplo:
    python3 src/collect_arg.py \
      --subscriptions 00000000-0000-0000-0000-000000000000 \
      --output runtime/assessment-arg.json

Autenticação: DefaultAzureCredential. O processo usa a identidade já disponível
no ambiente (Azure CLI, Managed Identity, workload identity ou variável de
ambiente), sem receber segredo por argumento.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

QUERY = """
Resources
| project id, name, type, subscriptionId, resourceGroup, location, kind, sku, tags, properties
| order by type asc, name asc
""".strip()

POLICY_QUERY = """
PolicyResources
| where type =~ 'Microsoft.PolicyInsights/PolicyStates'
| extend complianceState=tostring(properties.complianceState), resourceId=tostring(properties.resourceId), policyAssignmentId=tostring(properties.policyAssignmentId), policyAssignmentName=tostring(properties.policyAssignmentName), policyDefinitionName=tostring(properties.policyDefinitionName), timestamp=todatetime(properties.timestamp)
| project subscriptionId, resourceId, policyAssignmentId, policyAssignmentName, policyDefinitionName, complianceState, timestamp
""".strip()

ORPHAN_QUERY = """
Resources
| where type =~ 'Microsoft.Compute/disks'
| where tostring(properties.diskState) =~ 'Unattached'
| project name, type, subscriptionId, resourceGroup, location, reason='Unattached', resourceId=id
| union (Resources | where type =~ 'Microsoft.Network/publicIPAddresses' | where isempty(properties.ipConfiguration) | project name, type, subscriptionId, resourceGroup, location, reason='Not associated', resourceId=id)
| union (Resources | where type =~ 'Microsoft.Network/networkInterfaces' | where isempty(properties.virtualMachine.id) | project name, type, subscriptionId, resourceGroup, location, reason='No VM association', resourceId=id)
""".strip()

RETIREMENT_QUERY = """
ServiceHealthResources
| where type =~ 'microsoft.resourcehealth/events'
| extend eventType=tostring(properties.EventType), title=tostring(properties.Title), status=tostring(properties.Status), impactStartTime=todatetime(properties.ImpactStartTime), lastUpdate=todatetime(properties.LastUpdateTime), trackingId=tostring(properties.TrackingId)
| where eventType =~ 'HealthAdvisory'
| project title, status, impactStartTime, lastUpdate, trackingId, subscriptionId
| order by impactStartTime asc
""".strip()

ADVISOR_QUERY = """
advisorresources
| where type =~ 'microsoft.advisor/recommendations'
| extend recommendationStatus=tostring(properties.recommendationStatus), category=tostring(properties.category), impact=tostring(properties.recommendationImpact), description=tostring(properties.label), resourceId=tostring(properties.resourceMetadata.resourceId), annualSavings=toreal(properties.extendedProperties.annualSavingsAmount), savingsCurrency=tostring(properties.extendedProperties.savingsCurrency), lastUpdated=todatetime(properties.lastUpdated), recommendationTypeId=tostring(properties.recommendationTypeId)
| where recommendationStatus in~ ('New', 'InProgress') or isempty(recommendationStatus)
| project id, name, subscriptionId, resourceGroup, category, impact, description, resourceId, annualSavings, savingsCurrency, lastUpdated, recommendationTypeId, recommendationStatus
| order by impact asc, category asc
""".strip()

CONTAINERS_QUERY = """
ResourceContainers
| where type in~ ('microsoft.resources/subscriptions', 'microsoft.resources/resourcegroups', 'microsoft.management/managementgroups')
| project id, name, type, subscriptionId, tenantId, properties
| order by type asc, name asc
""".strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Coleta Azure Resource Graph read-only")
    parser.add_argument(
        "--subscriptions",
        default=os.getenv("AZURE_SUBSCRIPTION_IDS", ""),
        help="IDs separados por vírgula; também aceita AZURE_SUBSCRIPTION_IDS",
    )
    parser.add_argument(
        "--output",
        default="runtime/assessment-arg.json",
        help="Arquivo JSON de saída",
    )
    return parser.parse_args()


def resource_row(item: dict) -> dict:
    resource_id = item.get("id", "")
    resource_type = str(item.get("type", "")).lower()
    properties = item.get("properties") or {}
    created_at = properties.get("createdTime") or properties.get("createdDateTime") or item.get("createdTime") or "—"
    age_days = "—"
    if created_at and created_at != "—":
        try:
            created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - created).days)
        except ValueError:
            pass
    exposure = "Private"
    if "publicipaddresses" in resource_type:
        exposure = "Public"
    elif "microsoft.web/sites" in resource_type:
        exposure = "Public" if str(properties.get("publicNetworkAccess", "Enabled")).lower() != "disabled" else "Private"
    elif "microsoft.sql/servers" in resource_type:
        exposure = "Public network / Review"
    posture = []
    if exposure.lower().startswith("public") or "review" in exposure.lower():
        posture.append("Exposição de rede")
    if not (item.get("tags") or {}).get("owner"):
        posture.append("Sem owner")
    if not (item.get("tags") or {}).get("env"):
        posture.append("Sem env")
    security_signal = "Atenção" if any(signal == "Exposição de rede" for signal in posture) else "Sem sinal público detectado"
    governance_signal = "Atenção" if len(posture) > 0 else "Sem sinal básico"
    return {
        "name": item.get("name", "—"),
        "type": item.get("type", "—"),
        "subscription": item.get("subscriptionId", "—"),
        "resource_group": item.get("resourceGroup", "—"),
        "region": item.get("location", "—"),
        "exposure": exposure,
        "owner": (item.get("tags") or {}).get("owner", "A definir"),
        "tags": ", ".join(sorted((item.get("tags") or {}).keys())) or "Nenhuma",
        "resource_id": resource_id,
        "kind": item.get("kind") or "—",
        "sku": item.get("sku") or "—",
        "created_at": created_at,
        "age_days": age_days,
        "security_signal": security_signal,
        "governance_signal": governance_signal,
        "posture_signals": "; ".join(posture) or "Nenhum sinal básico",
    }


def policy_row(item: dict) -> dict:
    return {
        "policy": item.get("policyDefinitionName") or "—",
        "assignment": item.get("policyAssignmentName") or item.get("policyAssignmentId") or "—",
        "compliance_state": item.get("complianceState") or "Unknown",
        "non_compliant": 1 if str(item.get("complianceState", "")).lower() != "compliant" else 0,
        "exemptions": 0,
        "last_evaluated": item.get("timestamp") or "—",
        "resource_id": item.get("resourceId") or "—",
        "subscription": item.get("subscriptionId") or "—",
    }


def orphan_row(item: dict) -> dict:
    return {
        "name": item.get("name") or "—",
        "type": item.get("type") or "—",
        "subscription": item.get("subscriptionId") or "—",
        "resource_group": item.get("resourceGroup") or "—",
        "reason": item.get("reason") or "—",
        "monthly_cost": "Não calculado",
        "last_activity": "Não disponível",
        "owner": "A definir",
        "recommended_action": "Validar dependência, owner e custo antes de qualquer ação",
        "resource_id": item.get("resourceId") or "—",
    }


def advisor_row(item: dict) -> dict:
    """Normaliza recomendação do Advisor sem coletar dados de configuração."""
    return {
        "category": item.get("category") or "—",
        "impact": item.get("impact") or "—",
        "description": item.get("description") or "Recomendação Azure Advisor",
        "subscription": item.get("subscriptionId") or "—",
        "resource_group": item.get("resourceGroup") or "—",
        "resource_id": item.get("resourceId") or "—",
        "annual_savings": item.get("annualSavings") if item.get("annualSavings") is not None else "Não quantificado",
        "currency": item.get("savingsCurrency") or "—",
        "last_updated": item.get("lastUpdated") or "—",
        "status": item.get("recommendationStatus") or "New",
        "recommendation_type": item.get("recommendationTypeId") or "—",
    }


def collect(subscription_ids: list[str]) -> dict:
    # Imports tardios permitem que a execução registre dependências ausentes
    # no JSON de erro, em vez de abortar antes do mecanismo fail gracefully.
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions

    started = utc_now()
    if not subscription_ids:
        raise ValueError("Informe --subscriptions ou AZURE_SUBSCRIPTION_IDS")

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    client = ResourceGraphClient(credential)
    rows: list[dict] = []
    policy_rows: list[dict] = []
    orphan_rows: list[dict] = []
    retirement_rows: list[dict] = []
    advisor_rows: list[dict] = []
    container_rows: list[dict] = []
    skip_token: str | None = None

    while True:
        options = QueryRequestOptions(
            result_format="objectArray",
            top=5000,
            skip_token=skip_token,
        )
        request = QueryRequest(
            subscriptions=subscription_ids,
            query=QUERY,
            options=options,
        )
        response = client.resources(request)
        rows.extend(resource_row(item) for item in (response.data or []))
        skip_token = getattr(response, "skip_token", None)
        if not skip_token:
            break

    age_counts = [
        ("0–90 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and item["age_days"] <= 90)),
        ("91–365 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and 90 < item["age_days"] <= 365)),
        (">365 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and item["age_days"] > 365)),
        ("Data desconhecida", sum(1 for item in rows if not isinstance(item.get("age_days"), int))),
    ]
    age_rows = [{"age_band": band, "resources": count, "percentage": f"{(count / len(rows) * 100):.1f}%" if rows else "0%"} for band, count in age_counts]

    try:
        container_response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=CONTAINERS_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        container_rows = [{
            "name": item.get("name", "—"),
            "type": item.get("type", "—"),
            "subscription": item.get("subscriptionId", "—"),
            "tenant": item.get("tenantId", "—"),
        } for item in (container_response.data or [])]
        hierarchy_status = "success"
        hierarchy_note = "Subscriptions, resource groups e management groups via ResourceContainers"
    except Exception as exc:
        hierarchy_status = "not_available"
        hierarchy_note = f"Hierarquia indisponível: {type(exc).__name__}: {exc}"

    try:
        policy_response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=POLICY_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        policy_rows = [policy_row(item) for item in (policy_response.data or [])]
        policy_status = "success"
        policy_note = "Azure Policy states via Azure Resource Graph"
    except Exception as exc:
        policy_status = "not_available"
        policy_note = f"Policy Insights indisponível: {type(exc).__name__}: {exc}"

    try:
        orphan_response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=ORPHAN_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        orphan_rows = [orphan_row(item) for item in (orphan_response.data or [])]
        orphan_status = "success"
        orphan_note = "Heurísticas de associação via Azure Resource Graph; custo requer Cost Management"
    except Exception as exc:
        orphan_status = "not_available"
        orphan_note = f"Detecção de órfãos indisponível: {type(exc).__name__}: {exc}"

    try:
        advisor_response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=ADVISOR_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        advisor_rows = [advisor_row(item) for item in (advisor_response.data or [])]
        advisor_status = "success"
        advisor_note = "Recomendações ativas do Azure Advisor via Azure Resource Graph"
    except Exception as exc:
        advisor_status = "not_available"
        advisor_note = f"Azure Advisor indisponível: {type(exc).__name__}: {exc}"

    try:
        retirement_response = client.resources(QueryRequest(
            subscriptions=subscription_ids,
            query=RETIREMENT_QUERY,
            options=QueryRequestOptions(result_format="objectArray", top=5000),
        ))
        retirement_rows = [{
            "service": item.get("title") or "Health advisory",
            "feature": "Service Health advisory",
            "retirement_date": item.get("impactStartTime") or "Not published",
            "days_remaining": "Unknown",
            "impacted_resources": "Unknown",
            "action": "Review advisory and affected resources",
            "owner": "A definir",
            "status": item.get("status") or "Open",
            "tracking_id": item.get("trackingId") or "—",
        } for item in (retirement_response.data or [])]
        retirement_status = "success"
        retirement_note = "Service Health advisories via Azure Resource Graph"
    except Exception as exc:
        retirement_status = "not_available"
        retirement_note = f"Service Health indisponível: {type(exc).__name__}: {exc}"

    return {
        "metadata": {
            "engine_version": "0.1.8",
            "run_id": f"arg-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "collected_at": started,
            "scope": {"subscriptions": len(subscription_ids), "resources_assessed": len(rows)},
            "modules": {"governance": "success", "compliance": policy_status},
        },
        "controls": [],
        "findings": [],
        "discovery": {
            "resources": rows,
            "containers": container_rows,
            "policy_compliance": policy_rows,
            "lifecycle": {
                "summary": {"Recursos órfãos": len(orphan_rows), "Recomendações Advisor": len(advisor_rows)},
                "orphan_resources": orphan_rows,
                "advisor_recommendations": advisor_rows,
                "service_retirements": retirement_rows,
                "resource_age": age_rows,
            },
            "collection_log": [{
                "module": "Azure inventory",
                "source": "Azure Resource Graph",
                "status": "success",
                "records": len(rows),
                "note": "Consulta read-only; exposição e dependências exigem enriquecimento por módulo.",
            }, {
                "module": "Azure Policy",
                "source": "PolicyResources / Azure Resource Graph",
                "status": policy_status,
                "records": len(policy_rows),
                "note": policy_note,
            }, {
                "module": "Azure hierarchy",
                "source": "ResourceContainers / Azure Resource Graph",
                "status": hierarchy_status,
                "records": len(container_rows),
                "note": hierarchy_note,
            }, {
                "module": "Orphan resources",
                "source": "Azure Resource Graph",
                "status": orphan_status,
                "records": len(orphan_rows),
                "note": orphan_note,
            }, {
                "module": "Azure Advisor",
                "source": "AdvisorResources / Azure Resource Graph",
                "status": advisor_status,
                "records": len(advisor_rows),
                "note": advisor_note,
            }, {
                "module": "Service retirement",
                "source": "ServiceHealthResources / Azure Resource Graph",
                "status": retirement_status,
                "records": len(retirement_rows),
                "note": retirement_note,
            }],
        },
    }


def main() -> None:
    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        subscription_ids = [item.strip() for item in args.subscriptions.split(",") if item.strip()]
        payload = collect(subscription_ids)
    except Exception as exc:  # falha controlada para o runner registrar o motivo
        payload = {
            "metadata": {"engine_version": "0.1.8", "collected_at": utc_now(), "modules": {"governance": "error"}},
            "controls": [],
            "findings": [],
            "discovery": {"resources": [], "collection_log": [{
                "module": "Azure inventory", "source": "Azure Resource Graph", "status": "error", "records": 0,
                "note": f"Coleta não executada: {type(exc).__name__}: {exc}",
            }]},
        }
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        raise SystemExit(f"Falha controlada; saída gravada em {output}: {exc}") from exc
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Inventário ARG gravado: {output} ({len(payload['discovery']['resources'])} recursos)")


if __name__ == "__main__":
    main()
