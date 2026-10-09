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
import time
from datetime import datetime, timezone
from pathlib import Path
from version import engine_version


def retryable_arg_error(error: Exception) -> bool:
    """Reconhece throttling e falhas transitórias do SDK Resource Graph."""
    code = getattr(error, "status_code", None) or getattr(error, "status", None)
    return code in {429, 500, 502, 503, 504}


def query_arg_with_retry(client: object, request: object, attempts: int | None = None) -> object:
    """Repete apenas consultas ARG idempotentes; nunca repete operação de escrita."""
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
    raise RuntimeError("Azure Resource Graph não retornou resposta")

class ArgQueryResult(list):
    """Rows returned by ARG, retaining the completeness state of pagination."""

    def __init__(self):
        super().__init__()
        self.complete = True
        self.error: str | None = None


def arg_result_status(result: ArgQueryResult) -> str:
    if result.complete:
        return "success"
    return "partial" if result else "not_available"


def arg_result_note(label: str, result: ArgQueryResult, success_note: str) -> str:
    if result.complete:
        return success_note
    return f"{label} parcial ({len(result)} registros preservados): {result.error}"


def query_arg_all_pages(
    client: object,
    subscriptions: list[str],
    query: str,
    QueryRequest: object,
    QueryRequestOptions: object,
) -> ArgQueryResult:
    """Fetch every ARG page and preserve first pages if a later page fails."""
    rows = ArgQueryResult()
    skip_token: str | None = None
    seen_tokens: set[str] = set()
    while True:
        options = QueryRequestOptions(
            result_format="objectArray",
            top=5000,
            skip_token=skip_token,
        )
        request = QueryRequest(subscriptions=subscriptions, query=query, options=options)
        try:
            response = query_arg_with_retry(client, request)
        except Exception as exc:
            rows.complete = False
            rows.error = f"{type(exc).__name__}: {exc}"
            return rows
        rows.extend(response.data or [])
        next_token = getattr(response, "skip_token", None)
        if not next_token:
            return rows
        next_token = str(next_token)
        if next_token in seen_tokens:
            rows.complete = False
            rows.error = "Azure Resource Graph repetiu o skip_token; consulta interrompida para evitar loop."
            return rows
        seen_tokens.add(next_token)
        skip_token = next_token


QUERY = """
Resources
| project id, name, type, subscriptionId, resourceGroup, location, kind, sku, tags, properties
| order by type asc, name asc
""".strip()

POLICY_QUERY = """
PolicyResources
| where type =~ 'Microsoft.PolicyInsights/PolicyStates'
| extend complianceState=tostring(properties.complianceState), resourceId=tostring(properties.resourceId), policyAssignmentId=tostring(properties.policyAssignmentId), policyAssignmentName=tostring(properties.policyAssignmentName), policyDefinitionName=tostring(properties.policyDefinitionName), policyDefinitionId=tostring(properties.policyDefinitionId), policySetDefinitionId=tostring(properties.policySetDefinitionId), policyDefinitionAction=tostring(properties.policyDefinitionAction), resourceType=tostring(properties.resourceType), resourceLocation=tostring(properties.resourceLocation), timestamp=todatetime(properties.timestamp)
| project subscriptionId, resourceId, resourceType, resourceLocation, policyAssignmentId, policyAssignmentName, policyDefinitionId, policyDefinitionName, policySetDefinitionId, policyDefinitionAction, complianceState, timestamp
""".strip()

POLICY_ASSIGNMENTS_QUERY = """
PolicyResources
| where type =~ 'Microsoft.Authorization/PolicyAssignments'
| extend displayName=tostring(properties.displayName), enforcementMode=tostring(properties.enforcementMode), definitionId=tostring(properties.policyDefinitionId), scope=tostring(properties.scope), notScopes=properties.notScopes, parameters=properties.parameters
| project id, name, subscriptionId, resourceGroup, displayName, enforcementMode, definitionId, scope, notScopes, parameters
""".strip()

POLICY_DEFINITIONS_QUERY = """
PolicyResources
| where type in~ ('Microsoft.Authorization/PolicyDefinitions','Microsoft.Authorization/PolicySetDefinitions')
| extend displayName=tostring(properties.displayName), parameters=properties.parameters
| project id, name, type, displayName, parameters
""".strip()

ORPHAN_QUERY = """
Resources
| where type =~ 'Microsoft.Compute/disks'
| where tostring(properties.diskState) =~ 'Unattached'
| project name, type, subscriptionId, resourceGroup, location, reason='Unattached disk', resourceId=id
| union (Resources | where type =~ 'Microsoft.Network/publicIPAddresses' | where isempty(properties.ipConfiguration) | project name, type, subscriptionId, resourceGroup, location, reason='Unused public IP', resourceId=id)
| union (Resources | where type =~ 'Microsoft.Network/networkInterfaces' | where isempty(properties.virtualMachine.id) and isempty(properties.privateEndpoint.id) | project name, type, subscriptionId, resourceGroup, location, reason='Unused NIC', resourceId=id)
""".strip()

RESOURCE_GROUP_QUERY = """
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id, name, subscriptionId, location, tags
""".strip()

NETWORK_HEALTH_QUERY = """
Resources
| where type in~ ('microsoft.network/virtualnetworks','microsoft.network/connections','microsoft.network/virtualnetworkgateways','microsoft.network/expressroutecircuits')
| project id, name, type, subscriptionId, resourceGroup, location, properties
""".strip()

DEFENDER_SCORE_QUERY = """
SecurityResources
| where type =~ 'microsoft.security/securescores'
| extend current=todouble(properties.score.current), max=todouble(properties.score.max), percentage=todouble(properties.score.percentage)
| project subscriptionId, name, current, max, percentage
""".strip()

DEFENDER_CONTROLS_QUERY = """
SecurityResources
| where type =~ 'microsoft.security/securescores/securescorecontrols'
| extend displayName=tostring(properties.displayName), current=todouble(properties.score.current), max=todouble(properties.score.max), percentage=todouble(properties.score.percentage), unhealthy=tostring(properties.unhealthyResourceCount), healthy=tostring(properties.healthyResourceCount)
| project subscriptionId, name, displayName, current, max, percentage, unhealthy, healthy
""".strip()

RETIREMENT_QUERY = """
ServiceHealthResources
| where type =~ 'microsoft.resourcehealth/events'
| project name, subscriptionId, properties
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

# A tabela é populada pelo inventário do Azure Resource Graph quando o
# inventário do Power Platform está habilitado no tenant. A consulta só lê
# metadados; não acessa conteúdo de aplicativos, fórmulas, mensagens ou dados
# dos usuários.
POWER_PLATFORM_QUERY = """
PowerPlatformResources
| project id, name, type, subscriptionId, resourceGroup, location, properties
| order by type asc, name asc
""".strip()

BENEFITS_QUERY = """
Resources
| where type has_any ('microsoft.capacity/reservation', 'microsoft.billingbenefits/reservation', 'microsoft.billingbenefits/savingsplan', 'microsoft.costmanagement/exports')
| project id, name, type, subscriptionId, resourceGroup, location, properties, sku
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


def exposure_details(resource_type: str, properties: dict) -> tuple[str, str]:
    """Classifica exposição por sinais conhecidos; desconhecido permanece revisão."""
    resource_type = str(resource_type).lower()
    network = str(properties.get("publicNetworkAccess", "")).lower()
    if "publicipaddresses" in resource_type:
        return "Public", "Azure Public IP"
    if network == "disabled":
        return "Private", "publicNetworkAccess=Disabled"
    if network == "enabled":
        return "Public network / Review", "publicNetworkAccess=Enabled"
    if "microsoft.web/sites" in resource_type:
        return "Public network / Review", "App Service sem publicNetworkAccess=Disabled demonstrado"
    if "microsoft.storage/storageaccounts" in resource_type and properties.get("allowBlobPublicAccess") is True:
        return "Public access / Review", "allowBlobPublicAccess=True"
    if any(kind in resource_type for kind in ("microsoft.sql/servers", "microsoft.cache/redis", "microsoft.documentdb/databaseaccounts", "microsoft.keyvault/vaults")):
        return "Review", "Propriedade de rede não retornada pelo inventário"
    return "Private", "Nenhum sinal público conhecido"


def resource_security_posture(resource_type: str, properties: dict) -> list[str]:
    """Extrai sinais explícitos de segurança; ausência de propriedade não vira conformidade."""
    resource_type = str(resource_type).lower()
    properties = properties if isinstance(properties, dict) else {}
    signals: list[str] = []
    if "microsoft.storage/storageaccounts" in resource_type:
        if properties.get("allowBlobPublicAccess") is True:
            signals.append("Storage: blob público habilitado")
        if properties.get("supportsHttpsTrafficOnly") is False:
            signals.append("Storage: HTTPS-only desabilitado")
        if str(properties.get("minimumTlsVersion", "")).upper() in {"TLS1_0", "TLS1_1", "TLS 1.0", "TLS 1.1"}:
            signals.append("Storage: TLS mínimo legado")
    if "microsoft.keyvault/vaults" in resource_type:
        if properties.get("enableSoftDelete") is False or properties.get("softDeleteEnabled") is False:
            signals.append("Key Vault: soft delete desabilitado")
        if properties.get("enablePurgeProtection") is False or properties.get("purgeProtectionEnabled") is False:
            signals.append("Key Vault: purge protection desabilitado")
        if str((properties.get("networkAcls") or {}).get("defaultAction", "")).lower() == "allow":
            signals.append("Key Vault: ACL de rede permite acesso por padrão")
    if "microsoft.network/networksecuritygroups" in resource_type:
        rules = properties.get("securityRules") or properties.get("rules") or []
        if isinstance(rules, dict):
            rules = list(rules.values())
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict):
                continue
            source = str(rule.get("sourceAddressPrefix") or rule.get("sourceAddressPrefixes") or "").lower()
            destination = str(rule.get("destinationPortRange") or rule.get("destinationPortRanges") or "").lower()
            if str(rule.get("access", "")).lower() == "allow" and str(rule.get("direction", "")).lower() == "inbound" and (source in {"*", "0.0.0.0/0", "internet"} or "0.0.0.0/0" in source) and any(port in destination for port in ("22", "3389")):
                signals.append(f"NSG: entrada pública permitida na porta {('22/3389' if '22' in destination and '3389' in destination else '22' if '22' in destination else '3389')}")
    if "microsoft.web/sites" in resource_type:
        if properties.get("httpsOnly") is False:
            signals.append("App Service: HTTPS-only desabilitado")
        site_config = properties.get("siteConfig") or {}
        minimum_tls = properties.get("minTlsVersion") or site_config.get("minTlsVersion")
        if str(minimum_tls).upper() in {"1.0", "1.1", "TLS1_0", "TLS1_1", "TLS 1.0", "TLS 1.1"}:
            signals.append("App Service: TLS mínimo legado")
    if "microsoft.sql/servers/firewallrules" in resource_type:
        start_ip = str(properties.get("startIpAddress", "")).strip()
        end_ip = str(properties.get("endIpAddress", "")).strip()
        if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
            signals.append("SQL Firewall: acesso público de qualquer origem")
        elif start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
            signals.append("SQL Firewall: regra especial permite serviços Azure")
    if "microsoft.sql/servers" in resource_type and properties.get("publicNetworkAccess") is True:
        signals.append("Azure SQL: acesso público habilitado")
    if any(service in resource_type for service in ("microsoft.documentdb/databaseaccounts", "microsoft.cache/redis", "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers")):
        if str(properties.get("publicNetworkAccess", "")).lower() in {"true", "enabled"} or properties.get("publicNetworkAccess") is True:
            signals.append("Serviço de dados: acesso público habilitado")
    if "microsoft.documentdb/databaseaccounts" in resource_type and properties.get("isVirtualNetworkFilterEnabled") is False:
        signals.append("Cosmos DB: filtro de rede virtual desabilitado")
    if "microsoft.containerregistry/registries" in resource_type and properties.get("adminUserEnabled") is True:
        signals.append("Container Registry: usuário administrador habilitado")
    if "microsoft.network/applicationgateways" in resource_type:
        waf = properties.get("webApplicationFirewallConfiguration") or {}
        if isinstance(waf, dict) and waf.get("enabled") is False:
            signals.append("Application Gateway: WAF desabilitado")
    return sorted(set(signals))


def extract_resource_ids(value: object) -> list[str]:
    """Extrai referências Azure Resource Manager explícitas de estruturas retornadas pelo ARG."""
    found: set[str] = set()
    def walk(current: object) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if str(key).lower() in {"id", "resourceid", "scope"} and isinstance(child, str) and child.lower().startswith("/subscriptions/"):
                    found.add(child)
                walk(child)
        elif isinstance(current, list):
            for child in current:
                walk(child)
        elif isinstance(current, str) and current.lower().startswith("/subscriptions/"):
            found.add(current)
    walk(value)
    return sorted(found)


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
    exposure, exposure_reason = exposure_details(resource_type, properties)
    security_posture = resource_security_posture(resource_type, properties)
    posture = []
    if exposure.lower().startswith("public") or "review" in exposure.lower():
        posture.append("Exposição de rede")
    if not (item.get("tags") or {}).get("owner"):
        posture.append("Sem owner")
    if not (item.get("tags") or {}).get("env"):
        posture.append("Sem env")
    security_signal = "Atenção" if any(signal == "Exposição de rede" for signal in posture) or security_posture else "Sem sinal público detectado"
    governance_signal = "Atenção" if len(posture) > 0 else "Sem sinal básico"
    return {
        "name": item.get("name", "—"),
        "type": item.get("type", "—"),
        "subscription": item.get("subscriptionId", "—"),
        "resource_group": item.get("resourceGroup", "—"),
        "region": item.get("location", "—"),
        "exposure": exposure,
        "exposure_reason": exposure_reason,
        "owner": (item.get("tags") or {}).get("owner", "A definir"),
        "tags": ", ".join(sorted((item.get("tags") or {}).keys())) or "Nenhuma",
        "resource_id": resource_id,
        "kind": item.get("kind") or "—",
        "sku": item.get("sku") or "—",
        "created_at": created_at,
        "age_days": age_days,
        "security_signal": security_signal,
        "security_posture": "; ".join(security_posture) or "Nenhum sinal explícito retornado",
        "governance_signal": governance_signal,
        "posture_signals": "; ".join(posture) or "Nenhum sinal básico",
        "dependency_ids": [rid for rid in extract_resource_ids(properties) if rid.lower() != str(resource_id).lower()],
    }


def policy_row(item: dict) -> dict:
    raw_state = str(item.get("complianceState") or "Unknown").strip()
    normalized_state = raw_state.lower().replace("-", "_").replace(" ", "_")
    if normalized_state in {"compliant", "compliance"}:
        classification = "compliant"
        evidence_state = "CONFORMANT"
    elif normalized_state in {"noncompliant", "non_compliant", "noncompliance", "non_compliance", "conflict", "partial"}:
        classification = "non_compliant"
        evidence_state = "NON_CONFORMANT"
    elif normalized_state in {"exempt", "excluded"}:
        classification = "exempt"
        evidence_state = "INSUFFICIENT_EVIDENCE"
    else:
        classification = "unknown"
        evidence_state = "INSUFFICIENT_EVIDENCE"
    assignment_id = item.get("policyAssignmentId") or "—"
    assignment_scope = assignment_id.rsplit("/providers/Microsoft.Authorization/policyAssignments/", 1)[0] if "/providers/Microsoft.Authorization/policyAssignments/" in str(assignment_id) else "—"
    return {
        "policy": item.get("policyDefinitionName") or "—",
        "policy_definition_id": item.get("policyDefinitionId") or "—",
        "initiative_id": item.get("policySetDefinitionId") or "—",
        "assignment": item.get("policyAssignmentName") or assignment_id,
        "assignment_id": assignment_id,
        "assignment_scope": assignment_scope,
        "effect": item.get("policyDefinitionAction") or "—",
        "compliance_state": raw_state,
        "classification": classification,
        "evidence_state": evidence_state,
        "non_compliant": 1 if classification == "non_compliant" else 0,
        "exemptions": 1 if classification == "exempt" else 0,
        "last_evaluated": item.get("timestamp") or "—",
        "resource_id": item.get("resourceId") or "—",
        "resource_type": item.get("resourceType") or "—",
        "resource_location": item.get("resourceLocation") or "—",
        "subscription": item.get("subscriptionId") or "—",
    }


def summarize_policy_compliance(rows: list[dict]) -> list[dict]:
    """Agrupa compliance por policy, assignment e subscription para gestão."""
    grouped: dict[tuple[str, str, str], dict] = {}
    for row in rows:
        key = (str(row.get("policy", "—")), str(row.get("assignment", "—")), str(row.get("subscription", "—")))
        item = grouped.setdefault(key, {"policy": key[0], "assignment": key[1], "subscription": key[2], "evaluated": 0, "observations": 0, "non_compliant": 0, "exemptions": 0, "insufficient_evidence": 0})
        classification = str(row.get("classification", "")).lower()
        if not classification:
            state = str(row.get("compliance_state", "")).lower().replace("-", "_").replace(" ", "_")
            if state in {"compliant", "compliance"}:
                classification = "compliant"
            elif state in {"noncompliant", "non_compliant", "noncompliance", "non_compliance", "conflict", "partial"} or int(row.get("non_compliant", 0) or 0) > 0:
                classification = "non_compliant"
            elif state in {"exempt", "excluded"}:
                classification = "exempt"
            elif "non_compliant" in row:
                # Backward-compatible normalized rows may only carry the
                # legacy counter; zero means an explicit compliant sample.
                classification = "compliant"
        # Only explicit compliant/non-compliant observations belong in the
        # compliance denominator. Unknown states are evidence gaps, not fails.
        if classification in {"compliant", "non_compliant"}:
            item["evaluated"] += 1
        elif classification in {"exempt", "unknown", ""}:
            item["insufficient_evidence"] += 1
        item["observations"] += 1
        item["non_compliant"] += int(row.get("non_compliant", 0) or 0)
        item["exemptions"] += int(row.get("exemptions", 0) or 0)
    for item in grouped.values():
        item["compliant"] = item["evaluated"] - item["non_compliant"]
        item["compliance_rate"] = round(item["compliant"] / item["evaluated"] * 100, 1) if item["evaluated"] else 0
        item["evidence_coverage"] = round(item["evaluated"] / item["observations"] * 100, 1) if item["observations"] else 0
        if not item["evaluated"]:
            item["risk_signal"] = "Evidência insuficiente"
        elif item["compliance_rate"] < 50:
            item["risk_signal"] = "Crítico"
        else:
            item["risk_signal"] = "Atenção" if item["non_compliant"] else "Controlado"
    return sorted(grouped.values(), key=lambda item: (item["risk_signal"] != "Crítico", item["compliance_rate"]))


def summarize_security_posture(rows: list[dict]) -> dict:
    """Agrega sinais explícitos sem converter ausência em conformidade."""
    signal_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    resources_with_signals = 0
    for row in rows:
        signals = [item.strip() for item in str(row.get("security_posture", "")).split(";") if item.strip() and item.strip() != "Nenhum sinal explícito retornado"]
        if signals:
            resources_with_signals += 1
        resource_type = str(row.get("type", "—"))
        type_counts[resource_type] = type_counts.get(resource_type, 0) + len(signals)
        for signal in signals:
            signal_counts[signal] = signal_counts.get(signal, 0) + 1
    return {
        "resources": len(rows),
        "resources_with_explicit_signals": resources_with_signals,
        "signals_total": sum(signal_counts.values()),
        "coverage_note": "Somente propriedades de segurança explicitamente retornadas pelo Azure Resource Graph; ausência não é conformidade.",
        "by_signal": [{"signal": key, "resources": value} for key, value in sorted(signal_counts.items(), key=lambda item: (-item[1], item[0]))],
        "by_resource_type": [{"resource_type": key, "signals": value} for key, value in sorted(type_counts.items(), key=lambda item: (-item[1], item[0])) if value],
    }


def summarize_governance_posture(resources: list[dict], policy_rows: list[dict]) -> dict:
    """Resume ownership, tags e Policy sem afirmar governança completa."""
    without_owner = sum(1 for row in resources if row.get("owner") in {None, "", "A definir"})
    without_env = sum(1 for row in resources if "env" not in str(row.get("tags", "")).lower())
    without_tags = sum(1 for row in resources if str(row.get("tags", "")).lower() in {"", "nenhuma", "none"})
    evaluated = len(policy_rows)
    non_compliant = sum(int(row.get("non_compliant", 0) or 0) for row in policy_rows)
    return {
        "resources_assessed": len(resources),
        "without_owner": without_owner,
        "without_environment_tag": without_env,
        "without_tags": without_tags,
        "policy_evaluated": evaluated,
        "policy_non_compliant": non_compliant,
        "policy_compliance_rate": round((evaluated - non_compliant) / evaluated * 100, 1) if evaluated else "Não calculada",
        "interpretation": "Indicadores de governança observados; ausência de tag ou estado de Policy não prova risco nem conformidade isoladamente.",
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
def policy_definition_defaults(item: dict) -> dict:
    parameters = item.get("parameters") or {}
    if not isinstance(parameters, dict):
        return {}
    defaults = {}
    for name, definition in parameters.items():
        if isinstance(definition, dict) and "defaultValue" in definition:
            defaults[str(name)] = definition.get("defaultValue")
    return defaults


def enrich_policy_assignments(assignments: list[dict], definitions: list[dict]) -> list[dict]:
    """Resolve Default/Assigned/Effective sem inventar default ausente."""
    by_id = {str(item.get("id", "")).lower(): item for item in definitions if item.get("id")}
    result = []
    for assignment in assignments:
        definition = by_id.get(str(assignment.get("definition_id", "")).lower(), {})
        defaults = policy_definition_defaults(definition)
        assigned_by_name = {str(item.get("name")): item.get("assigned_value") for item in assignment.get("parameters", [])}
        names = sorted(set(defaults) | set(assigned_by_name))
        resolved = []
        for name in names:
            assigned_present = name in assigned_by_name
            default_present = name in defaults
            assigned = assigned_by_name.get(name)
            default = defaults.get(name)
            resolved.append({
                "name": name,
                "default_value": default if default_present else "Not set",
                "assigned_value": assigned if assigned_present else "Not set",
                "effective_value": assigned if assigned_present else (default if default_present else "Not set"),
                "value_source": "Assigned" if assigned_present else ("Default" if default_present else "Not set"),
            })
        enriched = dict(assignment)
        enriched["definition_display_name"] = definition.get("displayName") or definition.get("name") or "—"

        definition_type = str(definition.get("type", "")).lower()
        if definition_type.endswith("policysetdefinitions"):
            enriched["definition_type"] = "PolicySet"
        elif definition_type.endswith("policydefinitions"):
            enriched["definition_type"] = "Policy"
        else:
            enriched["definition_type"] = "Unresolved"

        enriched["definition_resolved"] = bool(definition)
        enriched["parameters"] = resolved
        enriched["parameter_count"] = len(resolved)
        result.append(enriched)
    return result


def policy_assignment_row(item: dict) -> dict:
    """Normaliza assignment e parâmetros sem confundir ausência com default efetivo."""
    parameters = item.get("parameters") or {}
    if not isinstance(parameters, dict):
        parameters = {}
    normalized = []
    for name, value in sorted(parameters.items()):
        raw = value.get("value") if isinstance(value, dict) else value
        normalized.append({"name": name, "assigned_value": raw, "value_source": "Assigned"})
    scope = item.get("scope") or "—"
    return {
        "assignment": item.get("displayName") or item.get("name") or "—",
        "assignment_name": item.get("name") or "—",
        "assignment_id": item.get("id") or "—",
        "definition_id": item.get("definitionId") or "—",
        "scope": scope,
        "scope_type": "ManagementGroup" if "/managementGroups/" in str(scope) else "ResourceGroup" if "/resourceGroups/" in str(scope) else "Subscription" if "/subscriptions/" in str(scope) else "Unknown",
        "enforcement_mode": item.get("enforcementMode") or "Default",
        "not_scopes": item.get("notScopes") or [],
        "parameters": normalized,
        "parameter_count": len(normalized),
        "subscription": item.get("subscriptionId") or "—",
    }


def hygiene_summary(resources: list[dict], orphans: list[dict], resource_groups: list[dict], network_rows: list[dict]) -> dict:
    """Resume higiene operacional com regras determinísticas e conservadoras."""
    empty_resource_groups = []
    counts: dict[tuple[str, str], int] = {}
    for resource in resources:
        subscription = str(
            resource.get("subscription")
            or resource.get("subscriptionId")
            or ""
        ).strip().lower()
        resource_group = str(
            resource.get("resource_group")
            or resource.get("resourceGroup")
            or ""
        ).strip().lower()
        key = (subscription, resource_group)
        counts[key] = counts.get(key, 0) + 1

    for group in resource_groups:
        subscription = str(
            group.get("subscriptionId")
            or group.get("subscription")
            or ""
        ).strip().lower()
        resource_group = str(
            group.get("name")
            or group.get("resourceGroup")
            or ""
        ).strip().lower()
        key = (subscription, resource_group)
        if counts.get(key, 0) == 0:
            empty_resource_groups.append({"name": group.get("name", "—"), "subscription": group.get("subscriptionId", "—"), "location": group.get("location", "—"), "severity": "Low", "finding": "Empty resource group"})
    unused = {}
    for row in orphans:
        reason = str(row.get("reason", "Other"))
        unused[reason] = unused.get(reason, 0) + 1
    network_attention = []
    for row in network_rows:
        props = row.get("properties") or {}
        resource_type = str(row.get("type", "")).lower()
        if "connections" in resource_type and str(props.get("connectionStatus", "")).lower() not in {"", "connected"}:
            network_attention.append({"name": row.get("name", "—"), "type": row.get("type", "—"), "state": props.get("connectionStatus", "Unknown"), "resource_group": row.get("resourceGroup", "—")})
        if "expressroutecircuits" in resource_type and str(props.get("serviceProviderProperties", {}).get("provisioningState", props.get("circuitProvisioningState", ""))).lower() in {"failed", "disabled", "notprovisioned"}:
            network_attention.append({"name": row.get("name", "—"), "type": row.get("type", "—"), "state": props.get("circuitProvisioningState", "Unknown"), "resource_group": row.get("resourceGroup", "—")})
    return {
        "empty_resource_groups": empty_resource_groups,
        "empty_resource_group_count": len(empty_resource_groups),
        "orphan_count": len(orphans),
        "unused_by_reason": dict(sorted(unused.items())),
        "network_attention": network_attention,
        "network_attention_count": len(network_attention),
        "interpretation": "Sinais de higiene para revisão; nenhuma exclusão ou alteração é executada pelo assessment.",
    }


def resource_map(resources: list[dict]) -> dict:
    """Cria grafo navegável de recursos e dependências usando IDs explícitos retornados pelo ARG."""
    nodes = []
    edge_keys: set[tuple[str, str]] = set()
    edges = []
    known = {str(row.get("resource_id", "")).lower(): row for row in resources if row.get("resource_id")}
    for row in resources:
        rid = str(row.get("resource_id", ""))
        nodes.append({"id": rid, "name": row.get("name", "—"), "type": row.get("type", "—"), "subscription": row.get("subscription", "—"), "resource_group": row.get("resource_group", "—"), "region": row.get("region", "—"), "security_signal": row.get("security_signal", "—"), "governance_signal": row.get("governance_signal", "—")})
        for dependency in row.get("dependency_ids", []) or []:
            target = str(dependency).lower()
            source = rid.lower()
            if target in known and target != source and (source, target) not in edge_keys:
                edge_keys.add((source, target))
                edges.append({"source": rid, "target": known[target].get("resource_id", dependency), "kind": "Resource dependency"})
        # Child resources such as subnets also carry a deterministic parent ARM ID.
        parts = rid.split("/")
        if len(parts) > 10:
            parent = "/".join(parts[:-2]).lower()
            if parent in known and parent != rid.lower() and (rid.lower(), parent) not in edge_keys:
                edge_keys.add((rid.lower(), parent))
                edges.append({"source": rid, "target": known[parent].get("resource_id"), "kind": "Parent/child"})
    return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges), "coverage_note": "Conexões são exibidas apenas quando a relação é demonstrada por IDs ARM retornados pela coleta; ausência de linha não significa ausência de dependência."}


def defender_summary(scores: list[dict], controls: list[dict]) -> dict:
    """Calcula potencial de ganho do Secure Score sem inventar pontos."""
    score_rows = [{"subscription": row.get("subscriptionId", "—"), "current": row.get("current", 0) or 0, "max": row.get("max", 0) or 0, "percentage": row.get("percentage", 0) or 0} for row in scores]
    control_rows = []
    for row in controls:
        maximum = float(row.get("max") or 0)
        current = float(row.get("current") or 0)
        control_rows.append({"subscription": row.get("subscriptionId", "—"), "control": row.get("displayName") or row.get("name") or "—", "score": current, "max_score": maximum, "potential_score_increase": round(max(0.0, maximum - current), 2), "unhealthy_resources": row.get("unhealthy") or "—", "healthy_resources": row.get("healthy") or "—"})
    control_rows.sort(key=lambda x: (-float(x.get("potential_score_increase", 0)), str(x.get("control", ""))))
    return {"scores": score_rows, "controls": control_rows, "top_improvements": control_rows[:10], "interpretation": "Potential score increase uses Defender Secure Score control points returned by Azure; it is prioritization context, not guaranteed risk reduction."}


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
        "monthly_savings": round(float(item.get("annualSavings")) / 12, 2) if item.get("annualSavings") not in {None, ""} else "Não quantificado",
        "currency": item.get("savingsCurrency") or "—",
        "last_updated": item.get("lastUpdated") or "—",
        "status": item.get("recommendationStatus") or "New",
        "recommendation_type": item.get("recommendationTypeId") or "—",
    }


def retirement_row(item: dict) -> dict:
    """Normaliza Service Health a partir do objeto properties sem KQL frágil."""
    properties = item.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    return {
        "service": properties.get("Title") or properties.get("title") or item.get("name") or "Health advisory",
        "feature": properties.get("EventType") or properties.get("eventType") or "Service Health advisory",
        "retirement_date": properties.get("ImpactStartTime") or properties.get("impactStartTime") or "Not published",
        "days_remaining": "Unknown",
        "impacted_resources": "Unknown",
        "action": "Review advisory and affected resources",
        "owner": "A definir",
        "status": properties.get("Status") or properties.get("status") or "Open",
        "tracking_id": properties.get("TrackingId") or properties.get("trackingId") or "—",
    }


def power_platform_row(item: dict) -> dict:
    """Normaliza inventário de Power Platform sem conteúdo funcional ou PII extra."""
    properties = item.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    resource_type = str(item.get("type") or properties.get("resourceType") or "—")
    connectors = properties.get("powerPlatformConnectors") or properties.get("connectors") or []
    if isinstance(connectors, dict):
        connectors = list(connectors.values())
    connector_names = []
    premium = 0
    for connector in connectors if isinstance(connectors, list) else []:
        if isinstance(connector, dict):
            connector_names.append(str(connector.get("id") or connector.get("name") or "—"))
            tier = str(connector.get("tier") or connector.get("connectorTier") or "").lower()
            premium += int("premium" in tier)
        else:
            connector_names.append(str(connector))
    owner = (properties.get("owner") or properties.get("createdBy") or
             properties.get("ownerEmail") or "A definir")
    created = properties.get("createdTime") or properties.get("createdDateTime") or "—"
    modified = properties.get("lastModifiedTime") or properties.get("modifiedTime") or "—"
    state = str(properties.get("state") or properties.get("status") or "Unknown")
    kind = str(properties.get("kind") or resource_type.rsplit("/", 1)[-1] or "—")
    kind_lower = kind.lower()
    type_lower = resource_type.lower()
    product = "Copilot Studio / Agent" if any(token in f"{kind_lower} {type_lower}" for token in ("copilot", "virtualagent", "bot", "agent")) else "Power Automate" if any(token in f"{kind_lower} {type_lower}" for token in ("flow", "powerautomate", "workflow")) else "Power Apps" if any(token in f"{kind_lower} {type_lower}" for token in ("powerapps", "powerapp", "canvasapp", "modeldriven")) else "Power Platform resource"
    signals = []
    if owner in {None, "", "A definir"}:
        signals.append("Sem owner demonstrado")
    if not connectors and kind.lower() in {"flow", "powerautomate", "powerapps", "app"}:
        signals.append("Sem conectores demonstrados")
    if premium:
        signals.append("Conector premium")
    if state.lower() in {"disabled", "deleted", "orphaned"}:
        signals.append(f"Estado: {state}")
    return {
        "name": item.get("name") or properties.get("displayName") or "—",
        "type": resource_type,
        "kind": kind,
        "product": product,
        "is_agent": product == "Copilot Studio / Agent",
        "environment": properties.get("environmentName") or properties.get("environmentId") or "—",
        "subscription": item.get("subscriptionId") or "—",
        "resource_group": item.get("resourceGroup") or "—",
        "region": item.get("location") or properties.get("region") or "—",
        "owner": owner,
        "state": state,
        "created_at": created,
        "modified_at": modified,
        "connector_count": len(connectors) if isinstance(connectors, list) else 0,
        "premium_connectors": premium,
        "connectors": ", ".join(connector_names) or "Nenhum demonstrado",
        "governance_signal": "Atenção" if signals else "Sem sinal básico",
        "posture_signals": "; ".join(signals) or "Nenhum sinal básico",
        "resource_id": item.get("id") or "—",
    }


def summarize_power_platform(rows: list[dict]) -> dict:
    """Produz somente contagens agregadas para a camada executiva/IA."""
    kinds: dict[str, int] = {}
    environments: dict[str, int] = {}
    for row in rows:
        kind = str(row.get("kind") or "Unknown")
        environment = str(row.get("environment") or "Unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
        environments[environment] = environments.get(environment, 0) + 1
    no_owner = sum(1 for row in rows if row.get("owner") in {None, "", "A definir"})
    premium = sum(int(row.get("premium_connectors", 0) or 0) for row in rows)
    return {
        "resources": len(rows),
        "apps": sum(1 for row in rows if str(row.get("kind", "")).lower() in {"app", "powerapps"}),
        "flows": sum(1 for row in rows if str(row.get("kind", "")).lower() in {"flow", "powerautomate"}),
        "environments": len({key for key in environments if key != "Unknown"}),
        "without_owner": no_owner,
        "premium_connectors": premium,
        "power_apps": sum(1 for row in rows if row.get("product") == "Power Apps"),
        "power_automate": sum(1 for row in rows if row.get("product") == "Power Automate"),
        "copilot_studio_agents": sum(1 for row in rows if row.get("product") == "Copilot Studio / Agent"),
        "credit_consumption": "Não disponível via inventário ARG; requer API/admin center autorizado.",
        "by_kind": dict(sorted(kinds.items())),
        "by_environment": dict(sorted(environments.items(), key=lambda item: (-item[1], item[0]))),
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
    policy_assignment_rows: list[dict] = []
    policy_definition_rows: list[dict] = []
    orphan_rows: list[dict] = []
    retirement_rows: list[dict] = []
    advisor_rows: list[dict] = []
    container_rows: list[dict] = []
    power_platform_rows: list[dict] = []
    benefit_rows: list[dict] = []
    resource_group_rows: list[dict] = []
    network_health_rows: list[dict] = []
    defender_score_rows: list[dict] = []
    defender_control_rows: list[dict] = []
    inventory_result = query_arg_all_pages(
        client, subscription_ids, QUERY, QueryRequest, QueryRequestOptions
    )
    rows = [resource_row(item) for item in inventory_result]
    inventory_status = arg_result_status(inventory_result)
    inventory_note = arg_result_note("Azure inventory", inventory_result, "Consulta read-only; exposição e dependências exigem enriquecimento por módulo.")

    age_counts = [
        ("0–90 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and item["age_days"] <= 90)),
        ("91–365 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and 90 < item["age_days"] <= 365)),
        (">365 dias", sum(1 for item in rows if isinstance(item.get("age_days"), int) and item["age_days"] > 365)),
        ("Data desconhecida", sum(1 for item in rows if not isinstance(item.get("age_days"), int))),
    ]
    age_rows = [{"age_band": band, "resources": count, "percentage": f"{(count / len(rows) * 100):.1f}%" if rows else "0%"} for band, count in age_counts]

    try:
        container_result = query_arg_all_pages(client, subscription_ids, CONTAINERS_QUERY, QueryRequest, QueryRequestOptions)
        container_rows = [{
            "name": item.get("name", "—"),
            "type": item.get("type", "—"),
            "subscription": item.get("subscriptionId", "—"),
            "tenant": item.get("tenantId", "—"),
        } for item in container_result]
        hierarchy_status = arg_result_status(container_result)
        hierarchy_note = arg_result_note("Hierarquia", container_result, "Subscriptions, resource groups e management groups via ResourceContainers")
    except Exception as exc:
        hierarchy_status = "not_available"
        hierarchy_note = f"Hierarquia indisponível: {type(exc).__name__}: {exc}"

    try:
        policy_result = query_arg_all_pages(client, subscription_ids, POLICY_QUERY, QueryRequest, QueryRequestOptions)
        policy_rows = [policy_row(item) for item in policy_result]
        policy_status = arg_result_status(policy_result)
        policy_note = arg_result_note("Azure Policy states", policy_result, "Azure Policy states via Azure Resource Graph")
    except Exception as exc:
        policy_status = "not_available"
        policy_note = f"Policy Insights indisponível: {type(exc).__name__}: {exc}"

    try:
        assignment_result = query_arg_all_pages(client, subscription_ids, POLICY_ASSIGNMENTS_QUERY, QueryRequest, QueryRequestOptions)
        definition_result = query_arg_all_pages(client, subscription_ids, POLICY_DEFINITIONS_QUERY, QueryRequest, QueryRequestOptions)
        policy_definition_rows = list(definition_result)
        policy_assignment_rows = enrich_policy_assignments([policy_assignment_row(item) for item in assignment_result], policy_definition_rows)
        incomplete = not assignment_result.complete or not definition_result.complete
        if not assignment_result.complete:
            assignment_status = "partial" if assignment_result else "not_available"
        elif incomplete or (assignment_result and not policy_definition_rows):
            assignment_status = "partial"
        else:
            assignment_status = "success"
        errors = [result.error for result in (assignment_result, definition_result) if result.error]
        assignment_note = "Policy assignments e parâmetros via Azure Resource Graph."
        if errors:
            assignment_note += f" Coleta incompleta; {len(policy_assignment_rows)} registros preservados: " + "; ".join(errors)
        elif assignment_result and not policy_definition_rows:
            assignment_note += " Definições de Policy não retornadas; enriquecimento incompleto."
    except Exception as exc:
        assignment_status = "not_available"
        assignment_note = f"Policy assignments indisponíveis: {type(exc).__name__}: {exc}"

    try:
        rg_result = query_arg_all_pages(client, subscription_ids, RESOURCE_GROUP_QUERY, QueryRequest, QueryRequestOptions)
        resource_group_rows = list(rg_result)
        rg_status = arg_result_status(rg_result)
        rg_note = arg_result_note("Resource groups", rg_result, "Resource groups via ResourceContainers")
    except Exception as exc:
        rg_status = "not_available"
        rg_note = f"Resource groups indisponíveis: {type(exc).__name__}: {exc}"

    try:
        network_result = query_arg_all_pages(client, subscription_ids, NETWORK_HEALTH_QUERY, QueryRequest, QueryRequestOptions)
        network_health_rows = list(network_result)
        network_status = arg_result_status(network_result)
        network_note = arg_result_note("Sinais de rede", network_result, "Sinais de rede via Azure Resource Graph")
    except Exception as exc:
        network_status = "not_available"
        network_note = f"Sinais de rede indisponíveis: {type(exc).__name__}: {exc}"

    try:
        defender_score_rows = query_arg_all_pages(client, subscription_ids, DEFENDER_SCORE_QUERY, QueryRequest, QueryRequestOptions)
        defender_control_rows = query_arg_all_pages(client, subscription_ids, DEFENDER_CONTROLS_QUERY, QueryRequest, QueryRequestOptions)
        defender_status = "success" if (defender_score_rows or defender_control_rows) else "partial"
        defender_note = "Secure Score e controles via SecurityResources; vazio pode significar Defender não habilitado ou sem dados."
    except Exception as exc:
        defender_status = "not_available"
        defender_note = f"Secure Score indisponível: {type(exc).__name__}: {exc}"

    try:
        orphan_rows = [orphan_row(item) for item in query_arg_all_pages(client, subscription_ids, ORPHAN_QUERY, QueryRequest, QueryRequestOptions)]
        orphan_status = "success"
        orphan_note = "Heurísticas de associação via Azure Resource Graph; custo requer Cost Management"
    except Exception as exc:
        orphan_status = "not_available"
        orphan_note = f"Detecção de órfãos indisponível: {type(exc).__name__}: {exc}"

    try:
        advisor_rows = [advisor_row(item) for item in query_arg_all_pages(client, subscription_ids, ADVISOR_QUERY, QueryRequest, QueryRequestOptions)]
        advisor_status = "success"
        advisor_note = "Recomendações ativas do Azure Advisor via Azure Resource Graph"
    except Exception as exc:
        advisor_status = "not_available"
        advisor_note = f"Azure Advisor indisponível: {type(exc).__name__}: {exc}"

    try:
        retirement_rows = [retirement_row(item) for item in query_arg_all_pages(client, subscription_ids, RETIREMENT_QUERY, QueryRequest, QueryRequestOptions)]
        retirement_status = "success"
        retirement_note = "Service Health advisories via Azure Resource Graph"
    except Exception as exc:
        retirement_status = "not_available"
        retirement_note = f"Service Health indisponível: {type(exc).__name__}: {exc}"

    try:
        power_platform_rows = [power_platform_row(item) for item in query_arg_all_pages(client, subscription_ids, POWER_PLATFORM_QUERY, QueryRequest, QueryRequestOptions)]
        power_platform_status = "success" if power_platform_rows else "partial"
        power_platform_note = "PowerPlatformResources via Azure Resource Graph; inventário pode exigir habilitação no tenant."
    except Exception as exc:
        power_platform_status = "not_available"
        power_platform_note = f"Inventário Power Platform indisponível: {type(exc).__name__}: {exc}"

    try:
        benefit_rows = [{"name": item.get("name", "—"), "type": item.get("type", "—"), "subscription": item.get("subscriptionId", "—"), "resource_group": item.get("resourceGroup", "—"), "region": item.get("location", "—"), "benefit_kind": "Savings Plan" if "savingsplan" in str(item.get("type", "")).lower() else "Reservation"} for item in query_arg_all_pages(client, subscription_ids, BENEFITS_QUERY, QueryRequest, QueryRequestOptions)]
        benefits_status = "success"
        benefits_note = "Inventário de benefícios via Azure Resource Graph; ausência de registros não prova inexistência fora do escopo."
    except Exception as exc:
        benefits_status = "not_available"
        benefits_note = f"Inventário de reservas/Savings Plans indisponível: {type(exc).__name__}: {exc}"

    payload = {
        "metadata": {
            "engine_version": engine_version(),
            "run_id": f"arg-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "collected_at": started,
            "scope": {"subscriptions": len(subscription_ids), "resources_assessed": len(rows)},
            "modules": {"governance": "success", "compliance": policy_status},
        },
        "controls": [],
        "findings": [],
        "discovery": {
            "resources": rows,
            "security_posture_summary": summarize_security_posture(rows),
            "containers": container_rows,
            "policy_compliance": policy_rows,
            "policy_assignments": policy_assignment_rows,
            "resource_map": resource_map(rows),
            "resource_hygiene": hygiene_summary(rows, orphan_rows, resource_group_rows, network_health_rows),
            "defender_secure_score": defender_summary(defender_score_rows, defender_control_rows),
            "lifecycle": {
                "summary": {"Recursos órfãos": len(orphan_rows), "Recomendações Advisor": len(advisor_rows)},
                "orphan_resources": orphan_rows,
                "advisor_recommendations": advisor_rows,
                "service_retirements": retirement_rows,
                "resource_age": age_rows,
            },
            "power_platform": power_platform_rows,
            "power_platform_summary": summarize_power_platform(power_platform_rows),
            "benefits": benefit_rows,
            "benefits_summary": {"reservations": sum(1 for item in benefit_rows if item.get("benefit_kind") == "Reservation"), "savings_plans": sum(1 for item in benefit_rows if item.get("benefit_kind") == "Savings Plan")},
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
                "module": "Azure Policy assignments",
                "source": "PolicyResources / Azure Resource Graph",
                "status": assignment_status,
                "records": len(policy_assignment_rows),
                "note": assignment_note,
            }, {
                "module": "Azure hierarchy",
                "source": "ResourceContainers / Azure Resource Graph",
                "status": hierarchy_status,
                "records": len(container_rows),
                "note": hierarchy_note,
            }, {
                "module": "Resource groups hygiene",
                "source": "ResourceContainers / Azure Resource Graph",
                "status": rg_status,
                "records": len(resource_group_rows),
                "note": rg_note,
            }, {
                "module": "Network health",
                "source": "Resources / Azure Resource Graph",
                "status": network_status,
                "records": len(network_health_rows),
                "note": network_note,
            }, {
                "module": "Defender Secure Score",
                "source": "SecurityResources / Azure Resource Graph",
                "status": defender_status,
                "records": len(defender_score_rows) + len(defender_control_rows),
                "note": defender_note,
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
            }, {
                "module": "Power Platform inventory",
                "source": "PowerPlatformResources / Azure Resource Graph",
                "status": power_platform_status,
                "records": len(power_platform_rows),
                "note": power_platform_note,
            }, {
                "module": "Reservations / Savings Plans",
                "source": "BenefitsResources / Azure Resource Graph",
                "status": benefits_status,
                "records": len(benefit_rows),
                "note": benefits_note,
            }],
        },
    }
    payload["discovery"]["policy_summary"] = summarize_policy_compliance(policy_rows)
    payload["discovery"]["governance_summary"] = summarize_governance_posture(rows, policy_rows)
    return payload


def main() -> None:
    args = parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        subscription_ids = [item.strip() for item in args.subscriptions.split(",") if item.strip()]
        payload = collect(subscription_ids)
    except Exception as exc:  # falha controlada para o runner registrar o motivo
        payload = {
            "metadata": {"engine_version": engine_version(), "collected_at": utc_now(), "modules": {"governance": "error"}},
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
