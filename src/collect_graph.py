#!/usr/bin/env python3
"""Coleta sinais de identidade do Microsoft Graph em modo somente leitura."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from version import engine_version


GRAPH = "https://graph.microsoft.com/v1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return min(maximum, max(minimum, value))


def retryable_graph_status(code: int) -> bool:
    """Indica falha transitória que pode ser repetida com segurança em GET."""
    return code == 429 or code in {500, 502, 503, 504}


def sign_in_path(start_date: str) -> str:
    """Monta filtro Graph codificado; URLs nunca podem conter espaços crus."""
    encoded_filter = urllib.parse.quote(f"createdDateTime ge {start_date}", safe="")
    return f"/auditLogs/signIns?$filter={encoded_filter}&$top=1000"


def permission_grant_row(item: dict, principals: dict[str, str], resources: dict[str, str]) -> dict:
    """Normaliza consentimento OAuth sem coletar tokens ou segredos."""
    scopes = str(item.get("scope", "")).split()
    risky_scopes = {"Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", "Mail.ReadWrite", "Files.ReadWrite.All"}
    risky = sorted(scope for scope in scopes if scope in risky_scopes)
    return {"client": principals.get(item.get("clientId"), item.get("clientId", "—")), "resource": resources.get(item.get("resourceId"), item.get("resourceId", "—")), "consent_type": item.get("consentType", "—"), "principal_id": item.get("principalId") or "Delegated by admin", "scopes": " ".join(scopes) or "—", "scope_count": len(scopes), "high_impact_scopes": ", ".join(risky) or "Nenhum sinal de alto impacto"}


def build_identity_summary(users: list[dict], permission_grants: list[dict]) -> dict:
    """Produz indicadores agregados para decisão, sem expor identidade individual."""
    return {
        "Usuários avaliados": len(users),
        "Convidados externos": sum(1 for item in users if str(item.get("account_type", "")).lower() == "guest"),
        "Contas desabilitadas": sum(1 for item in users if item.get("account_enabled") is False),
        "Último sign-in desconhecido": sum(1 for item in users if str(item.get("last_sign_in", "")).lower() in {"never", "unknown", "—"}),
        "Privilegiados sem MFA": sum(1 for item in users if item.get("privileged") and item.get("mfa_status") == "Not registered"),
        "Usuários com risco de identidade": sum(1 for item in users if str(item.get("risk", "None")).lower() not in {"none", "—", "unknown"}),
        "Consentimentos de alto impacto": sum(1 for item in permission_grants if item.get("high_impact_scopes") != "Nenhum sinal de alto impacto"),
    }


def user_posture(user: dict) -> tuple[str, str]:
    """Classifica sinais individuais sem concluir incidente ou intenção."""
    signals = []
    if user.get("privileged") and user.get("mfa_status") == "Not registered":
        signals.append("Privilegiado sem MFA")
    # Graph can return userType as null. Preserve the user record and treat
    # an unknown type as unknown instead of failing the entire collection.
    account_type = str(user.get("account_type") or "").strip().lower()
    if account_type == "guest":
        signals.append("Convidado externo")
    if user.get("account_enabled") is False:
        signals.append("Conta desabilitada")
    if str(user.get("last_sign_in", "")).lower() in {"never", "none", "unknown", "—"}:
        signals.append("Sem sign-in conhecido")
    if str(user.get("risk", "None")).lower() in {"high", "medium"}:
        signals.append(f"Risco de identidade {str(user.get('risk')).lower()}")
    if any(signal == "Privilegiado sem MFA" for signal in signals) or any("Risco de identidade high" in signal for signal in signals):
        return "Crítico", "; ".join(signals)
    if signals:
        return "Atenção", "; ".join(signals)
    return "Sem sinal básico", "Nenhum sinal básico"


def conditional_access_row(item: dict) -> dict:
    """Normaliza uma política e explicita sinais de cobertura incompleta."""
    conditions = item.get("conditions") or {}
    users = conditions.get("users") or {}
    included = users.get("includeUsers") or []
    excluded = (users.get("excludeUsers") or []) + (users.get("excludeGroups") or []) + (users.get("excludeRoles") or [])
    controls = (item.get("grantControls") or {}).get("builtInControls") or []
    state = str(item.get("state") or "—")
    control_text = ", ".join(str(control) for control in controls if control) or "—"
    signals = []
    if state.lower() != "enabled":
        signals.append("Não aplicada")
    if state.lower() == "enabled" and not any("mfa" in str(control).lower() or "authenticationstrength" in str(control).lower() for control in controls):
        signals.append("Sem MFA explícito")
    if excluded:
        signals.append(f"{len(excluded)} exclusões")
    return {
        "display_name": item.get("displayName", "—"),
        "state": state,
        "users_scope": "Todos os usuários" if "All" in included else f"{len(included)} escopo(s) configurado(s)" if included else "Não informado",
        "included": len(included),
        "excluded": len(excluded),
        "grant_controls": control_text,
        "coverage": "Atenção" if signals else "Sinal básico OK",
        "risk_signal": "; ".join(signals) or "Nenhum sinal básico",
    }


def credential_posture(credentials: list[dict], now: datetime | None = None) -> dict:
    """Conta credenciais expiradas e próximas do vencimento sem ler seus valores."""
    reference = now or datetime.now(timezone.utc)
    expired = 0
    expiring_30d = 0
    for credential in credentials:
        value = credential.get("endDateTime")
        if not value:
            continue
        try:
            expiry = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        if expiry < reference:
            expired += 1
        elif expiry <= reference + timedelta(days=30):
            expiring_30d += 1
    return {"expired": expired, "expiring_30d": expiring_30d}


def secure_score_summary(scores: list[dict], controls: list[dict]) -> dict:
    """Normaliza a postura do Secure Score sem enviar detalhes sensíveis à IA."""
    latest = scores[0] if scores else {}
    current = float(latest.get("currentScore", 0) or 0)
    maximum = float(latest.get("maxScore", 0) or 0)
    return {
        "current": current,
        "maximum": maximum,
        "percentage": round(current / maximum * 100, 1) if maximum else None,
        "recommendations": len(controls),
        "high_impact_recommendations": sum(1 for item in controls if str(item.get("implementationCost", "")).lower() in {"low", "medium"} and float(item.get("maxScore", 0) or 0) > 0),
    }


def license_posture(skus: list[dict]) -> dict:
    """Resume licenças por SKU sem atribuição individual ou UPN."""
    rows = []
    for item in skus:
        prepaid = item.get("prepaidUnits") or {}
        consumed = int(item.get("consumedUnits", 0) or 0)
        enabled = int(prepaid.get("enabled", 0) or 0)
        suspended = int(prepaid.get("suspended", 0) or 0)
        utilization = round(consumed / enabled * 100, 1) if enabled else None
        name = str(item.get("skuPartNumber", "—"))
        lowered = name.lower()
        product = "Copilot" if "copilot" in lowered else "Teams Premium" if "teams_premium" in lowered or "teams premium" in lowered else "Intune" if "intune" in lowered or "ems" in lowered else "Outro"
        rows.append({"sku": name, "product_family": product, "consumed": consumed, "enabled": enabled, "suspended": suspended, "utilization_percent": utilization, "unused_enabled": max(0, enabled - consumed), "signal": "Subutilização potencial" if enabled and consumed / enabled < 0.5 else "Revisar" if suspended else "Sem sinal básico"})
    return {"sku_count": len(rows), "consumed_total": sum(row["consumed"] for row in rows), "enabled_total": sum(row["enabled"] for row in rows), "suspended_total": sum(row["suspended"] for row in rows), "product_families": {family: sum(1 for row in rows if row["product_family"] == family) for family in ("Copilot", "Teams Premium", "Intune", "Outro")}, "skus": rows}


def directory_audit_summary(events: list[dict]) -> dict:
    """Agrega auditoria sem persistir atores, IPs, IDs ou detalhes de operação."""
    high_risk_tokens = ("role", "permission", "consent", "application", "policy", "credential", "password")
    categories = Counter(str(item.get("category") or item.get("loggedByService") or "Unknown") for item in events)
    risky = sum(1 for item in events if any(token in str(item.get("activityDisplayName", "")).lower() for token in high_risk_tokens))
    return {"events": len(events), "high_risk_operation_signals": risky, "categories": dict(categories), "pii_excluded": True}


def enrich_pim_rows(rows: list[dict], users: list[dict]) -> list[dict]:
    """Resolve o principal e classifica o escopo sem consultar novos dados."""
    names = {str(item.get("id")): item.get("display_name", "—") for item in users if item.get("id")}
    for row in rows:
        scope = str(row.get("scope", "—"))
        row["principal_name"] = names.get(str(row.get("principal_id")), "Principal não resolvido")
        row["scope_kind"] = (
            "Tenant" if scope in {"/", "—"} else
            "Administrative unit" if scope.lower().startswith("/administrativeunits/") else
            "Directory scope"
        )
    return rows


def aggregate_graph_status(logs: list[dict], module_names: set[str]) -> str:
    """Deriva o estado do domínio dos endpoints consultados, não do número de linhas."""
    statuses = [
        str(item.get("status", "unknown"))
        for item in logs
        if item.get("module") in module_names
    ]
    if not statuses:
        return "not_available"
    if all(status == "success" for status in statuses):
        return "success"
    if all(status == "not_run" for status in statuses):
        return "not_run"
    if all(status == "not_available" for status in statuses):
        return "not_available"
    if "success" in statuses or "partial" in statuses:
        return "partial"
    if "error" in statuses:
        return "error"
    return "partial"


def graph_failure_note(code: int, permission_hint: str) -> str:
    """Mantém a causa observada separada das hipóteses de permissão/licença."""
    if code == 401:
        return f"HTTP 401 Unauthorized; sessão/token Graph não aceito. Escopo esperado: {permission_hint}"
    if code == 403:
        return f"HTTP 403 Forbidden; acesso negado pelo serviço. Verifique consentimento/role read-only. Escopo esperado: {permission_hint}"
    if code == 429:
        return f"HTTP 429 Too Many Requests; throttling após tentativas configuradas. Escopo esperado: {permission_hint}"
    if code == 400:
        return f"HTTP 400 Bad Request; valide endpoint, parâmetros, disponibilidade e entitlement antes de ampliar permissões. Escopo esperado: {permission_hint}"
    if code >= 500:
        return f"HTTP {code}; falha transitória do serviço após tentativas configuradas. Escopo esperado: {permission_hint}"
    return f"HTTP {code}; chamada Graph não concluída. Escopo esperado: {permission_hint}"


def collect() -> dict:
    started = utc_now()
    from azure.identity import AzureCliCredential, DefaultAzureCredential

    # Preflight checks the Azure CLI Graph session. Use that same identity for
    # interactive consultant runs rather than a different cached credential
    # that DefaultAzureCredential might select on the machine.
    service_principal_mode = bool(os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_TENANT_ID"))
    credential = (
        DefaultAzureCredential(exclude_interactive_browser_credential=True)
        if service_principal_mode else AzureCliCredential()
    )
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    logs: list[dict] = []
    request_timeout = bounded_env_int("ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS", 30, 5, 300)
    max_retries = bounded_env_int("ASSESSMENT_GRAPH_MAX_RETRIES", 3, 0, 5)
    authentication_failed = False

    def get_all(path: str, module: str, permission_hint: str, max_pages: int | None = None) -> list[dict]:
        nonlocal authentication_failed
        rows: list[dict] = []
        if authentication_failed:
            logs.append({
                "module": module,
                "source": "Microsoft Graph",
                "status": "not_available",
                "records": 0,
                "note": "Consulta não executada: uma chamada anterior retornou HTTP 401; autenticação Graph indisponível nesta execução.",
            })
            return rows
        url = f"{GRAPH}{path}"
        requested_urls = {url}
        graph_host = urllib.parse.urlparse(GRAPH).netloc.lower()
        pages = 0
        attempts = 0
        try:
            while url:
                request = urllib.request.Request(url, headers=headers, method="GET")
                try:
                    with urllib.request.urlopen(request, timeout=request_timeout) as response:
                        payload = json.load(response)
                except urllib.error.HTTPError as exc:
                    if retryable_graph_status(exc.code) and attempts < max_retries:
                        retry_after = exc.headers.get("Retry-After", "1") if exc.headers else "1"
                        try:
                            delay = min(8, max(1, int(retry_after)))
                        except ValueError:
                            delay = 1
                        attempts += 1
                        time.sleep(delay)
                        continue
                    raise
                attempts = 0
                rows.extend(payload.get("value", []))
                pages += 1
                next_url = payload.get("@odata.nextLink")
                if next_url:
                    parsed_next = urllib.parse.urlparse(str(next_url))
                    if parsed_next.scheme != "https" or parsed_next.netloc.lower() != graph_host:
                        logs.append({
                            "module": module,
                            "source": "Microsoft Graph",
                            "status": "partial",
                            "records": len(rows),
                            "note": "Paginação interrompida: o nextLink não pertence ao host Microsoft Graph esperado.",
                        })
                        return rows
                    if next_url in requested_urls:
                        logs.append({
                            "module": module,
                            "source": "Microsoft Graph",
                            "status": "partial",
                            "records": len(rows),
                            "note": "Paginação interrompida: Microsoft Graph repetiu o nextLink; a evidência já recebida foi preservada.",
                        })
                        return rows
                    requested_urls.add(next_url)
                if max_pages and pages >= max_pages:
                    if next_url:
                        logs.append({"module": module, "source": "Microsoft Graph", "status": "partial", "records": len(rows), "note": f"Limite de {max_pages} páginas aplicada para proteger duração e carga da coleta."})
                    else:
                        logs.append({"module": module, "source": "Microsoft Graph", "status": "success", "records": len(rows), "note": permission_hint})
                    return rows
                url = next_url
            logs.append({"module": module, "source": "Microsoft Graph", "status": "success", "records": len(rows), "note": permission_hint})
            return rows
        except urllib.error.HTTPError as exc:
            note = graph_failure_note(exc.code, permission_hint)
            if exc.code == 401:
                # Authentication is tenant/session-wide for this bearer token.
                # Stop issuing identical failed GETs, but keep evidence collected
                # by earlier endpoints and make every skipped module explicit.
                authentication_failed = True
            logs.append({"module": module, "source": "Microsoft Graph", "status": "partial" if rows else "not_available", "records": len(rows), "note": note})
            return rows
        except Exception as exc:
            timed_out = isinstance(exc, (TimeoutError, urllib.error.URLError)) and (
                isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
            )
            status = "partial" if rows else ("error" if not timed_out else "not_available")
            note = f"{type(exc).__name__}: {exc}"
            if rows:
                note = f"Coleta interrompida após {len(rows)} registros: {note}"
            logs.append({"module": module, "source": "Microsoft Graph", "status": status, "records": len(rows), "note": note})
            return rows

    users = get_all("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,signInActivity", "Identity", "User.Read.All + AuditLog.Read.All")
    if not users and not authentication_failed:
        # signInActivity pode exigir licença/retenção/permissão adicional. A
        # indisponibilidade desse campo não deve eliminar o inventário básico.
        users = get_all("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled", "Identity basic", "User.Read.All")
    registrations = get_all("/reports/authenticationMethods/userRegistrationDetails", "MFA", "Reports.Read.All")
    groups = get_all("/groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled,visibility,createdDateTime,membershipRule&$top=999", "Groups", "Group.Read.All")
    subscribed_skus = get_all("/subscribedSkus?$select=skuPartNumber,skuId,consumedUnits,prepaidUnits,capabilityStatus&$top=999", "M365 licenses", "LicenseAssignment.Read.All")
    policies = get_all("/identity/conditionalAccess/policies", "Conditional Access", "Policy.Read.All")
    risky = get_all("/identityProtection/riskyUsers?$select=id,userDisplayName,userPrincipalName,riskLevel,riskState", "Identity risk", "IdentityRiskyUser.Read.All")
    secure_scores = get_all("/security/secureScores?$top=5", "Secure Score", "SecurityEvents.Read.All")
    secure_score_controls = get_all("/security/secureScoreControlProfiles?$top=999", "Secure Score controls", "SecurityEvents.Read.All")
    devices = get_all("/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime&$top=999", "Entra devices", "Device.Read.All")
    managed_devices = get_all("/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,managementState,lastSyncDateTime,userPrincipalName&$top=999", "Intune managed devices", "DeviceManagementManagedDevices.Read.All")
    service_principals = get_all("/servicePrincipals?$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,signInAudience,createdDateTime&$top=999", "Enterprise applications", "Application.Read.All")
    applications = get_all("/applications?$select=id,appId,displayName,signInAudience,requiredResourceAccess,createdDateTime,passwordCredentials,keyCredentials&$top=999", "App registrations", "Application.Read.All")
    permission_grants = get_all("/oauth2PermissionGrants?$select=clientId,consentType,principalId,resourceId,scope&$top=999", "Application consents", "DelegatedPermissionGrant.Read.All")
    role_assignments = get_all("/roleManagement/directory/roleAssignmentScheduleInstances?$select=principalId,roleDefinitionId,assignmentType,directoryScopeId,startDateTime,endDateTime,memberType&$top=999", "PIM active assignments", "RoleAssignmentSchedule.Read.Directory")
    role_eligibility = get_all("/roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType&$top=999", "PIM eligible assignments", "RoleEligibilitySchedule.Read.Directory")
    role_definitions = get_all("/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn&$top=999", "PIM role definitions", "RoleManagement.Read.Directory")
    defender_alerts = get_all("/security/alerts_v2?$select=severity,status,serviceSource,createdDateTime&$top=1000", "Defender alerts", "SecurityIncident.Read.All")
    defender_vulnerabilities = get_all("/security/vulnerabilities?$select=id,name,description,severity,status,createdDateTime,lastModifiedDateTime&$top=1000", "Defender vulnerabilities", "Vulnerability.Read.All")
    audit_max_pages = bounded_env_int("ASSESSMENT_AUDIT_MAX_PAGES", 10, 0, 10000)
    directory_audits = get_all("/auditLogs/directoryAudits?$top=100", "Directory audit events", "AuditLog.Read.All", max_pages=audit_max_pages or None)

    lookback_days = bounded_env_int("ASSESSMENT_SIGNIN_LOOKBACK_DAYS", 30, 1, 365)
    start_date = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Zero significa sem limite artificial: a paginação do Graph segue até o
    # fim da janela. Em tenants enormes, o cliente pode definir um limite
    # consciente por variável de ambiente e o manifesto marcará partial.
    # Limite seguro para Cloud Shell. Defina 0 conscientemente para consultar
    # todas as páginas; quando o limite é atingido, o log fica partial.
    sign_in_max_pages = bounded_env_int("ASSESSMENT_SIGNIN_MAX_PAGES", 10, 0, 10000)
    signins = get_all(sign_in_path(start_date), "Sign-ins / legacy auth", "AuditLog.Read.All", max_pages=sign_in_max_pages or None)
    legacy_clients = {"exchange activesync", "other clients", "imap4", "pop3", "smtp"}
    legacy_signins = [{
        "user_display_name": item.get("userDisplayName", "—"),
        "user_principal_name": item.get("userPrincipalName", "—"),
        "client_app": item.get("clientAppUsed", "—"),
        "application": item.get("appDisplayName", "—"),
        "created_at": item.get("createdDateTime", "—"),
        "result": "Success" if (item.get("status") or {}).get("errorCode", 0) == 0 else "Failed",
    } for item in signins if str(item.get("clientAppUsed", "")).strip().lower() in legacy_clients]

    # Funções privilegiadas permitem separar a cobertura de MFA dos usuários
    # comuns da cobertura de administradores. O endpoint é opcional: tenants
    # sem a permissão adequada continuam entregando o inventário básico.
    directory_roles = get_all("/directoryRoles", "Directory roles", "RoleManagement.Read.Directory")
    privileged_by_id: dict[str, list[str]] = {}
    for role in directory_roles:
        role_id = role.get("id")
        role_name = role.get("displayName", "Privileged role")
        if not role_id:
            continue
        members = get_all(
            f"/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName",
            f"Role members: {role_name}",
            "RoleManagement.Read.Directory + Directory.Read.All",
        )
        for member in members:
            if member.get("id"):
                privileged_by_id.setdefault(member["id"], []).append(role_name)

    registration_by_upn = {str(item.get("userPrincipalName", "")).lower(): item for item in registrations}
    risky_by_id = {item.get("id"): item for item in risky}
    normalized_users = []
    for item in users:
        upn = item.get("userPrincipalName", "")
        registration = registration_by_upn.get(str(upn).lower(), {})
        risk = risky_by_id.get(item.get("id"), {})
        account_type = str(item.get("userType") or "Unknown")
        base_user = {"privileged": bool(privileged_by_id.get(item.get("id"))), "mfa_status": "Registered" if registration.get("isMfaRegistered") else ("Not registered" if registration else "Unknown"), "account_type": account_type, "account_enabled": item.get("accountEnabled", "—"), "last_sign_in": (item.get("signInActivity") or {}).get("lastSignInDateTime", "Never"), "risk": risk.get("riskLevel", "None")}
        posture_level, posture_signal = user_posture(base_user)
        normalized_users.append({
            "id": item.get("id", "—"),
            "display_name": item.get("displayName", "—"),
            "user_principal_name": upn or "—",
            "account_type": account_type,
            "account_enabled": item.get("accountEnabled", "—"),
            "mfa_status": "Registered" if registration.get("isMfaRegistered") else ("Not registered" if registration else "Unknown"),
            "mfa_methods": ", ".join(str(method) for method in (registration.get("methodsRegistered") or []) if method) or "—",
            "ca_coverage": "Configured in policy" if any(str(policy.get("state", "")).lower() == "enabled" for policy in policies) else "Unknown",
            "privileged": bool(privileged_by_id.get(item.get("id"))),
            "privileged_roles": ", ".join(privileged_by_id.get(item.get("id"), [])) or "—",
            "risk": risk.get("riskLevel", "None"),
            "risk_state": risk.get("riskState", "—"),
            "last_sign_in": (item.get("signInActivity") or {}).get("lastSignInDateTime", "Never"),
            "posture_level": posture_level,
            "posture_signal": posture_signal,
        })

    normalized_policies = []
    for item in policies:
        normalized_policies.append(conditional_access_row(item))

    normalized_devices = []
    for item in devices:
        normalized_devices.append({
            "name": item.get("displayName", "—"),
            "operating_system": item.get("operatingSystem", "—"),
            "os_version": item.get("operatingSystemVersion", "—"),
            "trust_type": item.get("trustType", "—"),
            "compliant": item.get("isCompliant", "Unknown"),
            "managed": item.get("isManaged", "Unknown"),
            "last_sign_in": item.get("approximateLastSignInDateTime", "Never"),
            "source": "Entra ID",
        })
    for item in managed_devices:
        normalized_devices.append({
            "name": item.get("deviceName", "—"),
            "operating_system": item.get("operatingSystem", "—"),
            "os_version": item.get("osVersion", "—"),
            "trust_type": "Intune managed",
            "compliant": item.get("complianceState", "Unknown"),
            "managed": item.get("managementState", "Unknown"),
            "last_sign_in": item.get("lastSyncDateTime", "Never"),
            "user": item.get("userPrincipalName", "—"),
            "source": "Intune",
        })
    device_summary = {
        "entra_devices": len(normalized_devices) - len(managed_devices),
        "intune_devices": len(managed_devices),
        "non_compliant": sum(1 for item in normalized_devices if str(item.get("compliant", "")).lower() in {"false", "noncompliant", "not compliant"}),
        "unmanaged": sum(1 for item in normalized_devices if str(item.get("managed", "")).lower() in {"false", "unmanaged", "not managed"}),
        "unknown_posture": sum(1 for item in normalized_devices if str(item.get("compliant", "")).lower() in {"unknown", "—", "none"}),
    }
    app_rows = [{
        "name": item.get("displayName", "—"), "app_id": item.get("appId", "—"),
        "enabled": item.get("accountEnabled", "—"), "type": item.get("servicePrincipalType", "—"),
        "assignment_required": item.get("appRoleAssignmentRequired", "—"), "audience": item.get("signInAudience", "—"),
        "created_at": item.get("createdDateTime", "—"), "source": "Enterprise application"
    } for item in service_principals]
    registration_rows = []
    for item in applications:
        credentials = (item.get("passwordCredentials") or []) + (item.get("keyCredentials") or [])
        credential_expirations = [credential.get("endDateTime") for credential in credentials if credential.get("endDateTime")]
        posture = credential_posture(credentials)
        registration_rows.append({
            "name": item.get("displayName", "—"), "app_id": item.get("appId", "—"),
            "audience": item.get("signInAudience", "—"), "required_permissions": len(item.get("requiredResourceAccess") or []),
            "credentials": len(credentials), "password_credentials": len(item.get("passwordCredentials") or []),
            "certificate_credentials": len(item.get("keyCredentials") or []), "credential_expirations": ", ".join(credential_expirations) or "—", "expired_credentials": posture["expired"], "expiring_30d": posture["expiring_30d"], "credential_risk": "Crítico" if posture["expired"] else ("Alto" if posture["expiring_30d"] else ("Revisar" if credentials else "Sem credencial")), "created_at": item.get("createdDateTime", "—")
        })
    role_names = {item.get("id"): item.get("displayName", "—") for item in role_definitions}
    pim_rows = [{"principal_id": item.get("principalId", "—"), "role_id": item.get("roleDefinitionId", "—"), "role": role_names.get(item.get("roleDefinitionId"), "—"), "assignment_type": "Active", "member_type": item.get("memberType", "—"), "scope": item.get("directoryScopeId", "—"), "start": item.get("startDateTime", "—"), "end": item.get("endDateTime", "—")} for item in role_assignments]
    pim_rows.extend({"principal_id": item.get("principalId", "—"), "role_id": item.get("roleDefinitionId", "—"), "role": role_names.get(item.get("roleDefinitionId"), "—"), "assignment_type": "Eligible", "member_type": item.get("memberType", "—"), "scope": item.get("directoryScopeId", "—"), "start": item.get("startDateTime", "—"), "end": item.get("endDateTime", "—")} for item in role_eligibility)
    pim_rows = enrich_pim_rows(pim_rows, normalized_users)
    defender_summary = {"alerts": len(defender_alerts), "high": sum(1 for item in defender_alerts if str(item.get("severity", "")).lower() == "high"), "medium": sum(1 for item in defender_alerts if str(item.get("severity", "")).lower() == "medium"), "active": sum(1 for item in defender_alerts if str(item.get("status", "")).lower() not in {"resolved", "closed"})}
    normalized_alerts = [{"severity": item.get("severity", "—"), "status": item.get("status", "—"), "source": item.get("serviceSource", "—"), "created_at": item.get("createdDateTime", "—")} for item in defender_alerts]
    normalized_vulnerabilities = [{"name": item.get("name", "—"), "severity": item.get("severity", "—"), "status": item.get("status", "—"), "created_at": item.get("createdDateTime", "—"), "updated_at": item.get("lastModifiedDateTime", "—")} for item in defender_vulnerabilities]
    normalized_groups = [{"name": item.get("displayName", "—"), "group_type": ", ".join(str(group_type) for group_type in (item.get("groupTypes") or []) if group_type) or "Security/M365", "security_enabled": item.get("securityEnabled", "—"), "mail_enabled": item.get("mailEnabled", "—"), "visibility": item.get("visibility", "—"), "created_at": item.get("createdDateTime", "—"), "dynamic": bool(item.get("membershipRule"))} for item in groups]
    normalized_skus = [{"sku": item.get("skuPartNumber", "—"), "consumed": item.get("consumedUnits", 0), "enabled": (item.get("prepaidUnits") or {}).get("enabled", 0), "suspended": (item.get("prepaidUnits") or {}).get("suspended", 0), "status": item.get("capabilityStatus", "—")} for item in subscribed_skus]
    license_summary = license_posture(subscribed_skus)
    principal_names = {item.get("id"): item.get("displayName", "—") for item in service_principals}
    principal_names.update({item.get("appId"): item.get("displayName", "—") for item in service_principals})
    normalized_permission_grants = [permission_grant_row(item, principal_names, principal_names) for item in permission_grants]
    identity_summary = build_identity_summary(normalized_users, normalized_permission_grants)
    score_summary = secure_score_summary(secure_scores, secure_score_controls)

    result = {
        "metadata": {"engine_version": engine_version(), "run_id": f"graph-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}", "collected_at": started, "scope": {"users_assessed": len(normalized_users), "privileged_users_identified": sum(1 for item in normalized_users if item.get("privileged")), "signins_reviewed": len(signins), "legacy_auth_signins": len(legacy_signins), "devices_assessed": len(normalized_devices), "enterprise_applications": len(app_rows), "app_registrations": len(registration_rows), "groups_assessed": len(normalized_groups), "licenses_assessed": len(normalized_skus)}, "modules": {}},
        "controls": [],
        "findings": [],
        "discovery": {"users": normalized_users, "conditional_access": normalized_policies, "risky_users": risky, "groups": normalized_groups, "licenses": normalized_skus, "license_summary": license_summary, "directory_audit_summary": directory_audit_summary(directory_audits), "conditional_access": normalized_policies, "devices": normalized_devices, "device_summary": device_summary, "enterprise_applications": app_rows, "app_registrations": registration_rows, "oauth2_permission_grants": normalized_permission_grants, "pim_assignments": pim_rows, "pim_summary": {"active": len(role_assignments), "eligible": len(role_eligibility), "permanent_or_active": sum(1 for item in role_assignments if str(item.get("assignmentType", "")).lower() != "eligible")}, "defender_summary": {**defender_summary, "vulnerabilities": len(normalized_vulnerabilities), "critical_vulnerabilities": sum(1 for item in normalized_vulnerabilities if str(item.get("severity", "")).lower() == "critical")}, "defender_alerts": normalized_alerts, "defender_vulnerabilities": normalized_vulnerabilities, "secure_score": secure_scores, "secure_score_controls": [{"id": item.get("id", "—"), "title": item.get("title", "—"), "category": item.get("controlCategory", "—"), "max_score": item.get("maxScore", 0), "implementation_cost": item.get("implementationCost", "—"), "remediation": item.get("remediation", "—"), "action_url": item.get("actionUrl", "—")} for item in secure_score_controls], "legacy_auth_signins": legacy_signins, "legacy_auth_summary": {"lookback_days": lookback_days, "max_pages": sign_in_max_pages or "unlimited", "signins_reviewed": len(signins), "legacy_signins": len(legacy_signins), "affected_users": len({item.get("user_principal_name") for item in legacy_signins})}, "directory_roles": [{"role": item.get("displayName", "—"), "role_id": item.get("id", "—")} for item in directory_roles], "collection_log": logs},
    }
    identity_endpoints = {
        "Identity", "Identity basic", "MFA", "Groups", "M365 licenses",
        "Conditional Access", "Identity risk", "Entra devices",
        "Intune managed devices", "Enterprise applications", "App registrations",
        "Application consents", "PIM active assignments", "PIM eligible assignments",
        "PIM role definitions", "Directory roles",
    }
    identity_endpoints.update(
        str(item.get("module", ""))
        for item in logs
        if str(item.get("module", "")).startswith("Role members:")
    )
    security_endpoints = {
        "Secure Score", "Secure Score controls", "Defender alerts",
        "Defender vulnerabilities", "Directory audit events",
        "Sign-ins / legacy auth",
    }
    result["metadata"]["modules"] = {
        "identity": aggregate_graph_status(logs, identity_endpoints),
        "security": aggregate_graph_status(logs, security_endpoints),
    }
    result["discovery"]["user_summary"] = identity_summary
    result["discovery"]["secure_score_summary"] = score_summary
    return result
