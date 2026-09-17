#!/usr/bin/env python3
"""Coleta sinais de identidade do Microsoft Graph em modo somente leitura."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


GRAPH = "https://graph.microsoft.com/v1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def collect() -> dict:
    started = utc_now()
    from azure.identity import DefaultAzureCredential

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    logs: list[dict] = []

    def get_all(path: str, module: str, permission_hint: str, max_pages: int | None = None) -> list[dict]:
        rows: list[dict] = []
        url = f"{GRAPH}{path}"
        pages = 0
        try:
            while url:
                request = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(request, timeout=60) as response:
                    payload = json.load(response)
                rows.extend(payload.get("value", []))
                pages += 1
                if max_pages and pages >= max_pages:
                    if payload.get("@odata.nextLink"):
                        logs.append({"module": module, "source": "Microsoft Graph", "status": "partial", "records": len(rows), "note": f"Limite de {max_pages} páginas aplicada para proteger duração e carga da coleta."})
                    else:
                        logs.append({"module": module, "source": "Microsoft Graph", "status": "success", "records": len(rows), "note": permission_hint})
                    return rows
                url = payload.get("@odata.nextLink")
            logs.append({"module": module, "source": "Microsoft Graph", "status": "success", "records": len(rows), "note": permission_hint})
            return rows
        except urllib.error.HTTPError as exc:
            note = f"HTTP {exc.code}; verifique consentimento/licença: {permission_hint}"
            logs.append({"module": module, "source": "Microsoft Graph", "status": "not_available", "records": 0, "note": note})
            return []
        except Exception as exc:
            logs.append({"module": module, "source": "Microsoft Graph", "status": "error", "records": 0, "note": f"{type(exc).__name__}: {exc}"})
            return []

    users = get_all("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled,signInActivity", "Identity", "User.Read.All + AuditLog.Read.All")
    if not users:
        # signInActivity pode exigir licença/retenção/permissão adicional. A
        # indisponibilidade desse campo não deve eliminar o inventário básico.
        users = get_all("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled", "Identity basic", "User.Read.All")
    registrations = get_all("/reports/authenticationMethods/userRegistrationDetails", "MFA", "Reports.Read.All")
    groups = get_all("/groups?$select=id,displayName,groupTypes,securityEnabled,mailEnabled,visibility,createdDateTime,membershipRule&$top=999", "Groups", "Group.Read.All")
    subscribed_skus = get_all("/subscribedSkus?$select=skuPartNumber,skuId,consumedUnits,prepaidUnits,capabilityStatus&$top=999", "M365 licenses", "Organization.Read.All")
    policies = get_all("/identity/conditionalAccess/policies", "Conditional Access", "Policy.Read.All")
    risky = get_all("/identityProtection/riskyUsers?$select=id,userDisplayName,userPrincipalName,riskLevel,riskState", "Identity risk", "IdentityRiskyUser.Read.All")
    secure_scores = get_all("/security/secureScores?$top=5", "Secure Score", "SecurityEvents.Read.All")
    secure_score_controls = get_all("/security/secureScoreControlProfiles?$top=999", "Secure Score controls", "SecurityEvents.Read.All")
    devices = get_all("/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime&$top=999", "Entra devices", "Device.Read.All")
    managed_devices = get_all("/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,managementState,lastSyncDateTime,userPrincipalName&$top=999", "Intune managed devices", "DeviceManagementManagedDevices.Read.All")
    service_principals = get_all("/servicePrincipals?$select=id,appId,displayName,accountEnabled,appRoleAssignmentRequired,servicePrincipalType,signInAudience,createdDateTime&$top=999", "Enterprise applications", "Application.Read.All")
    applications = get_all("/applications?$select=id,appId,displayName,signInAudience,requiredResourceAccess,createdDateTime,passwordCredentials,keyCredentials&$top=999", "App registrations", "Application.Read.All")
    permission_grants = get_all("/oauth2PermissionGrants?$select=clientId,consentType,principalId,resourceId,scope&$top=999", "Application consents", "DelegatedPermissionGrant.Read.All")
    role_assignments = get_all("/roleManagement/directory/roleAssignmentScheduleInstances?$select=principalId,roleDefinitionId,assignmentType,directoryScopeId,startDateTime,endDateTime,memberType&$top=999", "PIM active assignments", "RoleManagement.Read.Directory")
    role_eligibility = get_all("/roleManagement/directory/roleEligibilityScheduleInstances?$select=principalId,roleDefinitionId,directoryScopeId,startDateTime,endDateTime,memberType&$top=999", "PIM eligible assignments", "RoleManagement.Read.Directory")
    role_definitions = get_all("/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn&$top=999", "PIM role definitions", "RoleManagement.Read.Directory")
    defender_alerts = get_all("/security/alerts_v2?$select=severity,status,serviceSource,createdDateTime&$top=1000", "Defender alerts", "SecurityIncident.Read.All")
    defender_vulnerabilities = get_all("/security/vulnerabilities?$select=id,name,description,severity,status,createdDateTime,lastModifiedDateTime&$top=1000", "Defender vulnerabilities", "Vulnerability.Read.All")

    lookback_days = max(1, int(os.getenv("ASSESSMENT_SIGNIN_LOOKBACK_DAYS", "30")))
    start_date = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins = get_all(sign_in_path(start_date), "Sign-ins / legacy auth", "AuditLog.Read.All", max_pages=5)
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
        normalized_users.append({
            "display_name": item.get("displayName", "—"),
            "user_principal_name": upn or "—",
            "account_type": item.get("userType", "Member"),
            "account_enabled": item.get("accountEnabled", "—"),
            "mfa_status": "Registered" if registration.get("isMfaRegistered") else ("Not registered" if registration else "Unknown"),
            "mfa_methods": ", ".join(registration.get("methodsRegistered", [])) or "—",
            "ca_coverage": "Configured in policy" if any(str(policy.get("state", "")).lower() == "enabled" for policy in policies) else "Unknown",
            "privileged": bool(privileged_by_id.get(item.get("id"))),
            "privileged_roles": ", ".join(privileged_by_id.get(item.get("id"), [])) or "—",
            "risk": risk.get("riskLevel", "None"),
            "risk_state": risk.get("riskState", "—"),
            "last_sign_in": (item.get("signInActivity") or {}).get("lastSignInDateTime", "Never"),
        })

    normalized_policies = []
    for item in policies:
        conditions = item.get("conditions") or {}
        users_condition = conditions.get("users") or {}
        excluded = users_condition.get("excludeUsers", []) + users_condition.get("excludeGroups", []) + users_condition.get("excludeRoles", [])
        normalized_policies.append({
            "display_name": item.get("displayName", "—"),
            "state": item.get("state", "—"),
            "users_scope": "Configured in Graph",
            "excluded": len(excluded),
            "grant_controls": ", ".join((item.get("grantControls") or {}).get("builtInControls", [])) or "—",
            "coverage": "To be calculated",
        })

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
        registration_rows.append({
            "name": item.get("displayName", "—"), "app_id": item.get("appId", "—"),
            "audience": item.get("signInAudience", "—"), "required_permissions": len(item.get("requiredResourceAccess") or []),
            "credentials": len(credentials), "password_credentials": len(item.get("passwordCredentials") or []),
            "certificate_credentials": len(item.get("keyCredentials") or []), "credential_expirations": ", ".join(credential_expirations) or "—", "created_at": item.get("createdDateTime", "—")
        })
    role_names = {item.get("id"): item.get("displayName", "—") for item in role_definitions}
    pim_rows = [{"principal_id": item.get("principalId", "—"), "role_id": item.get("roleDefinitionId", "—"), "role": role_names.get(item.get("roleDefinitionId"), "—"), "assignment_type": "Active", "member_type": item.get("memberType", "—"), "scope": item.get("directoryScopeId", "—"), "start": item.get("startDateTime", "—"), "end": item.get("endDateTime", "—")} for item in role_assignments]
    pim_rows.extend({"principal_id": item.get("principalId", "—"), "role_id": item.get("roleDefinitionId", "—"), "role": role_names.get(item.get("roleDefinitionId"), "—"), "assignment_type": "Eligible", "member_type": item.get("memberType", "—"), "scope": item.get("directoryScopeId", "—"), "start": item.get("startDateTime", "—"), "end": item.get("endDateTime", "—")} for item in role_eligibility)
    defender_summary = {"alerts": len(defender_alerts), "high": sum(1 for item in defender_alerts if str(item.get("severity", "")).lower() == "high"), "medium": sum(1 for item in defender_alerts if str(item.get("severity", "")).lower() == "medium"), "active": sum(1 for item in defender_alerts if str(item.get("status", "")).lower() not in {"resolved", "closed"})}
    normalized_alerts = [{"severity": item.get("severity", "—"), "status": item.get("status", "—"), "source": item.get("serviceSource", "—"), "created_at": item.get("createdDateTime", "—")} for item in defender_alerts]
    normalized_vulnerabilities = [{"name": item.get("name", "—"), "severity": item.get("severity", "—"), "status": item.get("status", "—"), "created_at": item.get("createdDateTime", "—"), "updated_at": item.get("lastModifiedDateTime", "—")} for item in defender_vulnerabilities]
    normalized_groups = [{"name": item.get("displayName", "—"), "group_type": ", ".join(item.get("groupTypes", [])) or "Security/M365", "security_enabled": item.get("securityEnabled", "—"), "mail_enabled": item.get("mailEnabled", "—"), "visibility": item.get("visibility", "—"), "created_at": item.get("createdDateTime", "—"), "dynamic": bool(item.get("membershipRule"))} for item in groups]
    normalized_skus = [{"sku": item.get("skuPartNumber", "—"), "consumed": item.get("consumedUnits", 0), "enabled": (item.get("prepaidUnits") or {}).get("enabled", 0), "suspended": (item.get("prepaidUnits") or {}).get("suspended", 0), "status": item.get("capabilityStatus", "—")} for item in subscribed_skus]
    principal_names = {item.get("id"): item.get("displayName", "—") for item in service_principals}
    principal_names.update({item.get("appId"): item.get("displayName", "—") for item in service_principals})
    normalized_permission_grants = [permission_grant_row(item, principal_names, principal_names) for item in permission_grants]

    result = {
        "metadata": {"engine_version": "0.1.5", "run_id": f"graph-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}", "collected_at": started, "scope": {"users_assessed": len(normalized_users), "privileged_users_identified": sum(1 for item in normalized_users if item.get("privileged")), "signins_reviewed": len(signins), "legacy_auth_signins": len(legacy_signins), "devices_assessed": len(normalized_devices), "enterprise_applications": len(app_rows), "app_registrations": len(registration_rows), "groups_assessed": len(normalized_groups), "licenses_assessed": len(normalized_skus)}, "modules": {"identity": "success" if users else "not_available", "security": "success" if secure_scores else "not_available"}},
        "controls": [],
        "findings": [],
        "discovery": {"users": normalized_users, "conditional_access": normalized_policies, "risky_users": risky, "groups": normalized_groups, "licenses": normalized_skus, "conditional_access": normalized_policies, "devices": normalized_devices, "device_summary": device_summary, "enterprise_applications": app_rows, "app_registrations": registration_rows, "oauth2_permission_grants": normalized_permission_grants, "pim_assignments": pim_rows, "pim_summary": {"active": len(role_assignments), "eligible": len(role_eligibility), "permanent_or_active": sum(1 for item in role_assignments if str(item.get("assignmentType", "")).lower() != "eligible")}, "defender_summary": {**defender_summary, "vulnerabilities": len(normalized_vulnerabilities), "critical_vulnerabilities": sum(1 for item in normalized_vulnerabilities if str(item.get("severity", "")).lower() == "critical")}, "defender_alerts": normalized_alerts, "defender_vulnerabilities": normalized_vulnerabilities, "secure_score": secure_scores, "secure_score_controls": [{"id": item.get("id", "—"), "title": item.get("title", "—"), "category": item.get("controlCategory", "—"), "max_score": item.get("maxScore", 0), "implementation_cost": item.get("implementationCost", "—"), "remediation": item.get("remediation", "—"), "action_url": item.get("actionUrl", "—")} for item in secure_score_controls], "legacy_auth_signins": legacy_signins, "legacy_auth_summary": {"lookback_days": lookback_days, "signins_reviewed": len(signins), "legacy_signins": len(legacy_signins), "affected_users": len({item.get("user_principal_name") for item in legacy_signins})}, "directory_roles": [{"role": item.get("displayName", "—"), "role_id": item.get("id", "—")} for item in directory_roles], "collection_log": logs},
    }
    return result
