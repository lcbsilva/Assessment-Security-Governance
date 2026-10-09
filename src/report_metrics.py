"""Shared executive KPIs with evidence-state gates for every report format."""

from __future__ import annotations


def _status_for_names(logs: list[dict], names: tuple[str, ...]) -> str:
    wanted = {name.casefold() for name in names}
    matching = [
        str(row.get("status", "unknown")).casefold()
        for row in logs
        if str(row.get("module", "")).casefold() in wanted
    ]
    if not matching:
        return "unknown"
    for status in ("error", "partial", "not_available", "not_run"):
        if status in matching:
            return status
    return "success" if all(status == "success" for status in matching) else "unknown"


def _combined_status(statuses: list[str]) -> str:
    for status in ("error", "partial", "not_available", "not_run", "unknown"):
        if status in statuses:
            return status
    return "success" if statuses and all(status == "success" for status in statuses) else "unknown"


def build_executive_metrics(data: dict) -> list[dict]:
    """Return the canonical source-aware KPI set consumed by HTML and exports.

    A zero is emitted only if the complete source group succeeded. Partial
    collection is withheld from summary cards rather than presented as a
    complete total; the technical evidence remains available in the report.
    """
    metadata = data.get("metadata", {}) or {}
    aggregate_identity = str((metadata.get("modules", {}) or {}).get("identity", "")).casefold()
    discovery = data.get("discovery", {}) or {}
    logs = discovery.get("collection_log", []) or []
    users = discovery.get("users", []) or []
    user_summary = discovery.get("user_summary", {}) or []
    rbac = discovery.get("rbac", []) or []
    resources = discovery.get("resources", []) or []
    policy_rows = discovery.get("policy_compliance", []) or []
    device_summary = discovery.get("device_summary", {}) or {}

    identity_status = _status_for_names(logs, ("Identity", "Identity basic"))
    if aggregate_identity and aggregate_identity != "success":
        identity_status = aggregate_identity

    mfa_status = _status_for_names(logs, ("MFA",))
    if mfa_status == "unknown" and identity_status == "success":
        # Backward compatibility for contracts whose Identity collector also
        # recorded registration details, but only when every user is classified.
        known_mfa = all(str(row.get("mfa_status", "")).casefold() in {"registered", "not registered"} for row in users)
        if known_mfa:
            mfa_status = "success"
    identity_mfa_status = _combined_status([identity_status, mfa_status])

    role_member_logs = [
        row for row in logs
        if str(row.get("module", "")).casefold().startswith("role members:")
    ]
    directory_roles_status = _status_for_names(logs, ("Directory roles",))
    privileged_statuses = [identity_status, mfa_status, directory_roles_status]
    if role_member_logs:
        privileged_statuses.extend(str(row.get("status", "unknown")).casefold() for row in role_member_logs)
    privileged_mfa_status = _combined_status(privileged_statuses)

    entra_status = _status_for_names(logs, ("Entra devices",))
    intune_status = _status_for_names(logs, ("Intune managed devices",))
    endpoints_status = _combined_status([entra_status, intune_status])

    def item(metric_id: str, label: str, value: object, status: str, modules: list[str], interpretation: str) -> dict:
        available = status == "success"
        return {
            "id": metric_id,
            "label": label,
            "value": value if available else None,
            "display_value": str(value) if available else "Sem evidência",
            "source_status": status,
            "source_modules": modules,
            "interpretation": interpretation,
        }

    mfa_users = sum(1 for row in users if str(row.get("mfa_status", "")).casefold() == "not registered")
    privileged_without_mfa = sum(
        1 for row in users
        if row.get("privileged") and str(row.get("mfa_status", "")).casefold() in {"not registered", "disabled", "false"}
    )
    guests = user_summary.get("Convidados externos") if isinstance(user_summary, dict) else None
    if guests is None:
        guests = sum(1 for row in users if str(row.get("account_type", "")).casefold() == "guest")

    public_resources = sum(
        1 for row in resources
        if str(row.get("exposure", "")).casefold().startswith("public")
    )
    high_risk_rbac = sum(
        1 for row in rbac
        if row.get("access_risk") in {"Crítico", "Alto"}
    )
    policy_non_compliant = sum(int(row.get("non_compliant", 0) or 0) for row in policy_rows)
    endpoint_attention = int(device_summary.get("non_compliant", 0) or 0) + int(device_summary.get("unmanaged", 0) or 0)

    return [
        item("identity_mfa", "Sem MFA", mfa_users, identity_mfa_status, ["Identity", "MFA"], "Contagem observada; depende de usuários e registro MFA completos."),
        item("privileged_mfa", "Privilegiados sem MFA", privileged_without_mfa, privileged_mfa_status, ["Identity", "MFA", "Directory roles", "Role members"], "Contagem observada; depende da resolução completa de membros privilegiados."),
        item("identity_guests", "Convidados externos", guests, identity_status, ["Identity"], "Contagem de contas classificadas como guest na fonte Identity."),
        item("rbac_high_risk", "RBAC alto risco", high_risk_rbac, _status_for_names(logs, ("RBAC",)), ["RBAC"], "Atribuições de alto/crítico observadas; não equivale a uso efetivo."),
        item("azure_public_resources", "Recursos públicos", public_resources, _status_for_names(logs, ("Azure inventory",)), ["Azure inventory"], "Sinais públicos explícitos encontrados no inventário concluído."),
        item("azure_policy_noncompliant", "Policy: soma de não conformidades", policy_non_compliant, _status_for_names(logs, ("Azure Policy",)), ["Azure Policy"], "Soma por linha; pode diferir do total de registros Policy."),
        item("endpoint_attention", "Endpoints em atenção", endpoint_attention, endpoints_status, ["Entra devices", "Intune managed devices"], "Contagem completa exige sucesso das duas fontes de dispositivos."),
    ]
