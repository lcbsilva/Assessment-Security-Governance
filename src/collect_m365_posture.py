#!/usr/bin/env python3
"""Coleta postura pública de domínio M365 sem ler mensagens ou conteúdo."""

from __future__ import annotations

import os
import shlex
import subprocess
from datetime import datetime, timezone

from version import engine_version


def capability_manifest() -> list[dict]:
    """Expõe cobertura M365 sem fingir que APIs específicas foram executadas."""
    return [
        {"module": "Exchange Online / forwarding externo", "status": "not_configured", "required_integration": "Exchange Online PowerShell ou Security & Compliance audit read-only", "note": "Não lê conteúdo de mensagens."},
        {"module": "SharePoint / OneDrive compartilhamento externo", "status": "not_configured", "required_integration": "SharePoint Online admin read-only", "note": "Links anônimos e compartilhamento exigem endpoint administrativo específico."},
        {"module": "Teams colaboração externa e reuniões", "status": "not_configured", "required_integration": "Microsoft Graph Teams admin read-only", "note": "Políticas de reunião e federação não são inferidas pelo inventário de usuários."},
        {"module": "Unified Audit Log", "status": "not_configured", "required_integration": "Purview/Exchange audit read-only", "note": "Ausência de eventos não é tratada como auditoria habilitada."},
        {"module": "Power Platform DLP", "status": "not_configured", "required_integration": "Power Platform admin API read-only", "note": "DLP por ambiente exige integração própria; Resource Graph não é suficiente."},\n        {"module": "Purview DLP policies", "status": "not_configured", "required_integration": "Purview read-only integration", "controls": ["CMP-001"], "note": "Sem adaptador Purview executado, o controle permanece com evidência insuficiente."},\n        {"module": "Purview sensitivity labels", "status": "not_configured", "required_integration": "Purview read-only integration", "controls": ["CMP-002"], "note": "Inventário de recursos Purview não comprova publicação ou governança de rótulos."},\n        {"module": "Purview retention policies", "status": "not_configured", "required_integration": "Purview read-only integration", "controls": ["CMP-003"], "note": "Sem consulta administrativa de retenção, ausência de dados não representa ausência de políticas."},
    ]


def compliance_collection_log() -> list[dict]:
    """Declara explicitamente lacunas de Compliance sem fabricar evidência."""
    return [
        {
            "module": "Purview DLP policies",
            "source": "Microsoft Purview",
            "status": "not_available",
            "records": 0,
            "note": "Integration not configured; Purview read-only adapter not provided. Control CMP-001 remains insufficient evidence.",
        },
        {
            "module": "Purview sensitivity labels",
            "source": "Microsoft Purview",
            "status": "not_available",
            "records": 0,
            "note": "Integration not configured; Purview read-only adapter not provided. Control CMP-002 remains insufficient evidence.",
        },
        {
            "module": "Purview retention policies",
            "source": "Microsoft Purview",
            "status": "not_available",
            "records": 0,
            "note": "Integration not configured; Purview read-only adapter not provided. Control CMP-003 remains insufficient evidence.",
        },
    ]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def query_txt(name: str) -> list[str] | None:
    """Consulta TXT usando ferramenta local; retorna None quando DNS não está disponível."""
    commands = [["dig", "+short", "TXT", name], ["nslookup", "-type=TXT", name]]
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            values = []
            for line in result.stdout.splitlines():
                line = line.strip().strip('"')
                if line and "can't find" not in line.lower() and "server:" not in line.lower() and "address:" not in line.lower():
                    values.append(line.replace('" "', ""))
            return values
    return None


def analyze_domain(domain: str, dns_lookup=query_txt) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not domain or any(character.isspace() for character in domain):
        return {"domain": domain or "—", "status": "invalid", "dns_available": False, "spf": "not_checked", "dmarc": "not_checked", "dkim_selector1": "not_checked", "dkim_selector2": "not_checked", "signals": "Domínio inválido"}
    queries = {
        "spf": domain,
        "dmarc": f"_dmarc.{domain}",
        "dkim_selector1": f"selector1._domainkey.{domain}",
        "dkim_selector2": f"selector2._domainkey.{domain}",
    }
    records = {key: dns_lookup(name) for key, name in queries.items()}
    if all(value is None for value in records.values()):
        return {"domain": domain, "status": "not_available", "dns_available": False, **{key: "not_checked" for key in queries}, "signals": "DNS não disponível no executor"}
    results = {key: ("present" if values and (key != "spf" or any("v=spf1" in value.lower() for value in values)) else "not_present") for key, values in records.items()}
    missing = [key.upper() for key, value in results.items() if value == "not_present"]
    return {"domain": domain, "status": "partial" if missing else "success", "dns_available": True, **results, "signals": "Ausente: " + ", ".join(missing) if missing else "SPF, DMARC e DKIM detectados"}


def collect(domains: list[str] | None = None, dns_lookup=query_txt) -> dict:
    """Analisa domínios informados por ambiente; não executa alterações."""
    started = utc_now()
    configured = domains or [item.strip() for item in os.getenv("ASSESSMENT_M365_DOMAINS", "").split(",") if item.strip()]
    if not configured:
        return {"metadata": {"engine_version": engine_version(), "collected_at": started, "modules": {"m365": "not_available"}}, "discovery": {"m365_domain_posture": [], "m365_capability_manifest": capability_manifest(), "m365_summary": {"domains": 0, "spf_present": 0, "dmarc_present": 0, "dkim_selector1_present": 0, "dkim_selector2_present": 0}, "collection_log": compliance_collection_log() + [{"module": "M365 domain posture", "source": "DNS TXT read-only", "status": "not_available", "records": 0, "note": "Informe ASSESSMENT_M365_DOMAINS para analisar domínios aprovados; nenhuma mensagem ou caixa é acessada."}]}}
    rows = [analyze_domain(domain, dns_lookup) for domain in configured]
    summary = {"domains": len(rows), **{f"{key}_present": sum(1 for row in rows if row.get(key) == "present") for key in ("spf", "dmarc", "dkim_selector1", "dkim_selector2")}}
    status = "success" if all(row["status"] == "success" for row in rows) else "partial" if any(row["status"] == "success" for row in rows) else "not_available"
    return {"metadata": {"engine_version": engine_version(), "collected_at": started, "scope": {"m365_domains_assessed": len(rows)}, "modules": {"m365": status}}, "discovery": {"m365_domain_posture": rows, "m365_capability_manifest": capability_manifest(), "m365_summary": summary, "collection_log": compliance_collection_log() + [{"module": "M365 domain posture", "source": "DNS TXT read-only", "status": status, "records": len(rows), "note": "SPF, DMARC e DKIM são sinais de postura de domínio; não representam configuração completa de Exchange Online."}]}}
