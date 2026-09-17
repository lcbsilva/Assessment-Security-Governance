#!/usr/bin/env python3
"""Coleta metadados de Azure DevOps usando somente requisições GET.

Configuração opcional por ambiente:
  AZDO_ORG_URL=https://dev.azure.com/organizacao
  AZDO_PAT=<PAT somente leitura>
  AZDO_PROJECT=<nome ou id opcional>

O PAT nunca é escrito no contrato, nos erros ou no payload da IA. O coletor
não acessa arquivos, commits, work items, logs de pipeline, variáveis ou
segredos de service connections.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from version import engine_version


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_api_error(error: Exception) -> str:
    status = getattr(error, "code", None)
    if status:
        return f"HTTP {status}; verifique AZDO_PAT read-only e escopo da organização."
    return f"{type(error).__name__}: {error}"


def get_json(url: str, pat: str, opener=urlopen) -> dict:
    token = base64.b64encode(f":{pat}".encode("utf-8")).decode("ascii")
    request = Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json"}, method="GET")
    with opener(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def api_url(org_url: str, path: str, **params: str) -> str:
    base = org_url.rstrip("/") + "/" + path.lstrip("/")
    return base + "?" + urlencode(params)


def project_row(item: dict) -> dict:
    return {
        "id": item.get("id") or "—",
        "name": item.get("name") or "—",
        "state": item.get("state") or "—",
        "visibility": item.get("visibility") or "private",
        "revision": item.get("revision") or "—",
        "url": item.get("url") or "—",
    }


def repository_row(item: dict, project: str) -> dict:
    visibility = str(item.get("project", {}).get("visibility") or item.get("visibility") or "private")
    signals = ["Repositório público" ] if visibility.lower() == "public" else []
    return {
        "id": item.get("id") or "—",
        "name": item.get("name") or "—",
        "project": project,
        "default_branch": item.get("defaultBranch") or "—",
        "visibility": visibility,
        "size": item.get("size") or 0,
        "web_url": item.get("webUrl") or "—",
        "governance_signal": "Crítico" if signals else "Sem sinal público",
        "posture_signals": "; ".join(signals) or "Nenhum sinal básico",
    }


def pipeline_row(item: dict, project: str) -> dict:
    return {
        "id": item.get("id") or "—",
        "name": item.get("name") or "—",
        "project": project,
        "revision": item.get("revision") or "—",
        "queue_status": item.get("queueStatus") or "—",
        "type": item.get("type") or "—",
        "url": item.get("url") or "—",
    }


def collect(org_url: str | None = None, pat: str | None = None, project: str | None = None, opener=urlopen) -> dict:
    """Retorna contrato parcial e fail gracefully quando DevOps não está configurado."""
    org_url = (org_url or os.getenv("AZDO_ORG_URL", "")).strip()
    pat = pat or os.getenv("AZDO_PAT", "")
    project = project or os.getenv("AZDO_PROJECT", "")
    started = utc_now()
    empty = {"projects": [], "repositories": [], "pipelines": [], "branch_policies": []}
    if not org_url or not pat:
        return {
            "metadata": {"engine_version": engine_version(), "collected_at": started, "modules": {"azure_devops": "not_available"}},
            "discovery": {"azure_devops": empty, "azure_devops_summary": summarize(empty), "collection_log": [{
                "module": "Azure DevOps", "source": "Azure DevOps REST API", "status": "not_available", "records": 0,
                "note": "Configure AZDO_ORG_URL e AZDO_PAT read-only; credencial não é solicitada por argumento.",
            }]},
        }
    try:
        projects_payload = get_json(api_url(org_url, "_apis/projects", **{"api-version": "7.1", "$top": "1000"}), pat, opener)
        projects = [project_row(item) for item in projects_payload.get("value", [])]
        selected = [item for item in projects if not project or item["id"] == project or item["name"].lower() == project.lower()]
        repositories: list[dict] = []
        pipelines: list[dict] = []
        policies: list[dict] = []
        partial_errors: list[str] = []
        for item in selected:
            project_id = quote(item["id"], safe="")
            project_name = item["name"]
            try:
                repo_payload = get_json(api_url(org_url, f"{project_id}/_apis/git/repositories", **{"api-version": "7.1", "$top": "1000"}), pat, opener)
                repositories.extend(repository_row(repo, project_name) for repo in repo_payload.get("value", []))
                for repo in repo_payload.get("value", []):
                    try:
                        policy_payload = get_json(api_url(org_url, "_apis/policy/configurations", repositoryId=repo.get("id", ""), project=project_id, **{"api-version": "7.1"}), pat, opener)
                        policies.extend({"project": project_name, "repository": repo.get("name") or "—", "enabled": item.get("isEnabled", True), "count": len(policy_payload.get("value", []))} for _ in [0])
                    except Exception as error:
                        partial_errors.append(safe_api_error(error))
            except Exception as error:
                partial_errors.append(safe_api_error(error))
            try:
                pipeline_payload = get_json(api_url(org_url, f"{project_id}/_apis/build/definitions", **{"api-version": "7.1", "$top": "1000"}), pat, opener)
                pipelines.extend(pipeline_row(build, project_name) for build in pipeline_payload.get("value", []))
            except Exception as error:
                partial_errors.append(safe_api_error(error))
        data = {"projects": selected, "repositories": repositories, "pipelines": pipelines, "branch_policies": policies}
        status = "partial" if partial_errors else "success"
        note = "Metadados read-only; não foram lidos código, commits, logs, work items ou segredos."
        if partial_errors:
            note += " Subconsultas indisponíveis: " + "; ".join(sorted(set(partial_errors)))
        return {
            "metadata": {"engine_version": engine_version(), "collected_at": started, "scope": {"devops_projects": len(selected), "devops_repositories": len(repositories), "devops_pipelines": len(pipelines)}, "modules": {"azure_devops": status}},
            "discovery": {"azure_devops": data, "azure_devops_summary": summarize(data), "collection_log": [{"module": "Azure DevOps", "source": "Azure DevOps REST API", "status": status, "records": len(selected) + len(repositories) + len(pipelines), "note": note}]},
        }
    except (HTTPError, URLError, TimeoutError, ValueError) as error:
        return {
            "metadata": {"engine_version": engine_version(), "collected_at": started, "modules": {"azure_devops": "not_available"}},
            "discovery": {"azure_devops": empty, "azure_devops_summary": summarize(empty), "collection_log": [{"module": "Azure DevOps", "source": "Azure DevOps REST API", "status": "not_available", "records": 0, "note": safe_api_error(error)}]},
        }


def summarize(data: dict) -> dict:
    repositories = data.get("repositories", [])
    public = sum(1 for item in repositories if str(item.get("visibility", "")).lower() == "public")
    return {"projects": len(data.get("projects", [])), "repositories": len(repositories), "pipelines": len(data.get("pipelines", [])), "public_repositories": public, "repositories_without_branch_policy_evidence": sum(1 for item in data.get("branch_policies", []) if not int(item.get("count", 0) or 0))}


def main() -> None:
    parser = argparse.ArgumentParser(description="Coleta Azure DevOps read-only")
    parser.add_argument("--output", default="runtime/assessment-devops.json")
    options = parser.parse_args()
    output = Path(options.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(collect(), ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Azure DevOps gravado em {output}")


if __name__ == "__main__":
    main()
