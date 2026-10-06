"""Transporte Azure OpenAI opcional para o payload agregado aprovado.

Usa HTTPS direto para manter a dependência pequena. Nenhuma chamada ocorre sem
configuração explícita; o gate de privacidade continua sendo aplicado por ai_advisory.
"""
from __future__ import annotations
import json, os, urllib.request
from urllib.parse import quote, urlsplit


def configured() -> bool:
    return all(os.getenv(k) for k in ("ASSESSMENT_AOAI_ENDPOINT", "ASSESSMENT_AOAI_DEPLOYMENT"))


def _endpoint_url() -> str:
    endpoint = os.environ["ASSESSMENT_AOAI_ENDPOINT"].rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Azure OpenAI endpoint must be a clean HTTPS URL")
    deployment = quote(os.environ["ASSESSMENT_AOAI_DEPLOYMENT"], safe="")
    version = quote(os.getenv("ASSESSMENT_AOAI_API_VERSION", "2024-10-21"), safe="")
    return f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={version}"


def invoke(payload: dict) -> str:
    if not configured():
        raise RuntimeError("Azure OpenAI transport is not configured")
    body = {
        "messages": [
            {"role": "system", "content": "Você é uma camada consultiva. Resuma somente as métricas agregadas recebidas. Não declare incidente, conformidade, causa raiz ou economia garantida."},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
        "temperature": 0.1,
    }
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("ASSESSMENT_AOAI_API_KEY")
    if api_key:
        headers["api-key"] = api_key
    else:
        from azure.identity import DefaultAzureCredential
        token = DefaultAzureCredential(exclude_interactive_browser_credential=True).get_token("https://cognitiveservices.azure.com/.default").token
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(_endpoint_url(), data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    timeout = min(180, max(5, int(os.getenv("ASSESSMENT_AOAI_TIMEOUT_SECONDS", "60"))))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.load(response)
    return str(result["choices"][0]["message"]["content"]).strip()
