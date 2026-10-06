"""Classifica limitações operacionais sem inferir causa além da evidência."""

from __future__ import annotations


def diagnose(module: str, status: str, note: str = "") -> dict:
    text = str(note or "").lower()
    if status == "success":
        return {"limitation_category": "none", "likely_cause": "Coleta concluída.", "next_step": "Nenhuma ação operacional; valide a evidência com o responsável pelo domínio."}
    if status == "not_run":
        return {"limitation_category": "out_of_profile", "likely_cause": "Módulo fora do perfil ou não configurado para esta execução.", "next_step": "Selecione um perfil que inclua o módulo ou configure a integração opcional aprovada."}
    if any(token in text for token in ("timeout", "timed out", "deadline")):
        return {"limitation_category": "timeout", "likely_cause": "A API ou a conexão não respondeu dentro do tempo disponível.", "next_step": "Reduza a janela/volume, verifique throttling e repita o módulo em uma janela aprovada."}
    if any(token in text for token in ("429", "throttl", "too many requests")):
        return {"limitation_category": "throttling", "likely_cause": "O serviço limitou temporariamente a taxa de consultas.", "next_step": "Aguarde o intervalo indicado pelo serviço e repita; reduza paginação ou paralelismo."}
    if any(token in text for token in ("401", "unauthorized", "invalidauthenticationtoken", "authentication")):
        return {"limitation_category": "authentication", "likely_cause": "A sessão ou o token não foi aceito pelo serviço.", "next_step": "Renove a sessão no tenant aprovado e confirme o público/tenant do token."}
    # HTTP 400 é ambíguo: notas de diagnóstico frequentemente dizem para
    # "validar entitlement/licença" sem comprovar que essa é a causa. Só trate
    # licenciamento como causa quando a própria evidência declarar ausência ou
    # requisito explícito de licença/SKU/entitlement.
    explicit_license = (
        "license required", "licence required", "license unavailable", "licence unavailable",
        "not licensed", "unlicensed", "licença necessária", "licenca necessaria",
        "licença indisponível", "licenca indisponivel", "sku required", "sku unavailable",
        "entitlement required", "entitlement unavailable", "missing entitlement",
    )
    if any(token in text for token in explicit_license):
        return {"limitation_category": "license_or_entitlement", "likely_cause": "A evidência indica requisito ou indisponibilidade de licença, SKU ou entitlement.", "next_step": "Confirme a licença e a disponibilidade do serviço com o administrador; mantenha o resultado como evidência insuficiente se indisponível."}
    # Um HTTP 400 explícito prevalece sobre linguagem consultiva na nota
    # ("validate ... permissions"). Isso evita transformar hipótese de correção
    # em evidência de falta de permissão.
    if "400" in text:
        return {"limitation_category": "bad_request_or_endpoint", "likely_cause": "A API rejeitou a solicitação; endpoint, parâmetro, permissão ou entitlement podem precisar de validação.", "next_step": "Revise a versão e os parâmetros do endpoint junto ao responsável da integração; não amplie permissões sem validação."}
    if any(token in text for token in ("403", "accessdenied", "insufficient privileges", "permission", "consent")):
        return {"limitation_category": "permission_or_role", "likely_cause": "A permissão Graph/Azure ou a função do usuário pode não cobrir esta operação.", "next_step": "Compare o endpoint com a matriz de permissões; peça ao owner para confirmar consentimento e função somente leitura."}
    if any(token in text for token in ("not configured", "configure ", "environment variable", "pat read-only", "not provided")):
        return {"limitation_category": "configuration", "likely_cause": "A integração opcional não foi configurada para esta execução.", "next_step": "Configure somente a integração aprovada ou deixe-a explicitamente como não configurada."}
    if status == "partial":
        return {"limitation_category": "partial_collection", "likely_cause": "A coleta terminou sem completar todo o escopo solicitado.", "next_step": "Revise o limite de páginas, duração, throttling e falhas registradas antes de comparar resultados."}
    if status == "error":
        return {"limitation_category": "collector_error", "likely_cause": "O coletor encerrou com uma falha não classificada.", "next_step": "Consulte o detalhe técnico local, valide dependências/conectividade e repita antes de concluir."}
    if module:
        return {"limitation_category": "unknown", "likely_cause": "A causa não pôde ser determinada a partir do status disponível.", "next_step": "Consulte o manifesto técnico e confirme a causa com o owner do serviço."}
    return {"limitation_category": "unknown", "likely_cause": "Causa não determinada.", "next_step": "Revise o manifesto técnico local."}
