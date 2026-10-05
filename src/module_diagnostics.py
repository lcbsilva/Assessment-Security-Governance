"""Classifica limitações operacionais sem inferir causa além da evidência."""

from __future__ import annotations


def _diagnostic(category: str, cause: str, next_step: str, confidence: str = "média") -> dict:
    """Retorna diagnóstico acionável sem afirmar causa além da evidência."""
    return {
        "limitation_category": category,
        "diagnostic_code": f"assessment.{category}",
        "diagnostic_confidence": confidence,
        "likely_cause": cause,
        "next_step": next_step,
    }


def diagnose(module: str, status: str, note: str = "") -> dict:
    text = str(note or "").lower()
    if status == "success":
        return _diagnostic("none", "Coleta concluída.", "Nenhuma ação operacional; valide a evidência com o responsável pelo domínio.", "alta")
    if status == "not_run":
        return _diagnostic("out_of_profile", "Módulo fora do perfil ou não configurado para esta execução.", "Selecione um perfil que inclua o módulo ou configure a integração opcional aprovada.", "alta")
    if any(token in text for token in ("timeout", "timed out", "deadline")):
        return _diagnostic("timeout", "A API ou a conexão não respondeu dentro do tempo disponível.", "Reduza a janela/volume, verifique throttling e repita o módulo em uma janela aprovada.", "alta")
    if any(token in text for token in ("429", "too many requests")) or (
        "throttl" in text and not any(token in text for token in ("400", "401", "403"))
    ):
        return _diagnostic("throttling", "O serviço limitou temporariamente a taxa de consultas.", "Aguarde o intervalo indicado pelo serviço e repita; reduza paginação ou paralelismo.", "alta")
    if any(token in text for token in ("401", "unauthorized", "invalidauthenticationtoken", "authentication")):
        return _diagnostic("authentication", "A sessão ou o token não foi aceito pelo serviço.", "Renove a sessão no tenant aprovado e confirme o público/tenant do token.", "alta")
    permission_tokens = ("403", "accessdenied", "insufficient privileges", "permission", "consent", "read.all", "roleassignment", "licenseassignment")
    if any(token in text for token in permission_tokens):
        return _diagnostic("permission_or_role", "A permissão Graph/Azure, o consentimento ou a função do usuário pode não cobrir esta operação.", "Compare o endpoint com a matriz de permissões; peça ao owner para confirmar consentimento e função somente leitura.", "alta" if any(token in text for token in ("403", "accessdenied", "insufficient privileges")) else "média")
    if any(token in text for token in ("not licensed", "license required", "licença necessária", "licença", "licenca", "sku", "entitlement", "defender p2")):
        return _diagnostic("license_or_entitlement", "A API pode depender de licença, SKU ou entitlement do serviço.", "Confirme a licença e a disponibilidade do serviço com o administrador; mantenha o resultado como evidência insuficiente se indisponível.", "média")
    if any(token in text for token in ("not configured", "configure ", "environment variable", "pat read-only", "not provided")):
        return _diagnostic("configuration", "A integração opcional não foi configurada para esta execução.", "Configure somente a integração aprovada ou deixe-a explicitamente como não configurada.", "alta")
    if "400" in text:
        return _diagnostic("bad_request_or_endpoint", "A API rejeitou a solicitação; endpoint, parâmetro ou entitlement podem precisar de validação.", "Revise a versão e os parâmetros do endpoint junto ao responsável da integração; não amplie permissões sem validação.", "média")
    if status == "partial":
        return _diagnostic("partial_collection", "A coleta terminou sem completar todo o escopo solicitado.", "Revise o limite de páginas, duração, throttling e falhas registradas antes de comparar resultados.", "alta")
    if status == "error":
        return _diagnostic("collector_error", "O coletor encerrou com uma falha não classificada.", "Consulte o detalhe técnico local, valide dependências/conectividade e repita antes de concluir.", "baixa")
    if module:
        return _diagnostic("unknown", "A causa não pôde ser determinada a partir do status disponível.", "Consulte o manifesto técnico e confirme a causa com o owner do serviço.", "baixa")
    return _diagnostic("unknown", "Causa não determinada.", "Revise o manifesto técnico local.", "baixa")
