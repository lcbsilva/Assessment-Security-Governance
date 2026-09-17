# Segurança do projeto

Este repositório contém um engine de discovery para Azure, Entra ID e
Microsoft 365. O princípio técnico é **somente leitura**.

## Regras obrigatórias

- Nunca publicar dados de clientes, identificadores de usuário, domínios,
  tokens, chaves, arquivos `runtime/` ou relatórios reais.
- Usar o repositório como privado para desenvolvimento e revisão interna.
- Conceder apenas as permissões documentadas em
  [`docs/PERMISSIONS-MATRIX.md`](docs/PERMISSIONS-MATRIX.md).
- Não adicionar chamadas de mutação (`PUT`, `PATCH` ou `DELETE`) aos coletores.
  A exceção controlada é o `POST` da API de consulta do Cost Management, que
  envia somente o filtro de leitura no corpo da requisição.
- Recomendações são evidências para decisão; o engine não executa correções.
- O payload destinado à IA deve permanecer agregado e sem PII.

## Reportar vulnerabilidade

Não abra uma issue pública contendo detalhes de segurança ou dados de tenant.
Comunique o responsável pelo repositório pelos canais internos da
SoftwareOne, incluindo impacto, versão, passos para reprodução e uma
proposta de correção sem dados reais.
