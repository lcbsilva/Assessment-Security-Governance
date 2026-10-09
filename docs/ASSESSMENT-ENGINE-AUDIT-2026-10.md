# Auditoria inicial e backlog — Assessment Engine

Data da auditoria: 2026-10-09  
Base revisada: branch `main`, repositório `lcbsilva/Assessment-Security-Governance`.

## Escopo verificado

- Estrutura e fontes de coletores, orquestração, estado de execução e gates.
- Testes unitários, fluxo E2E do relatório e pipeline de CI.
- Documentação de uso, roadmap, permissões e guardrails declarados.
- Nenhum tenant foi acessado; nenhuma permissão foi alterada.

## Achados priorizados

### P0 — autenticação Graph

**Achado:** `src/collect_graph.py:get_all` tratava um HTTP 401 como falha isolada de endpoint. A execução continuava tentando todos os endpoints e ainda tentava a consulta alternativa de usuários. Com token inválido, isso repetia chamadas que não poderiam funcionar, alongava a execução e gerava logs redundantes.

**Correção proposta neste PR:** interromper novas chamadas após o primeiro HTTP 401, registrar cada endpoint não consultado como `not_available`, manter resultados já coletados e não executar fallback básico depois da falha de autenticação.

**Aceite:** teste com 401 no primeiro endpoint comprova uma única chamada HTTP e logs explícitos para as consultas seguintes. Um 403 continua isolado por endpoint, pois pode refletir permissões específicas.

### P1 — estados por módulo

A metadata do coletor Graph declara apenas estados agregados de identidade e Secure Score. Outras áreas dependem de `collection_log` por endpoint, e consumidores que olham somente `metadata.modules` não conseguem distinguir cobertura de Conditional Access, Intune, PIM, aplicações, auditoria e Defender.

**Aceite futuro:** cada área expõe estado agregado derivado dos logs; sucesso parcial, falha de autenticação, falta de permissão, limite de páginas e ausência de registros permanecem estados distintos e não viram conformidade.

### P1 — validação Graph em tenant de laboratório

CI e cenários sintéticos verificam comportamento offline, mas não validam consentimento, licenciamento, respostas atuais do Graph nem divergências com o portal.

**Aceite operacional:** executar em tenant de laboratório autorizado, registrar endpoint/escopo/contagem/estado e reconciliar amostras com Graph Explorer ou portal. Não conceder permissões automaticamente.

### P1 — rastreabilidade entre artefatos

A pipeline valida a geração e integridade de HTML/PDF/PPTX/XLSX, mas validação de conteúdo equivalente entre formatos é uma etapa distinta da existência dos arquivos.

**Aceite futuro:** valores-chave, cobertura, estados de evidência e limitações correspondem entre todos os formatos para os mesmos fixtures; discrepâncias interrompem o gate.

### P2 — experiência consultiva e catálogo de fontes

O repositório já inclui dashboards, cenários sintéticos, análise cruzada e exports. Expansão de fontes (Purview, Fabric e Power Platform) deve começar com disponibilidade, permissões mínimas, qualidade do dado e cobertura explícita antes de gerar novos indicadores.

**Aceite futuro:** todo insight possui evidência rastreável, escopo, janela, confiança, impacto, prioridade, recomendação acionável e status de disponibilidade da fonte.

## Backlog resumido

| Prioridade | Entrega | Critério objetivo |
|---|---|---|
| P0 | Circuit breaker para HTTP 401 no Graph | 401 inicial gera uma chamada HTTP, status por consulta e mantém o restante do assessment executável |
| P0 | Diagnóstico de autenticação Graph consistente entre preflight e coletor | Testes distinguem token ausente, 401, 403 e falhas transitórias sem expor tokens |
| P1 | Estado agregado por área Graph | Cada área tem `success`, `partial`, `not_available`, `error` ou `not_run` derivado de evidências |
| P1 | Cobertura defensável de Graph, Azure e M365 | Não há conclusão positiva com fonte indisponível ou evidência insuficiente |
| P1 | Reconciliação em laboratório autorizado | Amostras do relatório conferidas no serviço de origem, com limitações registradas |
| P1 | Consistência semântica dos exports | Métricas essenciais equivalentes entre HTML/PDF/PPTX/XLSX/JSON em fixtures |
| P2 | Priorização cruzada e recomendações | Cada recomendação vinculada a evidência, impacto, prioridade e horizonte 30/60/90 |
| P2 | Avaliação de novas fontes | Power Platform, Purview, Fabric e Azure DevOps têm decisão documentada sobre valor, acesso e limitações |

## Limitações desta auditoria

A auditoria estática foi feita pela API do GitHub; o ambiente de execução não conseguiu clonar o repositório para executar a suíte localmente. Os gates existentes serão usados no PR. Nenhuma execução real de Graph/Azure é inferida a partir de testes sintéticos.
