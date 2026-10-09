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

### P0 — estado da evidência nos relatórios (amostras da Julia)

**Evidência revisada:** HTML, briefing, PDF executivo, PPTX e XLSX da execução de 2026-10-08. A execução informa erro do Graph e cobertura de 28%. PDF/PPTX exibem contagens de identidade como zero; o HTML mostra zero nos cartões de MFA, embora os scores por domínio indiquem “Sem evidência”. A economia realizável aparece como `None` no PDF/PPTX e célula vazia no Excel. O relatório indica 325 não conformidades no cartão/KPI e 345 registros Azure Policy no achado; a nota do HTML admite métodos diferentes, mas os rótulos atuais não deixam o cálculo suficientemente claro. A planilha contém controles Secure Score repetidos por nome, subscription e métricas; sem a dimensão/origem no relatório, é necessário confirmar se são registros distintos ou repetidos antes de agregá-los.

**Risco:** o cliente pode interpretar uma falha de coleta como ausência de usuários sem MFA ou como valor financeiro igual a zero. Números iguais a zero só são defensáveis após consulta bem-sucedida e sem registros. O XLSX foi inspecionado diretamente; ele contém a cobertura detalhada e confirma que Identity/MFA/CA/Intune estavam como `not_checked`, apesar de as métricas executivas correspondentes aparecerem como zero.

**Correção neste PR:** o modelo marca contagens vazias como indisponíveis quando a fonte não teve sucesso; PDF/PPTX/XLSX exibem `N/D · fonte indisponível`, estado da fonte e evitam o literal `None`. A lógica atual do HTML já guarda os cartões pelo estado do Graph; será incluído teste de regressão para impedir que futuros relatórios reproduzam os zeros do arquivo gerado pela Julia. Testes sintéticos validam falha Graph e coleta bem-sucedida sem registros nos exports.

**Aceite:** falha ou fonte desconhecida nunca vira zero; sucesso confirmado sem registros pode virar zero; HTML/PDF/PPTX/XLSX/JSON mantêm semântica compatível; diferenças de agregação (325 × 345) declaram método e unidade; recomendações repetidas expõem chave/dimensão ou são deduplicadas com regra verificável.

### P0 — normalização resiliente e estado real dos endpoints Graph

**Achados estáticos adicionais:** respostas Graph podem conter campos opcionais explicitamente nulos. A normalização de exclusões de Conditional Access somava esses valores como listas, e métodos MFA/tipos de grupo eram unidos diretamente. Um nulo nesses pontos poderia repetir o padrão da falha da Julia: exceção depois das chamadas e descarte do conjunto coletado.

Também havia um indicador agregado baseado em contagem de registros: `identity` dependia de `users` não vazio e `security` de `secure_scores` não vazio. Isso confundia consulta bem-sucedida sem linhas com indisponibilidade e não refletia os resultados dos demais endpoints.

**Correção proposta no PR de refinamento:** campos opcionais nulos são normalizados como coleções vazias sem inventar evidência; os estados de Identity e Security são derivados dos logs dos respectivos endpoints. Um teste sintético chama o coletor Graph completo e cobre usuários, políticas, grupos e métodos MFA com campos nulos; testes adicionais garantem que sucesso vazio permaneça sucesso e estados mistos resultem em parcial.

**Aceite:** respostas sintéticas vazias com HTTP 200 produzem estado `success`; sucesso misturado com endpoint indisponível produz `partial`; falha total continua `error`/ `not_available` conforme os logs; nenhum dado de tenant é necessário para o teste.

### P1 — estados por módulo

A metadata do coletor Graph declara apenas estados agregados de identidade e Secure Score. Outras áreas dependem de `collection_log` por endpoint, e consumidores que olham somente `metadata.modules` não conseguem distinguir cobertura de Conditional Access, Intune, PIM, aplicações, auditoria e Defender.

**Aceite futuro:** cada área expõe estado agregado derivado dos logs; sucesso parcial, falha de autenticação, falta de permissão, limite de páginas e ausência de registros permanecem estados distintos e não viram conformidade.

### P1 — validação Graph em tenant de laboratório

CI e cenários sintéticos verificam comportamento offline, mas não validam consentimento, licenciamento, respostas atuais do Graph nem divergências com o portal.

**Achado adicional confirmado na amostra da Julia:** o readiness check confirmou apenas a emissão de token pela sessão Azure CLI; não comprovou chamadas Graph nem consentimentos efetivos. O log do relatório registra `AttributeError: 'NoneType' object has no attribute 'lower'`. O caminho de normalização de usuários chamava `.lower()` diretamente em `userType`; quando a resposta traz `null`, a exceção ocorre depois das consultas e pode descartar o resultado completo do coletor, inclusive evidências de endpoints que responderam. A correção neste incremento normaliza `null` como `Unknown` e adiciona regressão para `user_posture`. Isso explica a falha observada nessa execução; não prova que todos os endpoints estavam autorizados. Após nova coleta, revisar os estados e HTTP 401/403 de cada endpoint para separar permissão, licença, retenção e disponibilidade.

**Aceite operacional:** executar em tenant de laboratório autorizado, registrar endpoint/escopo/contagem/estado e reconciliar amostras com Graph Explorer ou portal. Não conceder permissões automaticamente. Token emitido pelo CLI é apenas prontidão de sessão, nunca evidência de autorização por endpoint.

### P0 — pacote de entrega omitia formatos executivos

**Achado:** o builder permitia apenas `assessment.pdf`, `assessment.pptx` e `assessment.xlsx`, enquanto o exportador e as amostras da Julia usam `assessment-executive-summary.pdf`, `assessment-executive-summary.pptx` e `assessment-action-plan.xlsx`. Como a rotina aceitava qualquer arquivo disponível, o gate podia aprovar uma pasta de entrega sem PDF executivo, PowerPoint ou planilha.

**Correção proposta neste PR:** alinhar a allowlist aos cinco nomes realmente exportados e bloquear o pacote se qualquer um estiver ausente; testes verificam os cinco formatos e o bloqueio por pacote incompleto.

**Aceite:** pacote autorizado contém HTML, PDF executivo, PPTX, XLSX e briefing de uma página; manifesto lista os nomes e hashes; runtime bruto permanece excluído.

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
| P0 | Semântica de evidência em todos os exports | Fonte indisponível não vira zero/None; sucesso vazio continua zero em fixture |\n| P1 | Consistência semântica dos exports | Métricas essenciais equivalentes entre HTML/PDF/PPTX/XLSX/JSON em fixtures |
| P2 | Priorização cruzada e recomendações | Cada recomendação vinculada a evidência, impacto, prioridade e horizonte 30/60/90 |
| P2 | Avaliação de novas fontes | Power Platform, Purview, Fabric e Azure DevOps têm decisão documentada sobre valor, acesso e limitações |

## Limitações desta auditoria

A auditoria estática foi feita pela API do GitHub; o ambiente de execução não conseguiu clonar o repositório para executar a suíte localmente. Os gates existentes serão usados no PR. Nenhuma execução real de Graph/Azure é inferida a partir de testes sintéticos.
