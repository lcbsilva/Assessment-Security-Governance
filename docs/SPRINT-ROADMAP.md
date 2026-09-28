# Roadmap de sprints — Assessment Security & Governance

## Beta 71 — matriz de validação e fechamento técnico

- [x] Matriz offline para cenários `small`, `medium`, `limited`, `full` e `large`.
- [x] Cada cenário valida artefatos, manifesto, piloto e status de prontidão.
- [x] CI executa a matriz sem autenticar ou acessar tenant.
- [x] Escala grande permanece controlada para evitar consumo excessivo no CI.
- [ ] Validação humana em tenant autorizado e comparação com Portal/Graph/ARG.

Detalhes em [`SPRINT-DELIVERY-BETA71.md`](SPRINT-DELIVERY-BETA71.md).

## Beta 70 — fechamento para revisão interna

- [x] Navegação do relatório reorganizada em faixas centralizadas e responsivas.
- [x] Cenário sintético `medium` adicionado entre `small` e `large`.
- [x] Wrapper Bash corrigido para respeitar cenário e escala.
- [x] Handoff de execução autorizada preparado para revisão em ambiente com
  licenças ampliadas.
- [x] Suíte de testes, gates e geração de artefatos executados nos cenários
  pequeno, intermediário, limitado, completo e grande.
- [ ] Revisão humana do time e autorização formal do piloto.

## Beta 69 — apresentação e colaboração interna

- [x] Diagnóstico por módulo com causa provável e próximo passo.
- [x] Limites configuráveis para timeout/tentativas e retomada segura de checkpoints.
- [x] Briefing executivo de uma página com score provisório e saúde da coleta.
- [x] Guia de demonstração e template para feedback estruturado do time.
- [x] Testes de regressão, validação do pacote e gates técnicos.
- [ ] Revisão humana do time e eventual autorização formal para um piloto controlado.

Detalhes em [`SPRINT-DELIVERY-BETA69.md`](SPRINT-DELIVERY-BETA69.md). A revisão interna e aprovação de piloto não são inferidas pelos gates técnicos.

## Beta 64–67 — confiança, privacidade e contexto

- [x] Beta 64 — proteger arquivos locais, documentar retenção e fornecer limpeza manual com prévia.
- [x] Beta 65 — ligar cada controle/achado a fonte, estado e janela de coleta; remover associação inadequada de Azure Policy aos controles Purview.
- [x] Beta 66 — confiança por evidência do controle, alcance com unidade e estimativa relativa de esforço/impacto potencial.
- [x] Beta 67 — publicar contexto de perfil, escopo, duração e limitações nos relatórios e manifesto.
- [ ] Executar suíte completa, Release Gate e renderização de HTML/PDF/PPTX/XLSX em ambiente limpo.
- [ ] Revisar ACLs no Windows e permissões POSIX no Cloud Shell com operadores do laboratório.

O código e a documentação das quatro sprints foram concluídos. Os gates automatizados e a revisão nos shells do laboratório ainda precisam ser executados antes de declarar a entrega validada para piloto.

## Beta 63 — experiência observável de execução

- [x] Exibir etapas claras nos wrappers Linux/Cloud Shell e PowerShell 7.
- [x] Medir e mostrar tempo decorrido durante o fluxo.
- [x] Mostrar estado, duração e gravação do checkpoint por coletor.
- [x] Identificar coletores retomados e reutilizados após interrupção.
- [x] Mostrar importação Microsoft como etapa local opcional e scores separados.
- [x] Atualizar runbook e Release Gate.
- [ ] Validar a experiência em Cloud Shell e Windows PowerShell 7 no laboratório.

O aceite visual e operacional deve ser feito nos dois shells suportados; a inspeção local de sintaxe não substitui essa validação.

## Beta 61 — quatro sprints priorizadas

- [x] Sprint 1 — endurecer o limite read-only, restringir o POST de Cost
  Management ao endpoint de consulta e acrescentar inspeção AST no gate.
- [x] Sprint 2 — recalcular score/cobertura em cada cenário sintético, alinhar
  escopo aos registros produzidos e remover evidência herdada dos módulos
  simulados como indisponíveis.
- [x] Sprint 3 — mostrar `N/D` quando não houver controles avaliados e ampliar
  a detecção de identificadores/segredos no payload agregado para IA.
- [x] Sprint 4 — documentar execução no Cloud Shell, tratamento confidencial
  dos artefatos, critérios de aceite e o handoff do piloto interno.
- [ ] Reconciliação manual de amostras reais com Portal/Graph/ARG e revisão por
  outro consultor: execução operacional a ser feita pela equipe no laboratório.

Os itens de código e documentação desta entrega estão concluídos. O item de
reconciliação exige revisão humana dos dados do laboratório e não é inferido pelo
Release Gate local.

## Sprint atual — Qualidade e segurança do discovery

- [x] Barreira técnica permanente read-only.
- [x] PIM elegível versus ativo/permanente.
- [x] Usuários, convidados e inatividade com tratamento de dado desconhecido.
- [x] Enterprise Applications e App Registrations.
- [x] Defender e endpoints como módulos opcionais.
- [x] Priorização por risco, esforço e custo potencial.
- [x] Validar comportamento com cenários sintéticos pequeno, limitado e completo.
- [x] Validar release gate técnico, artefatos e guardrails read-only.
- [ ] Validar consentimento de permissões em tenant de laboratório.

## Próxima sprint — Piloto controlado

- [x] Integrar recomendações ativas do Azure Advisor (categoria, impacto, recurso e economia quando publicada).
- [x] Exibir recomendações Advisor no HTML com fonte e status.
- [x] Ampliar RBAC com classificação de nível, escopo e herança não presumida.
- [x] Detalhar alertas e vulnerabilidades Defender quando disponíveis.
- [x] Criar matriz de priorização com risco, impacto, esforço e sinal financeiro.
- [x] Registrar histórico mínimo e comparar execuções automaticamente.
- [x] Expandir discovery para grupos, licenças M365 e custos por recurso.
- [x] Classificar qualidade da evidência por permissão, licença, throttling, suporte e execução.
- [x] Exibir score de qualidade e causa da limitação no dashboard e manifesto técnico.
- [x] Validar regressão automatizada com 22 testes e pacote sem caches.

- Validar execução com uma subscription de laboratório e um tenant M365 de teste.
- Comparar amostras do relatório com Portal, Graph Explorer e Azure Resource Graph.
- Registrar cobertura por módulo, tempo de coleta, erros e limitações.
- Ajustar regras de falso positivo antes de apresentar a clientes.

## Sprint seguinte — Produto para consultoria

- Histórico de execuções e comparação de tendência.
- Benchmark anônimo por vertical somente com consentimento e dados agregados.
- Branding configurável por oferta, sem alterar o núcleo técnico.
- Exportação de evidências para workshop e plano de ação.
- Pipeline CI com testes, lint, validação do contrato e verificação de read-only.

## Critério de aceite

O assessment só pode ser considerado pronto para piloto quando todos os módulos
indisponíveis continuarem em `not_available`/`partial`, nenhum coletor usar método
de escrita no tenant e cada recomendação tiver evidência, limitação e owner.

## Estado do fechamento Beta 1.0

O gate técnico local está concluído quando `scripts/run-release-gate.sh` retorna
`beta_release_ready`. O piloto em tenant real continua sendo uma etapa operacional
obrigatória e não é substituído por dados sintéticos.

## Sprint beta.2 — Hardening de execução

- [x] Checkpoints por coletor gravados atomicamente.
- [x] Escopo de checkpoint vinculado a subscriptions e perfil.
- [x] Checkpoints com erro ou indisponibilidade total são refeitos no resume.
- [x] Duração e tentativa de cada coletor registradas no contrato.
- [x] Evidência de falha preservada sem transformar ausência em conformidade.
- [x] Regressão automatizada e Release Gate executados após a mudança.

## Sprint beta.3 — Integridade do contrato

- [x] Estados de evidência contraditórios são rejeitados pelo contrato.
- [x] `CONFORMANT` exige controle `pass`.
- [x] `NON_CONFORMANT` exige controle `partial` ou `fail`.
- [x] `INSUFFICIENT_EVIDENCE` exige `not_available` ou `error`.
- [x] Fixtures legadas continuam compatíveis quando não declaram estado formal.

## Sprint beta.4 — Score defensável e cobertura por domínio

- [x] Cobertura ponderada por domínio calculada a partir dos controles avaliados.
- [x] Domínios sem evidência são apresentados como insuficientes, não como conformes.
- [x] Dashboard informa cobertura geral e regra metodológica do score.
- [x] Metodologia do score registrada no contrato para auditoria e comparação.
- [x] Testes, artefatos e Release Gate executados após a mudança.

## Sprint beta.5 — Comparação histórica honesta

- [x] Controles avaliados nas duas execuções identificados explicitamente.
- [x] Variação média calculada somente no conjunto comparável.
- [x] Mudança de cobertura sinalizada como limitação da tendência.
- [x] Dashboard histórico informa quantidade de controles comparáveis.
- [x] Regressão, artefatos e Release Gate executados após a mudança.

## Sprint beta.6 — Escala sintética

- [x] Cenário `large` determinístico e totalmente offline.
- [x] Volume sintético de usuários, recursos, dispositivos, apps, RBAC e Policy.
- [x] Modos de falha 403/429 simulados sem inventar conformidade.
- [x] Parâmetro `--scale` para stress progressivo.
- [x] Renderer validado com 20 mil usuários e 25 mil recursos.

## Sprint beta.7 — Auditoria pré-entrega

- [x] Auditor automático de qualidade do contrato.
- [x] Detecção de achado sem evidência ou limitação.
- [x] Detecção de estados de evidência contraditórios.
- [x] Detecção de módulos indisponíveis e domínios com baixa cobertura.
- [x] Integração na validação de piloto sem alterar o tenant.

## Sprint beta.8 — Revisão objetiva de escopo

- [x] Núcleo de Segurança e Governança separado das integrações opcionais.
- [x] Perfis focados deixam de chamar DevOps, analytics e custo sem necessidade.
- [x] Decisão de manter, tornar opcional ou adiar cada capacidade documentada.
- [x] Riscos de PII, relatório grande, licença e estimativa financeira registrados.
- [x] Release Gate e testes executados após a revisão.

## Sprint beta.9 — Piloto focado de Segurança

- [x] Wrapper Linux/Cloud Shell para execução do perfil `security`.
- [x] Wrapper PowerShell equivalente.
- [x] Paralelismo conservador de um worker no piloto inicial.
- [x] Retomada por checkpoint habilitada por padrão.
- [x] Release Gate executado ao final do piloto local.

## Sprint beta.10 — Correção de compatibilidade Cloud Shell

- [x] Corrigido preflight incompatível com `az resource list --top`.
- [x] Readiness agora consulta somente o primeiro ID via `--query "[0].id"`.
- [x] Mantida leitura mínima e comportamento read-only.
- [x] Regressão automatizada adicionada para evitar retorno do erro.

## Sprint beta.11 — Gate reproduzível em pacote limpo

- [x] Testes de artefatos não dependem mais de arquivos antigos em `dist/`.
- [x] Fixtures de HTML, PDF, PPTX e XLSX são geradas temporariamente durante os testes.
- [x] Wrapper Linux e PowerShell exibem automaticamente o check bloqueado.
- [x] Release Gate validado em checkout sem artefatos pré-gerados.

## Sprint beta.12 — Correção de cobertura por evidência

- [x] Score não conta `INSUFFICIENT_EVIDENCE` como controle avaliado.
- [x] Cobertura por domínio e cobertura geral usam o estado formal da evidência.
- [x] Teste de regressão para status numérico sem evidência.
- [x] Evita relatório com cobertura artificialmente em 100%.

## Sprint beta.13 — Evidência de autorização do piloto

- [x] Manifesto local de aprovação separado da execução e dos segredos.
- [x] Consentimento confirmado, perfil e subscriptions validados antes do piloto.
- [x] Escopos incompatíveis com read-only bloqueados.
- [x] Gate não consulta, autentica, concede permissões ou altera o tenant.
