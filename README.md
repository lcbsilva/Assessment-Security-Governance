# Assessment Automatizado de Segurança & Governança

> **Vai testar a ferramenta pela primeira vez?** Comece por [TESTER-START-HERE.md](TESTER-START-HERE.md). O guia reduz o fluxo ao necessário para um teste autorizado e orienta o feedback.

Para conhecer o produto de ponta a ponta, consulte o [Product Tour](docs/PRODUCT-TOUR.md). Para gerar uma demonstração com cenários pequeno, médio, limitado, completo e grande sem acessar nenhum ambiente, execute `./scripts/run-product-tour.sh`.

Versão 1.1.0 do Assessment Engine para avaliações read-only de Segurança, Governança, Identidade e FinOps, com cobertura e limitações de evidência explícitas.

O repositório possui validação contínua em cada push e pull request. O pipeline
executa compilação, testes de contrato, verificação do relatório autocontido e
as proteções do modo somente leitura.

## O que esta versão já faz

- carrega um catálogo versionado de controles;
- calcula score por domínio e score geral;
- calcula cobertura e confiança da avaliação;
- prioriza achados por risco;
- ordena o plano de ação por prioridade combinando risco, esforço e sinal de custo potencial;
- identifica quick wins;
- gera um HTML autocontido, sem CDN e sem dependência de internet;
- mostra evidências, limitações e plano 30/60/90.
- exibe discovery técnico de usuários, MFA, Conditional Access, dispositivos Entra/Intune, recursos, RBAC, Azure Policy e log dos coletores;
- apresenta cada política de Conditional Access em cartões visuais para revisão rápida de estado, escopo, exclusões, controles e cobertura, inspirado no conceito do idPowerApp;
- consolida distribuição de severidade, risco por domínio, itens afetados e plano 30/60/90 com responsável e esforço;
- registra a origem dos achados e o manifesto de evidências dos módulos executados;
- identifica recursos órfãos, custo potencial, idade do inventário e serviços/features em aposentadoria;
- mantém runbooks de correção versionados, sem excluir ou alterar recursos durante o assessment;
- mantém uma única fonte de dados normalizada para futura integração com Graph, ARG, ARI, azqr, Maester e ScubaGear.
- mantém parâmetros de coleta, privacidade, qualidade e guardrails em `config/assessment.yaml`.
- encaminha achados para frentes consultivas (Identity & Access, Security, Cloud Governance, FinOps e Risk/Compliance), facilitando o handoff para os times.
- consulta recomendações ativas do Azure Advisor, custos agregados por recurso, grupos e licenças M365, além de alertas e vulnerabilidades Defender quando disponíveis;
- registra snapshots históricos sem PII e gera comparação automática quando existe uma execução anterior;
- classifica limitações por permissão, licença, throttling, suporte e execução, gerando um score conservador de qualidade da evidência;
- classifica cada recurso Azure com sinais independentes de segurança, governança, exposição pública, owner e tags;
- inventaria Power Apps, Power Automate, ambientes, conectores e owners via `PowerPlatformResources` quando o inventário do tenant estiver disponível;
- gera Azure Resource Intelligence com mapa de recursos/dependências demonstradas, Resource Hygiene, Azure Policy Default/Assigned/Effective, Secure Score com ganho potencial e Advisor enriquecido;

## Executar

O modo de execução é permanentemente **read-only**. A barreira técnica bloqueia
a execução se a configuração permitir escrita ou exclusão. O engine consulta,
normaliza, pontua e gera recomendações; não modifica o tenant.

```bash
cd assessment-engine
python3 src/generate_report.py
```

O relatório será criado em:

```text
dist/assessment-demo.html
```

### Guia rápido para outro consultor ou time

Se você recebeu acesso ao repositório Git, o fluxo recomendado é:

```bash
git clone <URL_DO_REPOSITORIO> assessment-engine
cd assessment-engine
python3 -m pip install -r requirements.txt
az login
az account set --subscription "<subscription-id>"
az account show --query '{tenantId:tenantId,subscriptionId:id}' -o table
```

No PowerShell 7, use `python` no lugar de `python3` quando esse for o comando
disponível. O `tenantId` exibido deve ser confirmado antes de continuar.

Execute primeiro o Readiness Gate:

```bash
python3 src/preflight.py \
  --subscriptions "<subscription-id>" \
  --profile security \
  --output runtime/preflight-security.json
```

O preflight somente verifica o ambiente; ele não concede permissões e não
altera o tenant. Se houver `blocked`, a execução deve parar até o responsável
autorizar ou corrigir o pré-requisito.

Para a primeira coleta, use o perfil de Segurança:

```bash
./scripts/run-focused-pilot.sh "<subscription-id>"
```

Depois de revisar o resultado, o perfil completo pode ser executado somente se
o escopo estiver autorizado:

```bash
./scripts/run-assessment.sh "<subscription-id>" full
```

No PowerShell 7, use:

```powershell
.\scripts\run-focused-pilot.ps1 -Subscriptions "<subscription-id>"
.\scripts\run-consultant-flow.ps1 -ExpectedTenantId "<tenant-id>" -Subscriptions "<subscription-id>" -Profile full
```

Os principais resultados ficam em `dist/` e `runtime/`:

- `dist/assessment.html`: relatório offline autocontido;
- `dist/assessment-executive-summary.pdf`: resumo executivo;
- `dist/assessment-executive-summary.pptx`: apresentação;
- `dist/assessment-action-plan.xlsx`: plano de ação;
- `runtime/assessment.json`: evidência técnica confidencial;
- `runtime/pilot-validation.json`: validação de contrato, integridade e
  guardrails;
- `runtime/ai-payload.json`: agregados protegidos contra PII.

Os estados `not_available` e `partial` são resultados válidos quando uma API
depende de licença, permissão, retenção ou throttling. Eles não devem ser
alterados manualmente nem interpretados como conformidade.

O roteiro completo para uma execução autorizada em outro ambiente está em
[`docs/LAB-HANDOFF-FOR-REVIEWER.md`](docs/LAB-HANDOFF-FOR-REVIEWER.md). Para operação e handoff entre consultores, use também [`docs/OPERATIONAL-HANDOFF.md`](docs/OPERATIONAL-HANDOFF.md). Os
cenários sintéticos para testar a ferramenta sem tenant estão em
[`docs/SIMULATION-RUNBOOK.md`](docs/SIMULATION-RUNBOOK.md).

### Importar relatório Microsoft Zero Trust (opcional)

O JSON ou ZIP exportado pelo assessment Microsoft pode ser importado localmente para comparar evidências e apoiar a revisão. Os estados Microsoft ficam separados e não são convertidos nem combinados com o score deste engine.

```bash
python3 src/import_zt_assessment.py \
  --source "/caminho/ZeroTrustAssessmentReport.zip" \
  --data runtime/assessment.json \
  --output runtime/assessment-combined.json
python3 src/generate_report.py --data runtime/assessment-combined.json --output dist/assessment.html
python3 src/export_artifacts.py --data runtime/assessment-combined.json --output-dir dist
```

Se o contrato local não tiver tenant ID completo ou mascarado para validar a correspondência, confirme manualmente que os relatórios pertencem ao mesmo tenant e acrescente `--confirm-same-tenant`. Os wrappers Bash e PowerShell também aceitam importação automática quando `ASSESSMENT_ZERO_TRUST_REPORT` contém o caminho local do JSON/ZIP. O payload de IA continua sendo criado somente dos dados base deste engine; o conteúdo bruto do ZIP não é enviado à IA. Trate os relatórios e artefatos combinados como confidenciais.

## Testes de integridade

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/*.py
```

Para validar a prontidão da release sem acessar nenhum tenant:

```bash
python3 src/release_gate.py --data mock/assessment.json
```

O `beta_gate.py` permanece apenas como componente de compatibilidade do conjunto de checks; o gate principal da release 1.0 é `release_gate.py`.

Para personalizar o cliente, engagement e classificação dos artefatos, consulte [docs/ENGAGEMENT-CONFIG.md](docs/ENGAGEMENT-CONFIG.md). A configuração é local e não altera o escopo read-only.

O gate compila o código, executa os testes, gera HTML/XLSX/PPTX/PDF, valida os
guardrails de IA e confirma o piloto em diretório temporário.

No Windows, os testes de integridade continuam disponíveis pelos scripts legados de compatibilidade, enquanto a decisão final de release é produzida por `src/release_gate.py`.

Para testar tenants com tamanhos e licenças diferentes sem acessar um ambiente real, use os cenários sintéticos documentados em [`docs/SIMULATION-RUNBOOK.md`](docs/SIMULATION-RUNBOOK.md). Eles são marcados como DEMO e não substituem o piloto em tenant.

No Linux, macOS ou Azure Cloud Shell:

Antes da coleta, o script executa o **Readiness Gate**. Ele exibe checks de Python,
Azure CLI, sessão, acesso Reader à subscription, sessão Graph e guardrail read-only.

- verde (`pass`): pré-requisito validado;
- amarelo (`warning`): execução continua, mas o relatório registra cobertura limitada;
- vermelho (`blocked`): execução para antes dos coletores, sem qualquer alteração no tenant.

O resultado fica em `runtime/preflight.json` e também aparece no HTML final. A estimativa
de duração é indicativa e pode variar com volume, paginação, throttling, retenção e licenças.

Ao final, `runtime/pilot-validation.json` também contém um checklist automático de pré-entrega.
Ele diferencia bloqueios (read-only, contrato, manifesto ou IA), warnings (cobertura e
limitações de módulos) e condições que exigem revisão consultiva antes de compartilhar o
relatório.

O arquivo `runtime/artifact-manifest.json` registra a classificação confidencial, o perfil,
o run ID e o SHA-256 dos artefatos em `dist`, permitindo verificar se HTML, PDF, PPTX ou XLSX
foram alterados depois da geração.

Cada entrada do `collection_log` registra início, fim, duração e tentativa do módulo. Isso
deixa explícito que um assessment longo é uma sequência de janelas de coleta, e não um
snapshot temporal único.

O inventário Azure também normaliza sinais explícitos de postura para Storage, Key Vault e
NSG, incluindo blob público, HTTPS-only, TLS legado, soft delete, purge protection e regras
inbound públicas para SSH/RDP. Propriedade ausente continua sendo evidência insuficiente.

Para compartilhar uma cópia com identificadores protegidos, sem alterar o assessment original:

```bash
./scripts/generate-shareable-report.sh runtime/assessment.json
```

Os artefatos pseudonimizados são gravados em `dist-shareable/`. O salt usado para a
pseudonimização nunca é armazenado no contrato.

Para revisar arquivos locais antigos, a ferramenta começa somente em modo de prévia; a remoção requer `--apply` explícito:

```bash
python3 src/cleanup_local.py
python3 src/cleanup_local.py --include-reports
python3 src/cleanup_local.py --include-reports --apply
```

A retenção padrão é 30 dias (`privacy.local_artifact_retention_days` em `config/assessment.yaml`). Revise a lista antes de acrescentar `--apply`. A rotina cobre apenas `runtime/`, `dist/` e `dist-shareable/`; não roda automaticamente e não promete apagamento físico seguro. Em Windows, proteja as pastas usando ACLs da conta/perfil local; em POSIX, o engine restringe diretórios de saída conhecidos quando aplicável.

Os coletores independentes executam com paralelismo conservador de 2 workers. Para um
ambiente com limites de API mais restritivos, use `ASSESSMENT_MAX_WORKERS=1`; para um
ambiente validado, o máximo suportado pelo engine é 3. O valor usado fica registrado no
manifesto da execução.

### Validação do relatório com Playwright

O E2E valida o artefato local sem acessar o tenant:

```bash
./scripts/run-report-e2e.sh
```

Ele verifica conteúdo executivo, seções críticas, filtro do discovery, painéis
compactáveis, responsividade, impressão e erros JavaScript. Se o ambiente já tiver
Playwright instalado, também é possível executar `npx playwright test` diretamente.

```bash
chmod +x scripts/run-beta-gate.sh
./scripts/run-beta-gate.sh
```

Para comparar uma nova execução com uma anterior:

```bash
python3 src/compare_runs.py \
  --previous runtime/assessment-anterior.json \
  --current runtime/assessment.json \
  --output runtime/run-comparison.json
```

O pipeline valida o contrato antes de produzir o resultado e registra o status
da validação em `metadata.contract_status`.

Os dados atuais são fictícios e identificados como DEMO. Nenhum tenant é acessado nesta etapa.

## Conteúdo do HTML atual

Além do dashboard executivo, o relatório demonstrativo possui tabelas para:

- usuários, tipo de conta, MFA, cobertura de Conditional Access, risco, último sign-in e funções privilegiadas do Entra ID;
- sign-ins recentes classificados como autenticação legada e recomendações individuais do Microsoft Secure Score;
- dispositivos Entra ID/Intune, sistema operacional, gerenciamento, conformidade, última atividade e origem do dado;
- políticas de Conditional Access, estado, escopo, exclusões, controles e cobertura;
- visão visual individual das políticas de Conditional Access para apoiar workshops com segurança, IAM e donos de aplicações;
- inventário de recursos Azure, exposição, owner e tags;
- atribuições RBAC, escopo, PIM e status de revisão;
- compliance de Azure Policy, não conformidades e isenções;
- inventário de Power Platform com resumo agregado e sinais por recurso;
- status, fonte e quantidade de registros de cada coletor.

As linhas são sintéticas para validar o formato. Na execução real, o mesmo contrato será preenchido pelos coletores read-only.

## Primeiro coletor real: Azure Resource Graph

Instale as dependências e autentique usando uma identidade já autorizada no
Azure CLI, Managed Identity ou workload identity:

```bash
python3 -m pip install -r requirements.txt
az login
python3 src/collect_arg.py \
  --subscriptions <subscription-id-1>,<subscription-id-2> \
  --output runtime/assessment-arg.json
```

O coletor consulta somente `Resources`, não executa alterações e grava o
inventário no contrato JSON normalizado. Se faltar SDK, credencial, permissão ou
subscription, ele grava um `collection_log` com status `error` e encerra sem
modificar o tenant. A matriz completa está em
[`docs/PERMISSIONS-MATRIX.md`](docs/PERMISSIONS-MATRIX.md).

## Execução integrada

Depois de instalar as dependências, o runner executa ARG e Microsoft Graph e
consolida a saída:

```bash
python3 src/run_assessment.py \
  --subscriptions <subscription-id-1>,<subscription-id-2> \
  --profile full \
  --output runtime/assessment.json
python3 src/generate_report.py \
  --data runtime/assessment.json \
  --output dist/assessment-real.html
```

O runner não envia dados para IA e não executa remediação. O módulo Graph usa
as permissões descritas na matriz; endpoints indisponíveis são registrados no
`collection_log` para que o relatório não transforme ausência de licença em
falso sinal de conformidade.

Por padrão, os sign-ins percorrem todas as páginas disponíveis dentro da janela
configurada. Em tenants muito grandes, `ASSESSMENT_SIGNIN_MAX_PAGES` permite
limitar conscientemente a duração; nesse caso o coletor registra `partial` e o
relatório informa a limitação.

Auditoria de diretório também usa paginação limitada para evitar que tenants
extensos esgotem o tempo de execução: `ASSESSMENT_AUDIT_MAX_PAGES` é 10 por
padrão e `0` remove o limite conscientemente. Se uma página falhar após páginas
válidas, os registros recebidos são mantidos e o módulo é marcado como
`partial`. No resumo do laboratório, `control_coverage_percent` é cobertura do
catálogo de controles, não percentual de APIs/coletas concluídas; o score é
marcado como provisório quando há módulos indisponíveis ou parciais.

Limites operacionais configuráveis: `ASSESSMENT_GRAPH_REQUEST_TIMEOUT_SECONDS`
(60 s, faixa 5–300), `ASSESSMENT_GRAPH_MAX_RETRIES` (3, faixa 0–5),
`ASSESSMENT_COST_REQUEST_TIMEOUT_SECONDS` (60 s, faixa 5–300),
`ASSESSMENT_COST_MAX_RETRIES` (3, faixa 0–5), `ASSESSMENT_ARG_MAX_ATTEMPTS`
(3, faixa 1–6) e `ASSESSMENT_CHECKPOINT_MAX_AGE_HOURS` (168 h, faixa 1–8760).
Limites fora da faixa são ajustados para o intervalo aceito; valor inválido usa
o padrão seguro.

O script `scripts/run-beta-demo.ps1 -Scenario limited` inclui o PDF de briefing
de uma página, guia de reunião e template de feedback. Os dados da demo são
sintéticos e a geração não autentica nem consulta tenant.

O inventário de Power Platform consulta somente metadados publicados no Azure
Resource Graph. Fórmulas, conteúdo de fluxos, mensagens, dados de negócio e
segredos de conexões não são coletados. Se o inventário não estiver habilitado
ou o escopo não estiver disponível, o manifesto registra `not_available` ou
`partial`. DevOps e Purview permanecem integrações opcionais com autenticação e
permissões próprias, sem ampliar o token Azure por padrão.

Perfis disponíveis: `security` concentra identidade, exposição, sinais de
segurança e postura de domínio M365; `governance` concentra inventário,
hierarquia, RBAC e Policy; `full` executa também custo e integrações opcionais.
Módulos fora do perfil aparecem explicitamente como `not_run` no manifesto.
As decisões de escopo estão documentadas em [`docs/BETA-SCOPE-REVIEW.md`](docs/BETA-SCOPE-REVIEW.md).

### Execução local no tenant do cliente

Não é necessário provisionar uma VM para o MVP. O assessment pode ser executado
em uma estação de trabalho, jump box ou notebook autorizado, desde que a máquina
tenha Azure CLI, Python e conectividade com as APIs Microsoft. A autenticação
fica associada ao tenant escolhido no `az login`; os arquivos são gerados
localmente e nenhum comando de escrita é executado.

No Windows PowerShell:

```powershell
az login
.\scripts\run-consultant-flow.ps1 -ExpectedTenantId "<tenant-id>" -Subscriptions "<subscription-id-1>,<subscription-id-2>"
```

Para o primeiro piloto focado, use o wrapper de Segurança. Ele executa com um
worker, habilita retomada por checkpoint e valida o Release Gate ao final:

```bash
./scripts/run-focused-pilot.sh "<subscription-id-1>"
```

No PowerShell:

```powershell
.\scripts\run-focused-pilot.ps1 -Subscriptions "<subscription-id-1>"
```

No Linux ou macOS:

```bash
az login
chmod +x scripts/run-assessment.sh
./scripts/run-assessment.sh "<subscription-id-1>,<subscription-id-2>"
```

O script gera `dist/assessment.html`, os formatos complementares em `dist/` e
o payload agregado em `runtime/ai-payload.json` e a validação em
`runtime/pilot-validation.json`. O validador bloqueia contrato inválido, modo
diferente de read-only ou possível dado identificável no payload de IA. Para uma primeira execução,
comece com uma subscription de laboratório. Se um endpoint não estiver
disponível por permissão ou licença, o relatório registra `not_available` ou
`partial` e continua a execução. A matriz de conferência do piloto está em
[`docs/PILOT-VALIDATION-MATRIX.md`](docs/PILOT-VALIDATION-MATRIX.md).

## Exportações complementares

Com as bibliotecas opcionais instaladas, o mesmo contrato gera plano de ação em
Excel, resumo executivo em PowerPoint e PDF print-friendly:

```bash
python3 src/export_artifacts.py \
  --data runtime/assessment.json \
  --output-dir dist
```

Para preparar uma entrada segura para futura geração de resumo com Azure OpenAI:

```bash
python3 src/ai_payload.py \
  --data runtime/assessment.json \
  --output runtime/ai-payload.json
```

O payload contém somente métricas agregadas. Os guardrails estão descritos em
[`docs/AI-GUARDRAILS.md`](docs/AI-GUARDRAILS.md).

Cada execução também grava um snapshot mínimo em `runtime/history/`. Esses
snapshots contêm apenas scores, status, cobertura, módulos, escopo numérico e
IDs de controles/achados; o conteúdo detalhado do tenant não é copiado para o
histórico. A partir da segunda execução, `runtime/run-comparison.json` e a
seção “Evolução entre execuções” são gerados automaticamente.

## Referências de implementação

A estratégia para aproveitar projetos open source e manter rastreabilidade está em [`docs/REFERENCE-INTEGRATION.md`](docs/REFERENCE-INTEGRATION.md).

O mapa de encaminhamento consultivo está em [`docs/SOFTWAREONE-OFFERING-MAP.md`](docs/SOFTWAREONE-OFFERING-MAP.md). Ele organiza o próximo time e o tipo de conversa sem transformar o resultado técnico em promessa comercial.

O [CloudMoveAnalyzer](https://github.com/jrlimax/CloudMoveAnalyzer) foi incluído como referência complementar para processamento local, exploração de inventários, filtros, exportações, atualização de bases oficiais e testes de qualidade. Seu mecanismo de suporte à movimentação de recursos não faz parte do scoring de Segurança & Governança.

## Próxima evolução — macro-sprints prioritárias

1. **Core & Reliability** — fechar coleta, Cost Management, RBAC/PIM/Defender/Secure Score, diagnóstico, evidência, cobertura e preparação/validação de laboratório.
2. **Intelligence & Trends** — consolidar histórico, comparação entre execuções, lifecycle/FinOps e tendências; benchmark externo somente com coorte real e metodologia documentada.
3. **Executive Delivery** — alinhar HTML, PDF, PPTX, XLSX e one-page ao mesmo contexto executivo, prioridades, limitações e plano 30/60/90.
4. **AI & Security** — manter IA opt-in, limitada ao payload agregado aprovado e separada de score, compliance, causa raiz e evidência determinística.
5. **Release Candidate** — executar testes, E2E, validação de artefatos, release/delivery gates, documentação e fechamento da versão candidata.

Melhorias cosméticas e funcionalidades secundárias ficam fora deste bloco até a conclusão das cinco macro-sprints.

### Guardrails de lifecycle e FinOps

Recursos órfãos, custo potencial e aposentadorias são sinais de investigação,
não comandos operacionais. O MVP nunca exclui, move, altera tags ou modifica
políticas no tenant. Cada recomendação exige validação de owner, dependências,
criticidade, backup e janela de mudança; quando a fonte não oferece cobertura
suficiente, o relatório marca a limitação explicitamente.
