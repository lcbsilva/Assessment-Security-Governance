# Assessment Automatizado de Segurança & Governança

MVP inicial para validar o formato do assessment antes da conexão com um tenant real.

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

## Testes de integridade

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/*.py
```

Para validar a prontidão da versão beta sem acessar nenhum tenant:

```bash
python3 src/beta_gate.py --data mock/assessment.json
```

O gate compila o código, executa os testes, gera HTML/XLSX/PPTX/PDF, valida os
guardrails de IA e confirma o piloto em diretório temporário.

No Windows, o mesmo processo pode ser executado pelo PowerShell:

```powershell
.\scripts\run-beta-gate.ps1
```

No Linux, macOS ou Azure Cloud Shell:

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

O inventário de Power Platform consulta somente metadados publicados no Azure
Resource Graph. Fórmulas, conteúdo de fluxos, mensagens, dados de negócio e
segredos de conexões não são coletados. Se o inventário não estiver habilitado
ou o escopo não estiver disponível, o manifesto registra `not_available` ou
`partial`. DevOps e Purview permanecem integrações opcionais com autenticação e
permissões próprias, sem ampliar o token Azure por padrão.

Perfis disponíveis: `security` concentra identidade, exposição e sinais de
segurança; `governance` concentra inventário, hierarquia, RBAC e Policy; `full`
executa todos os módulos, incluindo custo. Módulos fora do perfil aparecem
explicitamente como `not_available` no manifesto.

### Execução local no tenant do cliente

Não é necessário provisionar uma VM para o MVP. O assessment pode ser executado
em uma estação de trabalho, jump box ou notebook autorizado, desde que a máquina
tenha Azure CLI, Python e conectividade com as APIs Microsoft. A autenticação
fica associada ao tenant escolhido no `az login`; os arquivos são gerados
localmente e nenhum comando de escrita é executado.

No Windows PowerShell:

```powershell
az login
.\scripts\run-assessment.ps1 -Subscriptions "<subscription-id-1>,<subscription-id-2>"
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

## Próxima evolução

1. enriquecer retirement com Advisor, Service Health e Azure EOL;
2. ampliar RBAC, PIM, Defender, Secure Score e Cost Management;
3. validar os resultados no tenant de laboratório;
4. adicionar tendências entre execuções e benchmark anonimizado;
5. conectar a camada Azure OpenAI ao payload agregado, após revisão de segurança;
6. evoluir os templates executivos de PDF, PPTX e XLSX.

### Guardrails de lifecycle e FinOps

Recursos órfãos, custo potencial e aposentadorias são sinais de investigação,
não comandos operacionais. O MVP nunca exclui, move, altera tags ou modifica
políticas no tenant. Cada recomendação exige validação de owner, dependências,
criticidade, backup e janela de mudança; quando a fonte não oferece cobertura
suficiente, o relatório marca a limitação explicitamente.
