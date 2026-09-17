# Estratégia de integração das referências

## Objetivo

Usar projetos maduros como aceleradores de coleta, regras e experiência visual, mantendo um modelo de dados e um renderer próprios da SoftwareOne.

## Referências selecionadas

| Referência | Uso no engine | Decisão |
|---|---|---|
| [ARI](https://github.com/microsoft/ARI) | Inventário detalhado, recursos, redes e visualização Azure | Usar como referência/adapter de inventário |
| [Azure Quick Review](https://github.com/Azure/azqr) | Recomendações, recursos impactados, Policy, Defender, Advisor e custo | Prioridade para o módulo Azure |
| [CCOInsights](https://github.com/Azure/CCOInsights) | Organização de dashboards, filtros e páginas executivas | Usar como referência de UX |
| [Maester](https://github.com/maester365/maester) | Testes de segurança Microsoft 365 e relatórios | Prioridade para Graph/Entra/M365 |
| [ScubaGear](https://github.com/cisagov/ScubaGear) | Baselines declarativas, exceções e rastreabilidade | Usar o conceito de baseline-as-code |
| [Prowler](https://github.com/prowler-cloud/prowler) | Mapeamento de frameworks e checks adicionais | Avaliar para fase futura |
| [CloudMoveAnalyzer](https://github.com/jrlimax/CloudMoveAnalyzer) | Exploração local de inventário, filtros, exportações, i18n e hardening | Usar como referência de UX, privacidade e qualidade |
| [Azure Orphaned Resources](https://github.com/dolevshor/azure-orphan-resources) | Workbook baseado em ARG para recursos sem associação e custo potencial | Usar as consultas como referência; nunca habilitar exclusão automática |
| [Azure EOL](https://github.com/Azure/EOL) | Catálogo de serviços/features em fim de vida | Usar como fonte complementar de lifecycle |
| [Service Retirement Workbook](https://github.com/microsoft/Application-Insights-Workbooks/tree/master/Workbooks/Azure%20Advisor/AzureServiceRetirement) | Aposentadorias, prazos, recursos impactados e ações | Correlacionar Advisor, Service Health e ARG |

## Regra de integração

O engine não deve depender de Excel ou de uma página Power BI como fonte primária. Cada coletor deve entregar JSON normalizado para o contrato interno:

- `metadata`: tenant mascarado, escopo, timestamps, versão, permissões e limitações;
- `identities`: usuários, grupos, convidados, MFA, risco e último sign-in;
- `policies`: Conditional Access, Azure Policy e assignments;
- `resources`: inventário, tags, exposição, owner e criticidade;
- `rbac`: principal, função, escopo, herança, PIM e revisão;
- `findings`: evidência, severidade, confiança, referência e correção;
- `collection_log`: fonte, status, quantidade, erro e observação.

## O que será incorporado

### Azure Quick Review

- estágio modular (`inventory`, `advisor`, `defender`, `policy`, `cost`);
- recursos impactados por recomendação;
- saída JSON/CSV além do HTML;
- filtros de escopo por YAML;
- distinção entre fora de escopo, não disponível e não conforme.

### CCOInsights

- navegação por domínio;
- visão resumida com drill-down;
- páginas específicas para RBAC, rede, recursos ociosos, Advisor e Defender;
- filtros por subscription, resource group, região, tipo e tag.

### Maester e ScubaGear

- controles reproduzíveis e versionados;
- testes automatizados com evidência;
- exceções documentadas e aceites de risco;
- exportação HTML/JSON/CSV;
- repetibilidade entre execuções e comparação de tendências.

### CloudMoveAnalyzer

O CloudMoveAnalyzer é um analisador client-side de exportações Azure voltado a verificar se recursos podem ser movidos entre subscriptions, resource groups e regiões. Ele não é um coletor de segurança, mas traz padrões diretamente úteis para o nosso relatório:

- processamento local para reduzir risco de exfiltração;
- busca, filtros, ordenação e seleção de colunas em inventários grandes;
- exportação para CSV e PDF;
- base de conhecimento versionada e atualizada a partir da documentação oficial;
- validação de entrada, sanitização de conteúdo, CSP e assets locais;
- testes automatizados e atualização controlada da base de regras;
- suporte a múltiplos idiomas sem depender de CDN em runtime.

No nosso engine, esses padrões serão aplicados como:

1. uma tabela explorável de recursos, usuários, políticas e atribuições;
2. exportação dos detalhes técnicos para CSV/JSON, mantendo o HTML como relatório principal;
3. catálogo de controles e recomendações com fonte, versão e data de revisão;
4. validação de arquivos e dados antes do processamento;
5. testes de integridade para garantir que cada achado tenha evidência e origem.

Não vamos usar a base de regras de movimentação do CloudMoveAnalyzer para concluir riscos de segurança. A separação de domínios é necessária para evitar falsos positivos.

### Recursos órfãos e ciclo de vida

Os sinais de recursos órfãos seguem a abordagem de correlação via Azure Resource
Graph: o engine procura recursos sem associação esperada, cruza o inventário com
metadados de custo quando disponíveis e apresenta o resultado como hipótese para
validação. Exemplos incluem discos, IPs públicos, NICs, planos de App Service e
outros componentes que podem permanecer sem workload dependente. O resultado não
autoriza exclusão; a ação recomendada é confirmar owner, dependências, backup,
criticidade e janela de mudança antes de anexar, mover, reutilizar ou retirar o
recurso.

Para aposentadorias, o engine correlaciona Azure Advisor, Service Health, Azure
EOL e inventário ARG. O achado deve informar serviço/feature, data prevista,
recursos impactados, fonte e qualidade da cobertura. A ausência de recursos
impactados não é interpretada como ausência de risco, pois a disponibilidade do
detalhamento depende do serviço e dos metadados publicados pela Microsoft.

Referências usadas nesta versão: [Azure Orphaned Resources](https://github.com/dolevshor/azure-orphan-resources), [Azure EOL](https://github.com/Azure/EOL), [Service Retirement Workbook](https://github.com/microsoft/Application-Insights-Workbooks/tree/master/Workbooks/Azure%20Advisor/AzureServiceRetirement) e [documentação do workbook de aposentadoria](https://github.com/MicrosoftDocs/azure-monitor-docs/blob/main/articles/advisor/advisor-workbook-service-retirement.md).

## Limites e governança

- somente permissões read-only;
- nenhum dado de usuário ou recurso enviado para IA;
- IDs, UPNs e nomes podem ser mascarados na versão executiva;
- licenças ausentes geram `not_available`, não falha da execução;
- toda informação deve indicar fonte, horário e nível de confiança;
- dependências de terceiros devem ser fixadas por versão e avaliadas quanto à licença;
- o relatório não é certificação, auditoria legal ou garantia absoluta de segurança.

## Ordem de implementação

1. Contrato JSON normalizado e catálogo de controles.
2. HTML técnico com discovery detalhado.
3. Coletor Azure Resource Graph e Policy Insights.
4. Coletor Microsoft Graph para identidades, Conditional Access, funções privilegiadas, sign-ins legados e Secure Score.
   A apresentação visual por política no HTML reaproveita o conceito do
   [idPowerToys/idPowerApp](https://idpowertoys.merill.net/) sem depender do
   aplicativo externo.
5. Regras de achados e referências CIS/NIST/Zero Trust.
6. Execução real em tenant de laboratório.
7. IA, PDF, PPTX, XLSX e tendências.
