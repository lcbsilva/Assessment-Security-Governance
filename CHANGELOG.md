# Changelog

## 0.2.0-beta.70

- Reorganiza a navegação do HTML em faixas centralizadas e consistentes,
  incluindo comportamento responsivo sem rolagem lateral dos controles.
- Adiciona cenário sintético `medium` para validar porte intermediário entre
  `small` e `large`.
- Corrige o wrapper Bash para respeitar cenário e escala informados.
- Inclui handoff para revisão autorizada por outro consultor, com preflight,
  consentimento, validação de fontes e tratamento confidencial dos artefatos.
- Mantém read-only, ausência de PII no payload de IA e ausência de remediação.

## 0.2.0-beta.69

- Classifica limitações por módulo com causa provável e próximo passo; linguagem não declara causa confirmada sem evidência.
- Torna configuráveis timeout/tentativas Graph e Cost, tentativas ARG e validade do checkpoint; checkpoints parciais, indisponíveis ou com erro são refeitos.
- Cria briefing executivo PDF de uma página com score provisório, cobertura de controles, saúde das coletas, riscos e limitações; valida que o PDF possui exatamente uma página.
- Acrescenta kit de demonstração e template de feedback do time; pacotes sintéticos os incluem sem autenticar ou consultar tenant.
- Mantém os artefatos e metadados locais confidenciais e a execução tenant somente leitura.

## 0.2.0-beta.68

- Usa permissões Graph de menor privilégio para consulta de licenças M365 e instâncias PIM; mantém permissões separadas para definições e associação de funções.
- Limita por padrão a paginação de auditoria de diretório para reduzir timeouts em tenants extensos; `ASSESSMENT_AUDIT_MAX_PAGES=0` remove o limite explicitamente.
- Preserva registros já coletados quando uma página posterior falha e registra o módulo como `partial`.
- O resumo de laboratório explicita que a cobertura é cobertura de controles, marca scores como provisórios quando há módulos incompletos e lista módulos/estados sem expor notas potencialmente sensíveis.
- Sem alterações no tenant; execução permanece somente leitura.

## 0.2.0-beta.64 a beta.67

- Beta 64: restringe permissões POSIX de diretórios locais de saída, ignora `dist-shareable/` no Git e oferece prévia/remoção manual de arquivos antigos de runtime e relatórios.
- Beta 65: associa controles e achados a fontes, estados, janelas de coleta e limitações do módulo; Compliance Purview sem integração nativa não herda evidência de Azure Policy.
- Beta 66: confiança passa a refletir evidência por controle; relatórios mostram unidade do alcance afetado, impacto potencial em usuários e esforço relativo, sem inferir incidente ou custo real.
- Beta 67: inclui escopo, perfil, Run ID, janela, duração, classificação e limitações no HTML e nos artefatos executivos; o manifesto registra contagens de escopo e limitações.
- Artefatos locais continuam confidenciais; remoção não é automática e não representa apagamento físico seguro.
- Nenhuma mudança no tenant, remediação ou chamada de IA foi adicionada.

## 0.2.0-beta.63

- Exibe as etapas do runner e o status/duração de cada coletor em linhas compatíveis com Bash, PowerShell 7 e logs do Cloud Shell.
- Informa quais coletores foram retomados dos checkpoints e quais foram executados novamente.
- Mostra duração geral e progresso de Readiness, coleta, importação opcional, artefatos, validação e fechamento.
- Preserva retomada local vinculada ao perfil e às subscriptions; nenhuma operação adicional no tenant.

## 0.2.0-beta.62

- Adiciona três controles de Compliance para DLP, rótulos de sensibilidade e retenção; sem evidência Purview suficiente, ficam como insuficientes.
- Importa localmente JSON/ZIP do Microsoft Zero Trust com minimização de campos e correspondência explícita de tenant.
- Exibe estados, pilares e mapeamentos Microsoft em seção separada; os scores nunca são combinados.
- Acrescenta a visão Microsoft aos artefatos XLSX, PPTX e PDF e agrupa a navegação técnica.
- Permite importação opcional nos wrappers Bash/PowerShell sem incluir o relatório externo no payload de IA.
- Escapa texto importado com aparência de fórmula ao gravar a aba Microsoft no XLSX.
- Corrige a cobertura para considerar o catálogo completo e marcar controles sem resultado como evidência insuficiente.
- Mantém execução tenant read-only; o importador processa arquivos locais sem chamadas Microsoft.

## 0.2.0-beta.61

- Endurece o limite read-only: POST de Cost Management só passa para a consulta HTTPS aprovada; o gate inspeciona chamadas urllib por AST.
- Corrige cenários sintéticos para recalcular score, cobertura, achados e resumos sem reaproveitar evidência de módulos indisponíveis.
- Exibe score `N/D` quando não há controles avaliados, em vez de sugerir postura zero.
- Amplia a inspeção do payload de IA para chaves camelCase, emails, UUIDs, IPs e caminhos de recursos Azure.
- Fecha documentação das quatro sprints, do runbook Cloud Shell e dos critérios de revisão consultiva.
- Não adiciona chamadas de escrita nem chamadas a modelos de IA; a coleta no tenant permanece read-only.

## 0.2.0-beta.60

- Declara `pypdf` como dependência do conjunto de testes para que o Release Gate funcione em ambientes limpos, incluindo Cloud Shell.
- Mantém o caminho de execução e as chamadas ao tenant inalterados.

## 0.2.0-beta.57

- Adiciona Pilot Evidence Gate para cruzar preflight, assessment, validação e aprovação local.
- Exige consentimento administrativo confirmado, perfil e subscriptions dentro do escopo aprovado.
- Rejeita escopos de escrita e campos sensíveis no manifesto de aprovação.
- Não consulta, autentica, concede permissões ou altera o tenant.

## 0.2.0-beta.59

- Sinaliza domínios sem controles implementados como `Não configurado`, sem tratá-los como conformidade.
- Reforça fail-fast no wrapper PowerShell do pacote demo.
- Corrige o job E2E do CI para instalar Python e as dependências do renderer.
- Reforça o runbook de compartilhamento pseudonimizado e preserva o relatório técnico como confidencial.
- Faz o fluxo shareable interromper imediatamente quando pseudonimização, exportação ou validação falhar.
- Corrige o parâmetro PowerShell do fluxo shareable, evitando conflito com a variável automática `$Input`.

## 0.2.0-beta.56

- Publica a metodologia de score, cobertura, evidência e priorização.
- Adiciona banner de limitações na primeira camada do relatório executivo.
- Diferencia módulos indisponíveis, fora do perfil e controles sem evidência suficiente.
- Aplica limite padrão de 20 páginas para sign-ins, com liberação explícita via `ASSESSMENT_SIGNIN_MAX_PAGES=0`.
- Mantém o relatório técnico detalhado como confidencial e reforça pseudonimização explícita para compartilhamento.
- Inclui a metodologia no Release Gate da Beta.

## 0.2.0-beta.55

- Endurece a evidência de Azure Policy com classificação explícita por estado.
- Diferencia conformidade, não conformidade, isenção e evidência insuficiente.
- Remove estados `Unknown` do denominador de conformidade para evitar falso negativo.
- Exibe cobertura da evidência, observações insuficientes e classificação no relatório técnico.
- Adiciona regressão automatizada para garantir que ausência de evidência não seja tratada como falha.

## 0.2.0-beta.54

- Reorganiza o HTML em modos de leitura Executivo, Técnico e Completo.
- Adiciona navegação compacta por módulos e reduz a sobrecarga da leitura executiva.
- Adiciona matriz visual de risco × esforço com quick wins, iniciativas estratégicas e backlog.
- Preserva o discovery detalhado em painéis técnicos recolhíveis e com filtro/exportação.
- Atualiza a apresentação para uma identidade SoftwareOne-inspired com grafite, azul e magenta.
- Mantém o HTML autocontido, offline, responsivo e read-only.

## 0.2.0-beta.53

- Adiciona diagnóstico operacional (`doctor`) para Cloud Shell e execução local.
- Valida tenant selecionado, subscription, sessão Graph, espaço, caminho de saída e read-only.
- Adiciona wrappers Bash e PowerShell e documentação no runbook do piloto.
- Mantém permissões opcionais como limitações dos coletores, sem bloquear indevidamente a Beta.

## 0.2.0-beta.52

- Fecha a Beta demonstrável com gerador offline de pacote completo.
- Gera HTML, PDF, PPTX, XLSX, contrato normalizado, payload agregado, validações e manifesto SHA-256.
- Adiciona wrappers Bash/PowerShell para apresentação sem tenant completo.
- Inclui `demo-summary.json` com score, cobertura, integridade, limitações e aviso explícito de dados sintéticos.
- Adiciona regressão automatizada para validar o pacote demonstrável ponta a ponta.

## 0.2.0-beta.51

- Adiciona varredura de release para detectar chamadas explícitas de mutação no caminho de execução.
- Verifica coletores e wrappers contra operações de criação, alteração, exclusão e chamadas Graph de escrita.
- Integra o resultado ao Release Gate e adiciona regressão automatizada do guardrail read-only.

## 0.2.0-beta.50

- Evolui o resumo de validação de laboratório com `overall_status` e `readiness` por perfil.
- Diferencia automaticamente `pass`, `warning`, `blocked` e `not_run`.
- Propaga cobertura, score, módulos não executados, indisponíveis, parciais, warnings e erros.
- Bloqueia o resumo quando o manifesto de integridade está inválido.
- Adiciona regressões para cenários de aviso, perfil ausente e artefato inválido.

## 0.2.0-beta.49

- Unifica o resumo do piloto de laboratório em módulo Python compartilhado.
- Bash/Cloud Shell e PowerShell passam a gerar o mesmo contrato `summary.json`.
- Mantém perfis ausentes explícitos como `not_run`.
- Adiciona regressão de consistência cross-platform.

## 0.2.0-beta.48

- Adiciona piloto automatizado de laboratório para os perfis `security`, `governance` e `full`.
- Gera artefatos separados por perfil e resumo consolidado da validação.
- Executa Readiness Gate, validação de artefatos, hashes e piloto em cada perfil.
- Mantém todas as chamadas read-only e explicita limitações por licença/permissão.
- Adiciona runbook operacional e regressões dos wrappers.

## 0.2.0-beta.47

- Documenta configuração de engagement para execução consultiva.
- Inclui metadados locais no Release Gate obrigatório.
- Documenta campos permitidos, guardrails e exclusão do payload de IA.
- Adiciona referência da configuração ao README.

## 0.2.0-beta.46

- Aplica metadados de engagement ao PPTX executivo.
- Aplica metadados de engagement ao PDF executive summary.
- Mantém cliente, consultor, nome e classificação consistentes entre HTML, PDF e PPTX.
- Adiciona regressão de branding nos artefatos executivos.

## 0.2.0-beta.45

- Adiciona configuração local opcional de engagement.
- Permite nome do cliente, engagement, consultor e classificação sem editar código.
- Mantém escopo, permissões, coletores e guardrails inalterados.
- Metadados de branding não entram no payload agregado de IA.
- Adiciona template e regressão para filtragem segura da configuração.

## 0.2.0-beta.44

- Inclui insights cruzados no PPTX executivo.
- Inclui insights cruzados no PDF executive summary.
- Mantém HTML, XLSX, PDF e PPTX alinhados na narrativa de Segurança e Governança.
- Atualiza regressão de estrutura do deck.

## 0.2.0-beta.43

- Integra insights cruzados à matriz 30/60/90 do HTML.
- Inclui insights como linhas rastreáveis no XLSX de plano de ação.
- Define validação, execução aprovada e reavaliação como sequência segura.
- Adiciona regressão para garantir que insights não fiquem fora dos artefatos de entrega.

## 0.2.0-beta.42

- Adiciona prioridade, responsável sugerido e esforço aos insights cruzados.
- Exibe esses campos no relatório técnico e executivo.
- Inclui os agregados no payload seguro de IA.
- Responsáveis são papéis consultivos, nunca pessoas identificadas.
- Adiciona regressão para priorização e roteamento dos insights.

## 0.2.0-beta.41

- Adiciona insights executivos para recursos sem owner demonstrado.
- Adiciona insights para não conformidades observadas em Azure Policy.
- A severidade considera proporção observada, sem declarar incidente ou culpa.
- As ações recomendam validação de escopo, exceções e owner antes de qualquer mudança.
- Adiciona regressões para a correlação de Governança.

## 0.2.0-beta.40

- Enriquece o tenant sintético grande com governança de owner, tags e Azure Policy.
- O stress test passa a exercitar a visão completa de Segurança, RBAC e Governança.
- Mantém métricas determinísticas e explicitamente sintéticas.
- Adiciona regressão para consistência do resumo de governança entre execuções.

## 0.2.0-beta.39

- Adiciona resumo de governança de recursos com owner, tags e Azure Policy.
- Exibe lacunas de responsabilização e taxa de conformidade observada.
- Inclui o agregado no payload seguro de IA.
- Mantém interpretação conservadora: ausência de tag ou Policy não prova risco isoladamente.
- Adiciona regressões para governança e privacidade do payload.

## 0.2.0-beta.38

- Adiciona verificação de determinismo ao Beta Gate.
- Compara duas execuções sintéticas grandes completas para detectar deriva inesperada.
- Reforça a estabilidade de scoring, postura e contrato entre reexecuções.
- Mantém a validação offline e sem acesso ao tenant.

## 0.2.0-beta.37

- Enriquece o tenant sintético grande com sinais de Storage e RBAC.
- O stress test passa a exercitar posture summary, blast radius e insights executivos.
- Mantém dados determinísticos, offline e marcados como sintéticos.
- Adiciona regressões para garantir que o cenário grande contenha sinais de segurança e governança.

## 0.2.0-beta.36

- Inclui governança RBAC agregada no payload seguro para IA.
- A camada executiva passa a receber blast radius, escopos e atribuições críticas.
- Não envia IDs, nomes pessoais ou evidência de uso efetivo para a IA.
- Adiciona teste de privacidade e estrutura do agregado RBAC.

## 0.2.0-beta.35

- Adiciona resumo agregado de RBAC por escopo, risco e função.
- Exibe blast radius administrativo na camada técnica sem expor IDs adicionais.
- Diferencia atribuições permanentes/desconhecidas e documenta a limitação de herança.
- Adiciona regressão para garantir que escopo declarado não seja tratado como herança efetiva.

## 0.2.0-beta.34

- Amplia sinais explícitos de segurança para Cosmos DB, Redis e bancos gerenciados.
- Detecta Container Registry com usuário administrador habilitado.
- Detecta Application Gateway com WAF explicitamente desabilitado.
- Mantém a regra de não inferir risco quando a propriedade não é retornada.
- Adiciona regressões para os novos serviços Azure.

## 0.2.0-beta.33

- Inclui manifesto SHA-256 e validação de integridade no stress test de tenant grande.
- O cenário sintético agora cobre coleta simulada, scoring, renderização, exportação, IA e cadeia de hashes.
- Mantém a execução offline e não representativa de evidência de cliente.

## 0.2.0-beta.32

- Expande o stress test para o pipeline completo de entrega.
- Valida HTML, PDF, PPTX, XLSX, payload agregado de IA e validação de artefatos em tenant sintético grande.
- Evita declarar escala suportada apenas porque o HTML foi renderizado.
- Mantém todos os dados sintéticos offline e explicitamente não representativos de cliente.

## 0.2.0-beta.31

- Adiciona stress test sintético de aproximadamente 10 mil usuários e 12,5 mil recursos.
- Inclui renderização de tenant grande no Beta Gate para detectar regressões de escala.
- Mantém o cenário determinístico, offline e explicitamente não representativo de cliente.
- Adiciona verificação de tamanho mínimo do HTML gerado no cenário de stress.

## 0.2.0-beta.30

- Integra a validação de hashes ao checklist de pré-entrega.
- Registra a integridade dos artefatos no `pilot-validation.json`.
- Falha de hash bloqueia a revisão; execução manual sem essa etapa fica explicitamente como não verificada.
- Atualiza a ordem dos wrappers para validar o manifesto antes da decisão final do piloto.

## 0.2.0-beta.29

- Adiciona validação automática dos hashes do manifesto.
- Detecta artefatos ausentes, caminhos inválidos e alterações após a geração.
- Integra a validação aos wrappers Bash e PowerShell, inclusive no modo shareable.
- Mantém a verificação totalmente local e read-only.
- Adiciona regressão para adulteração de artefato.

## 0.2.0-beta.28

- Evolui o manifesto de integridade para a versão 1.1.
- Registra SHA-256 do assessment normalizado e do payload agregado de IA.
- Mantém hashes dos artefatos HTML, PDF, PPTX e XLSX.
- Atualiza wrappers Bash e PowerShell para registrar os dados de entrada.
- Adiciona teste de rastreabilidade dos arquivos de entrada.

## 0.2.0-beta.27

- Inclui postura de segurança Azure agregada no payload seguro para IA.
- Inclui cobertura e qualidade da evidência para contextualizar recomendações.
- Mantém somente sinais agregados, sem nomes, IDs, UPNs ou `resource_id`.
- Adiciona teste de privacidade e estrutura do novo payload.

## 0.2.0-beta.26

- Converte sinais explícitos de postura Azure em insight executivo rastreável.
- Exibe quantidade afetada, principais sinais, severidade e ação de validação.
- Mantém o insight como prioridade de investigação, sem declarar incidente ou conformidade.
- Adiciona regressão para garantir que postura técnica chegue à camada de decisão.

## 0.2.0-beta.25

- Adiciona resumo agregado de postura de segurança dos recursos Azure.
- Exibe quantidade de recursos com sinais explícitos e tabela de sinais na visão executiva.
- Mantém a proveniência no nível do recurso para investigação técnica.
- Reforça a regra de que ausência de propriedade retornada não representa conformidade.
- Adiciona teste de agregação e proteção contra falso positivo de conformidade.

## 0.2.0-beta.24

- Aprofunda sinais de segurança de App Service e Azure SQL.
- Detecta HTTPS-only desabilitado e TLS legado no App Service.
- Detecta acesso público habilitado no Azure SQL.
- Detecta regras de firewall SQL abertas para qualquer origem e a regra especial de serviços Azure.
- Mantém detecções conservadoras: propriedades ausentes não são tratadas como conformidade.
- Adiciona regressões automatizadas para os novos sinais de postura.

## 0.2.0-beta.23

- Aprofunda o discovery Azure com postura explícita de Storage, Key Vault e NSG.
- Detecta blob público, HTTPS-only desabilitado, TLS legado, soft delete e purge protection.
- Detecta regras inbound públicas para SSH (22) e RDP (3389).
- Exibe a postura de segurança por recurso no HTML.
- Mantém ausência de propriedade como evidência insuficiente, sem falso “conforme”.
- Adiciona regressões automatizadas para os sinais de segurança de recursos.

## 0.2.0-beta.22

- Registra início, fim, duração e tentativa por módulo no `collection_log`.
- Propaga a janela temporal para o manifesto de execução e o discovery técnico.
- Melhora a transparência de assessments longos e sujeitos a throttling.
- Adiciona regressão automatizada para a rastreabilidade temporal dos coletores.

## 0.2.0-beta.21

- Adiciona modo de relatório pseudonimizado para compartilhamento seguro.
- Preserva o contrato original e nunca grava o salt de pseudonimização.
- Cria wrappers Bash e PowerShell para gerar HTML, PDF, PPTX e XLSX protegidos.
- Exibe no relatório o modo de privacidade utilizado.
- Valida a geração pseudonimizada ponta a ponta sem expor e-mails ou nomes.

## 0.2.0-beta.20

- Adiciona manifesto de integridade dos artefatos com hashes SHA-256.
- Registra classificação confidencial, perfil, run ID, schema e modo read-only.
- Integra a geração do manifesto aos wrappers Bash e PowerShell.
- Documenta a verificação de integridade do HTML, PDF, PPTX e XLSX.
- Adiciona teste automatizado para hash e preservação do guardrail read-only.

## 0.2.0-beta.19

- Adiciona checklist automático de pré-entrega no `pilot-validation.json`.
- Bloqueia entrega quando read-only, contrato, manifesto de coleta ou payload de IA falham.
- Sinaliza warnings de cobertura, módulos indisponíveis e achados condicionais.
- Documenta o checklist no fluxo operacional da Beta.
- Adiciona regressão automatizada para decisão `pass`, `warning` e `blocked`.

## 0.2.0-beta.18

- Impede que achados com `INSUFFICIENT_EVIDENCE` sejam classificados como P1.
- Marca esses achados como `conditional_review`, preservando visibilidade sem declarar risco confirmado.
- Propaga estado de evidência, confiança e gate de licença para os achados reais.
- Exibe prioridade e elegibilidade da evidência no HTML técnico.
- Adiciona regressão automatizada para a regra de prioridade segura.

## 0.2.0-beta.17

- Implementa gating de licença por controle para Secure Score, Defender e Intune.
- Impede que evidência parcial seja apresentada como conformidade quando o entitlement não foi verificado.
- Registra `license_gate_status` e `license_or_entitlement_not_verified` no contrato.
- Exibe o estado do gate de licença na tabela técnica do HTML.
- Adiciona regressão automatizada contra falso positivo de conformidade.

## 0.2.0-beta.16

- Torna o resumo executivo orientado pelos dados, identificando o domínio prioritário real da execução.
- Corrige o contador de controles avaliados para excluir evidência insuficiente.
- Remove narrativa fixa que poderia atribuir risco à Governança Azure quando os dados apontassem outro domínio.
- Adiciona teste de regressão para evitar conclusões executivas estáticas.

## 0.2.0-beta.15

- Adiciona manifesto de execução por perfil, separando módulos coletados, indisponíveis e fora do escopo.
- Inclui o manifesto no contrato normalizado, mantendo apenas contagens, status e limitações não sensíveis.
- Corrige a transparência do HTML: dados reais não são mais rotulados como demonstração fictícia.
- Adiciona teste de regressão para rastreabilidade do escopo da execução.

## 0.2.0-beta.14

- Ajusta o score de qualidade da evidência para excluir módulos fora do perfil do denominador.
- Mantém `not_run` visível como escopo não executado, sem tratá-lo como falha ou conformidade.
- Adiciona regressão automatizada para a separação entre qualidade e cobertura operacional.

## 0.2.0-beta.13

- Diferencia módulos fora do perfil (`not_run`) de módulos indisponíveis ou com erro.
- Evita degradar artificialmente a qualidade da evidência em perfis focados.
- Exibe no relatório o total de módulos fora do perfil e documenta a interpretação segura.
- Amplia a validação do piloto com `modules_not_run` e mantém 90 testes automatizados.

## 0.1.9

- Discovery read-only de consentimentos OAuth e permissões delegadas.
- Destaque de escopos de alto impacto sem coleta de tokens ou secrets.
- Correlações de risco entre Segurança e Governança.
- Camada executiva de decisões e cobertura de evidência por controle.
- Perfis de execução `security`, `governance` e `full`.
- Sinais de postura por recurso Azure.
- 29 testes automatizados passando.
