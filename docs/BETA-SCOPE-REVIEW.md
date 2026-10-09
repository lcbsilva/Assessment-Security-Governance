# Revisão de escopo antes da entrega Beta

## Decisão executiva

O produto deve ser entregue como um **Assessment de Segurança e Governança
Microsoft**, enriquecido por sinais de Identidade, FinOps e ecossistema. Não é
necessário transformar a Beta em um inventário completo de todos os portais
Microsoft. A cobertura adicional só deve entrar quando gerar uma decisão,
achado ou impacto financeiro defensável.

O critério adotado é:

> manter o que produz evidência acionável; tornar opcional o que depende de
> licença/integracão específica; adiar o que apenas aumenta inventário sem
> mudar a decisão executiva.

## O que fica no núcleo Beta

| Capacidade | Valor | Decisão |
|---|---|---|
| Readiness Gate e guardrail read-only | Evita execução sem escopo/permissão e protege o tenant | Manter como obrigatório |
| Azure Resource Graph: inventário, exposição, tags e hierarquia | Base de Governança Azure e evidência de superfície | Manter como obrigatório |
| RBAC, PIM, escopo e privilégios | Principal conexão entre segurança e governança | Manter como obrigatório |
| Entra: usuários, MFA, CA, sign-ins, convidados e inatividade | Produz riscos claros para o gestor | Manter como obrigatório |
| Aplicações, credenciais e consentimentos OAuth | Identifica risco de persistência e excesso de privilégio | Manter como obrigatório |
| Azure Policy e não conformidades | Evidência objetiva de governança | Manter como obrigatório |
| Secure Score, Defender e Intune | Alta relevância, mas com estado explícito quando não licenciados | Manter como módulos opcionais do núcleo |
| Evidência em três estados, cobertura e auditoria pré-entrega | Protege a credibilidade do relatório | Manter como obrigatório |
| Scoring, priorização, owners e plano 30/60/90 | Converte dados em decisão consultiva | Manter como obrigatório |
| HTML autocontido e exportações | Facilita apresentação e handoff | Manter HTML + XLSX; PDF/PPTX como pacote executivo |
| Checkpoints, histórico e comparação | Reduz risco operacional e permite acompanhamento | Manter como obrigatório |

## O que agrega valor, mas deve ser opcional

| Capacidade | Valor objetivo | Condição |
|---|---|---|
| Cost Management, Advisor, órfãos e ciclo de vida | Mostra desperdício e oportunidades de custo | Executar no perfil `full` com Cost Management Reader |
| Licenças M365 | Identifica capacidade contratada sem uso | Exibir agregado; não expor atribuição individual por padrão |
| SPF, DMARC e DKIM | Quick win de segurança de e-mail | Manter no perfil de Segurança quando domínio for informado |
| Power Platform | Governança de Apps, Automate, agentes e conectores premium | Inventário somente; DLP real depende de adaptador próprio |
| Azure DevOps | Governança de repositórios públicos e pipelines | Somente com integração explicitamente habilitada e PAT read-only |
| Purview, Fabric, Synapse, Databricks e Power BI | Contexto de dados e arquitetura | Manter como inventário opcional, sem afirmar postura de segurança que não foi coletada |
| Reservas e Savings Plans | Contexto FinOps | Mostrar inventário e origem; não prometer economia sem billing completo |

## O que não deve bloquear a Beta

- DLP/retention do Purview sem integração específica.
- Postura profunda de SharePoint, Teams e Exchange sem APIs e permissões
  dedicadas.
- Benchmark entre clientes antes de existir consentimento, anonimização e
  base estatística.
- IA generativa para conclusões técnicas. A camada de IA deve continuar
  limitada a métricas agregadas e narrativa executiva.
- Inventário de todo o ecossistema quando não houver insight ou controle
  associado.

## Ajuste aplicado nos perfis

- `security`: ARG, Graph e postura de domínios M365; módulos DevOps,
  analytics e custo não são chamados.
- `governance`: ARG, RBAC Azure e endpoints Graph de Entra PIM; os demais
  endpoints de identidade/segurança, M365, DevOps e analytics ficam
  explicitamente como `not_run` e não são consultados.
- `full`: executa também custo, Power Platform, analytics e integrações
  opcionais, mantendo limitações no manifesto.

Isso reduz chamadas desnecessárias no piloto, evita pedir permissões que não
agregam ao objetivo principal e mantém a funcionalidade disponível para uma
execução ampliada.

## Riscos que precisam permanecer visíveis

1. **Relatório grande demais:** inventários detalhados devem ficar em seções
   recolhíveis e exportação técnica; a leitura executiva deve mostrar agregados.
2. **PII no pacote técnico:** UPNs, IDs e nomes de recursos precisam de modo
   pseudonimizado antes de circulação fora do time autorizado.
3. **Licença não é conformidade:** Secure Score, Defender, Intune e Purview
   indisponíveis devem aparecer como evidência insuficiente.
4. **Custo potencial não é economia:** toda estimativa deve exibir fonte,
   período e fórmula.
5. **Inventário não é postura:** existência de recurso, app ou workspace não
   prova configuração segura.

## Conclusão

Não recomendamos remover os coletores opcionais do código. Recomendamos tirá-los
do caminho principal da Beta e do resumo executivo quando não houver evidência.
O produto fica mais rápido, mais defensável e mais alinhado à oferta de
Segurança e Governança, sem perder capacidade de expansão após a apresentação ao
gestor.
