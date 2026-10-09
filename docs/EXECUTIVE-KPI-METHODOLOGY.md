# Metodologia dos indicadores executivos

Os indicadores desta página são contagens observadas na janela da execução.
Eles não certificam conformidade, risco de negócio ou eficácia de controles.

## Regra de evidência

- Um valor numérico, inclusive zero, só é exibido quando todas as fontes necessárias concluíram com status success.
- Se uma fonte estiver partial, not_available, error, not_run ou sem registro, o resumo exibe “Sem evidência”. O manifesto técnico mantém o estado e a causa observada/provável.
- A falha de uma subconsulta de identidade, como membros de função, limita o indicador agregado de Identity quando pode causar subcontagem.
- HTML, PDF, PPTX e XLSX usam o mesmo modelo de métricas. A aba “Indicadores executivos” da planilha inclui valor, status, fontes e interpretação.
- “Sem evidência” não significa zero, conformidade nem ausência de risco.

## Indicadores e fontes

| Indicador | Fontes necessárias | Definição |
|---|---|---|
| Sem MFA | Identity e MFA | Usuários classificados explicitamente como “Not registered”; usuários com MFA desconhecido não entram na contagem. |
| Privilegiados sem MFA | Identity, MFA e membros de função quando consultados | Contas marcadas como privilegiadas e classificadas explicitamente sem MFA. |
| Convidados externos | Identity | Contas cujo tipo retornado pela fonte é Guest. |
| RBAC alto risco | RBAC | Atribuições marcadas como Alto ou Crítico; não demonstra uso efetivo da permissão. |
| Recursos públicos | Azure inventory | Recursos com sinal de exposição explicitamente retornado pelo inventário. |
| Azure Policy | Azure Policy | Soma de não conformidades nas linhas retornadas; pode diferir do número total de registros de Policy. |
| Endpoints em atenção | Entra devices e Intune managed devices | Soma observada de não conformes e não gerenciados, exigindo coleta completa das duas fontes. |

Os dados detalhados, as limitações por coletor e as janelas de coleta permanecem
no contrato técnico confidencial. Antes de recomendar remediação, valide o
escopo e o contexto com o owner do serviço.
