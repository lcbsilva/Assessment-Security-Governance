# Adaptadores de evidência M365

O engine separa o que já é coletado por DNS/Graph do que exige uma API administrativa específica. Isso evita afirmar que Exchange, SharePoint, Teams, Unified Audit Log ou Power Platform DLP foram avaliados quando o endpoint não foi executado.

## Estado atual

- SPF, DMARC e DKIM: coleta DNS read-only opcional por `ASSESSMENT_M365_DOMAINS`.
- Exchange forwarding externo: adaptador ainda não configurado.
- SharePoint/OneDrive sharing: adaptador ainda não configurado.
- Teams federation/reuniões: adaptador ainda não configurado.
- Unified Audit Log: adaptador Purview/Exchange ainda não configurado.
- Power Platform DLP: adaptador Power Platform Admin API ainda não configurado.

## Regra de integração

Cada adaptador deve:

1. receber somente credencial read-only aprovada;
2. declarar seu escopo no Readiness Gate;
3. retornar `success`, `partial` ou `not_available`;
4. produzir metadados agregados e evitar conteúdo de negócio;
5. informar licença, retenção e janela de coleta;
6. entrar no contrato, mapa de cobertura e validação de evidência.

Até a integração ser implementada e testada, a capacidade permanece `not_configured` no relatório.
