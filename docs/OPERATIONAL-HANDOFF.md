# Operational Handoff

Este runbook permite que outro consultor execute o Assessment Engine sem ampliar privilégios nem alterar o tenant.

## Fluxo obrigatório

1. Confirme tenant e subscriptions autorizadas antes da coleta.
2. Execute o Readiness Gate e interrompa se `execution_decision=blocked`.
3. Comece pelo perfil `security`; amplie para `full` somente dentro do escopo aprovado.
4. Trate `partial`, `not_available` e `error` como limitações de evidência, nunca como conformidade.
5. Valide artefatos e manifesto antes do handoff ao cliente.

## Diagnóstico rápido

- `runtime/preflight.json`: ambiente, sessão, guardrail e escopos esperados.
- `runtime/assessment.json`: contrato e collection_log por módulo.
- `runtime/pilot-validation.json`: bloqueios e warnings de pré-entrega.
- `runtime/artifact-manifest.json`: hashes e classificação dos artefatos.
- `runtime/lab-validation/summary.json`: somente existe após execução real do roteiro de laboratório.

## Regras de segurança

O assessment é read-only. Não conceda permissões automaticamente para aumentar cobertura. Não execute contra tenant diferente do aprovado. Falhas de licença, consentimento, retenção, throttling ou endpoint devem permanecer registradas com seu estado real. A execução de laboratório só pode ser declarada validada quando os artefatos dessa execução existirem e forem revisados.

## Azure OpenAI opcional

A camada consultiva de IA é opt-in e aceita somente o payload agregado aprovado pelo gate de privacidade. Ausência de configuração mantém o recurso desabilitado. A saída de IA não altera score, controles ou evidências determinísticas.
