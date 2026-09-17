# Matriz de validação do piloto

## Preparação

1. Usar tenant e subscription de laboratório ou escopo previamente aprovado.
2. Criar/usar uma identidade dedicada com permissões somente de leitura.
3. Registrar tenant, subscriptions, horário, versão do engine e consentimentos.
4. Executar primeiro o preflight e confirmar `ready`.

## Conferência cruzada

| Evidência | Fonte de referência | Resultado esperado |
|---|---|---|
| Usuários e convidados | Entra admin center / Graph Explorer | Quantidade compatível e diferenças justificadas |
| MFA | Entra > Authentication methods | Registrados e não registrados compatíveis |
| Conditional Access | Entra > Protection > Policies | Nome, estado, escopo e exclusões compatíveis |
| PIM | Entra > Privileged Identity Management | Ativos e elegíveis separados |
| Recursos Azure | Resource Graph Explorer | Contagem e tipos compatíveis por subscription |
| RBAC | IAM > Role assignments | Escopo, função e tipo compatíveis |
| Azure Policy | Policy > Compliance | Não conformidades e isenções compatíveis |
| Secure Score/Defender | Microsoft Defender portal | Indisponibilidade aparece como `not_available` |
| Custos | Cost Management | Mesmo período e escopo de comparação |

## Critérios de aceite

- Nenhuma chamada de escrita no código ou no log dos coletores.
- `metadata.execution.tenant_mutation` igual a `false`.
- `metadata.contract_status` igual a `valid`.
- `runtime/pilot-validation.json` igual a `ready_for_pilot_review`.
- Diferenças relevantes explicadas por escopo, permissão, paginação ou retenção.
- Módulos indisponíveis explicitamente registrados.
- Nenhum segredo, certificado ou PII no payload de IA.

Guardar os arquivos técnicos do piloto separadamente do relatório executivo:
JSON normalizado, preflight, validação, comparação e logs.
