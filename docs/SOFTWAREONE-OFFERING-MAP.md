# Mapa de encaminhamento consultivo

O relatório usa a classificação abaixo para transformar achados técnicos em
frentes de trabalho. Ela organiza o handoff interno e não representa, por si
só, uma definição comercial, produto obrigatório ou compromisso de escopo.

| Frente no relatório | Exemplos de achados | Próximo time a envolver |
|---|---|---|
| Identity & Access | MFA, Conditional Access, PIM, convidados, contas inativas | IAM / Entra / Zero Trust |
| Cloud & M365 Security | Secure Score, Defender, endpoints, autenticação legada | Security / SOC / Modern Workplace |
| Cloud Governance | Hierarquia, tags, RBAC, exposição pública, Policy | Cloud Platform / Governance |
| FinOps & Cloud Optimization | Recursos órfãos, idade, recomendações de custo | FinOps / Cloud Economics |
| Risk & Compliance | Evidências de controle, cobertura e exceções | GRC / Risk / Compliance |

## Regras de integridade

- A frente é derivada do controle avaliado e não altera o score.
- Um módulo `not_available`, `error` ou `partial` permanece visível no
  manifesto de evidências; não é convertido em conformidade presumida.
- O plano recomenda validação pelo owner antes de qualquer mudança.
- O assessment não executa remediação, exclusão, criação ou alteração no
  tenant.

## Evolução planejada

Para serviços em aposentadoria, a coleta deve usar uma fonte suportada para
avisos de Service Health ou o Azure Advisor, mantendo no relatório a origem,
data da coleta e a janela de validade da recomendação. O inventário não deve
inferir data de aposentadoria a partir de nomes ou tipos de recursos.
