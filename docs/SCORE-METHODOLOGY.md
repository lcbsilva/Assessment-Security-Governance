# Metodologia de score — Beta

## Princípios

- O score mede somente controles com evidência suficiente nesta execução.
- `not_available`, `error`, `not_run` e `INSUFFICIENT_EVIDENCE` não são tratados como conformidade.
- A cobertura é exibida separadamente e reduz a confiança da interpretação.
- Um domínio sem controles avaliáveis recebe score `N/D`, cobertura `0%` e não é incluído silenciosamente no peso do score geral.
- Um domínio sem controles no catálogo aparece como `Não configurado`. Um domínio com controles catalogados, mas sem evidência avaliada, aparece como `N/D`, cobertura `0%` e `insufficient`.
- O domínio Compliance agora possui controles de DLP, rótulos de sensibilidade e retenção. Até haver coleta nativa de Purview ou evidência suficiente, permanecem `INSUFFICIENT_EVIDENCE`; a importação opcional Microsoft Zero Trust é exibida separadamente e não altera o score próprio.
- O resultado não é certificação, auditoria legal ou garantia absoluta de segurança.

## Cálculo

Para cada domínio:

```text
score_do_domínio = Σ(score_do_controle × peso_do_controle)
                   / Σ(peso_dos_controles_com_evidência)
```

O score geral usa os pesos de domínio somente para domínios que possuem pelo menos um controle avaliável:

```text
score_geral = Σ(score_do_domínio × peso_do_domínio)
              / Σ(peso_dos_domínios_com_evidência)
```

```text
cobertura = controles_com_evidência / controles_no_catálogo × 100
```

Isso evita que um domínio ainda não implementado seja apresentado como seguro e evita renormalização silenciosa do denominador. A exclusão de um domínio do score geral é registrada pela cobertura `0%` e pelo estado `insufficient`.

Controles ausentes do contrato de uma execução são materializados como `not_available`/`INSUFFICIENT_EVIDENCE` antes do cálculo. Assim, a cobertura usa o catálogo completo e uma coleta parcial não melhora artificialmente o resultado.

## Evidência e licença

| Estado | Interpretação |
|---|---|
| `CONFORMANT` | Evidência suficiente e resultado acima do limiar do controle. |
| `NON_CONFORMANT` | Evidência suficiente e resultado abaixo do limiar. |
| `INSUFFICIENT_EVIDENCE` | Permissão, licença, retenção, endpoint, escopo ou execução insuficiente. |

Licença ausente, permissão negada ou endpoint indisponível nunca resultam em `CONFORMANT`.

## Priorização

O risco técnico permanece separado do esforço. A prioridade usa risco, severidade, confiança e sinais financeiros quantificados. O esforço é utilizado para sequenciamento e para a matriz impacto × esforço.

A confiança de cada achado acompanha a confiança registrada no controle associado; `INSUFFICIENT_EVIDENCE` sempre implica confiança baixa e impede prioridade P1 confirmada. O alcance é expresso na unidade observada (por exemplo, usuários, recursos, dispositivos ou registros de Policy). Isso não mede impacto operacional, indisponibilidade ou ocorrência de incidente. A faixa de esforço é uma estimativa relativa de planejamento, não horas ou valor contratado.

Achados com `INSUFFICIENT_EVIDENCE` não são elegíveis para P1 confirmado; aparecem como revisão condicional.

## Comparação entre execuções

Scores só devem ser comparados junto com a cobertura e com o conjunto de controles avaliados nas duas execuções. Mudança de permissão, licença, escopo ou retenção pode alterar o score sem representar melhoria ou deterioração real.

## Privacidade

O relatório técnico contém dados derivados do tenant e deve ser tratado como confidencial. Para compartilhamento fora do perímetro do cliente, gerar uma cópia pseudonimizada com salt local. O payload de IA permanece agregado e sem identificadores.
