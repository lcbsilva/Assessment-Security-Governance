# Entrega da sprint beta.71 — matriz de validação

## Objetivo

Garantir que a cadeia offline continue íntegra em portes diferentes antes de
uma apresentação ao time ou de uma execução em tenant autorizado.

## Entrega

- `scripts/run-synthetic-matrix.sh` executa os cenários `small`, `medium`,
  `limited`, `full` e `large` em escala controlada.
- Cada execução gera contrato, HTML, PDF, PPTX, XLSX, payload agregado,
  manifesto e resumo de prontidão.
- O script falha quando um cenário não retorna `ready_for_internal_demo`,
  quando a integridade é inválida ou quando a execução deixa de ser sintética
  e somente leitura.
- O GitHub Actions executa a mesma matriz após os testes e o Release Gate.

## Fronteiras

Esta sprint não autentica, consulta ou modifica tenant. Dados sintéticos não
substituem a reconciliação humana com Portal Azure, Microsoft Graph e Resource
Graph. O aceite de piloto continua condicionado à autorização formal e às
permissões aprovadas.

## Critério de aceite

O script deve concluir todos os cinco cenários com artefatos válidos e status
`ready_for_internal_demo`.
