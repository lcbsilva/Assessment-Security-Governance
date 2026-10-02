# Entrega Beta 73 — confiança, onboarding e fechamento do piloto

## Entregas

- A saúde da execução agora expõe `confidence_score`, `confidence_band` e a
  base de cálculo, sem misturar confiança com score de segurança.
- O `validate_pilot.py` bloqueia a entrega quando
  `metadata.contract_status` é explicitamente `invalid`; contratos legados sem
  esse campo continuam compatíveis.
- `src/generate_pilot_pack.py` gera um handoff local com escopo, permissões de
  leitura, módulos esperados, procedimento e limitações.
- O relatório HTML apresenta a confiança operacional junto do mapa de cobertura.
- O runner PowerShell aceita o launcher `py`, lista HTML/PDF/PPTX/XLSX e abre o
  relatório HTML automaticamente no Windows.
- Quando o engagement não informa o cliente, o relatório usa o tenant detectado
  como identificação visual de fallback.
- A versão foi atualizada para `0.2.0-beta.73`.

## Limites preservados

- Nenhuma chamada de escrita, exclusão ou remediação foi adicionada.
- O pacote de handoff não autentica e não acessa o tenant.
- Módulos sem licença, permissão, retenção ou configuração continuam como
  `not_available`, `partial` ou `not_run`.
- Confiança operacional não é certificação, score de compliance ou garantia de
  ausência de risco.

## Critério de encerramento

Após os gates automatizados, a próxima etapa é validação controlada em tenants
de laboratório pequeno, médio e completo, com revisão humana das diferenças.

