# Cenários sintéticos offline

O engine possui cenários locais para testar comportamento antes de usar um tenant real. Eles não fazem login, não chamam APIs e não representam evidência de cliente.

```bash
python3 src/simulate_tenant.py --scenario small --output runtime/sim-small.json
python3 src/generate_report.py --data runtime/sim-small.json --output dist/assessment-small.html

python3 src/simulate_tenant.py --scenario medium --output runtime/sim-medium.json
python3 src/generate_report.py --data runtime/sim-medium.json --output dist/assessment-medium.html

python3 src/simulate_tenant.py --scenario limited --output runtime/sim-limited.json
python3 src/generate_report.py --data runtime/sim-limited.json --output dist/assessment-limited.html

python3 src/simulate_tenant.py --scenario full --output runtime/sim-full.json
python3 src/generate_report.py --data runtime/sim-full.json --output dist/assessment-full.html
```

| Cenário | O que valida |
|---|---|
| `small` | Poucos usuários, recursos e módulos opcionais ausentes |
| `medium` | Volume intermediário, paginação representativa e limitações opcionais |
| `limited` | 403, 429, falta de licença e cobertura parcial |
| `full` | Fluxo executivo com maior cobertura sintética |

O JSON recebe `metadata.simulation.is_simulation=true` e `evidence_status=synthetic_not_customer_evidence`. Esses arquivos não devem ser usados como evidência real.
# Cenários sintéticos e teste de escala

Os cenários são locais e não autenticam no Azure nem no Microsoft Graph. Eles
servem para validar contrato, scoring, renderer, falhas esperadas e volume.

## Cenário grande

```bash
python src/simulate_tenant.py --scenario large --output runtime/simulation-large.json
python src/generate_report.py --data runtime/simulation-large.json --output runtime/assessment-large.html
```

O cenário padrão gera milhares de usuários, recursos, dispositivos, aplicações,
RBAC e Azure Policy. Também inclui respostas sintéticas `partial`/429 e
`not_available`/403 para confirmar que a ausência de licença, permissão ou
throttling não vira conformidade.

Para ampliar o volume:

```bash
python src/simulate_tenant.py --scenario large --scale 10 --output runtime/simulation-large-x10.json
```

`--scale 10` gera aproximadamente 20 mil usuários e 25 mil recursos. O arquivo
fica marcado como `synthetic_not_customer_evidence` e nunca deve ser apresentado
como evidência de cliente.
