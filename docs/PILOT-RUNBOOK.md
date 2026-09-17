# Runbook do piloto

## Objetivo

Executar o assessment em uma estação de trabalho autorizada, sem provisionar
VM e sem executar alterações no tenant.

## Antes da execução

1. Confirmar autorização do cliente e subscriptions incluídas.
2. Criar ou selecionar uma identidade dedicada somente leitura.
3. Confirmar `Reader` no escopo Azure e as permissões Graph documentadas na
   [matriz de permissões](PERMISSIONS-MATRIX.md).
4. Instalar Python 3.10 ou superior e Azure CLI.
5. Executar `az login` no tenant correto.

## Execução rápida no Windows

```powershell
az login --tenant <tenant-id>
.\scripts\run-assessment.ps1 -Subscriptions "<subscription-id>"
```

## Execução rápida no Linux/macOS

```bash
az login --tenant <tenant-id>
chmod +x scripts/run-assessment.sh
./scripts/run-assessment.sh "<subscription-id>"
```

## Saídas

- `runtime/preflight.json`: validação inicial do ambiente e sessão.
- `runtime/assessment.json`: contrato normalizado completo.
- `runtime/ai-payload.json`: somente métricas agregadas para futura IA.
- `dist/assessment.html`: relatório técnico e executivo offline.
- `dist/assessment-action-plan.xlsx`: plano de ação.
- `dist/assessment-executive-summary.pdf`: resumo print-friendly.
- `dist/assessment-executive-summary.pptx`: apresentação executiva.

## Critérios de aceite do piloto

- `metadata.contract_status = valid`.
- Nenhum status `error` sem observação no manifesto de evidências.
- Os escopos coletados correspondem à autorização aprovada.
- O HTML abre sem internet e não possui referências externas.
- O payload de IA não contém nomes, UPNs, IDs de recursos ou evidências brutas.
- O cliente valida os achados antes de qualquer remediação.
