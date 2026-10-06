# Sprint 7 — Azure Lab Validation

Esta etapa valida a versão estável em um tenant de laboratório autorizado. Ela não é substituída por CI, mocks ou cenários sintéticos.

## Critérios de aceite

- confirmar tenant e subscriptions antes de qualquer coletor;
- executar os perfis `security`, `governance` e `full` pelo runner oficial;
- preservar execução somente leitura;
- gerar HTML, PDF, PPTX, XLSX, payload de IA, manifesto e validações para cada perfil;
- consolidar `runtime/lab-validation/summary.json`;
- tratar `partial` e `not_available` como limitações observáveis, nunca como conformidade;
- não declarar a Sprint 7 validada enquanto a execução real não tiver ocorrido.

## PowerShell

```powershell
.\scripts\run-lab-validation.ps1 \
  -Subscriptions "<subscription-id>" \
  -ExpectedTenantId "<tenant-id-autorizado>"
```

## Bash / Cloud Shell

```bash
./scripts/run-lab-validation.sh "<subscription-id>" "<tenant-id-autorizado>"
```

## Interpretação

`pass` significa que os perfis executados não apresentaram bloqueios nos gates locais. `warning` preserva limitações de cobertura para revisão consultiva. `blocked` impede aprovação. `not_run` significa que não existe evidência suficiente para declarar a validação realizada.

Os arquivos em `runtime/lab-validation` podem conter material confidencial e não devem ser commitados.
