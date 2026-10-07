# Consultant Flow

Fluxo guiado para executar o assessment sem pular os gates de segurança e entrega.

## Uso

```powershell
.\scripts\run-consultant-flow.ps1 -Subscriptions "<subscription-id>" -ExpectedTenantId "<tenant-id>" -Profile full
```

O runner confirma o tenant esperado e as subscriptions visíveis antes de iniciar. Em seguida reutiliza o fluxo oficial de readiness, coleta read-only, geração e validação dos artefatos, executa o Delivery Gate e encerra no Release Gate.

Nenhum gate transforma ausência de evidência em conformidade. Resultado bloqueado deve ser corrigido ou documentado; não deve ser contornado para produzir um pacote de cliente.
