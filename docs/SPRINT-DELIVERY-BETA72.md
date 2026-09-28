# Entrega da sprint beta.72 — acompanhamento contínuo local

## Objetivo

Adicionar uma visão inspirada em dashboards operacionais sem transformar o
Assessment Engine em um serviço persistente ou conceder novas permissões.

## Uso

Após uma ou mais execuções autorizadas:

```bash
./scripts/generate-history-dashboard.sh
```

No PowerShell 7:

```powershell
.\scripts\generate-history-dashboard.ps1
```

O resultado é `dist/history-dashboard.html`, autocontido e offline.

## Segurança e limites

- O dashboard somente lê `runtime/history/`.
- Não autentica, coleta, altera ou remedia o tenant.
- Não inclui usuários, UPNs, recursos, IDs ou texto de evidência.
- A coleta continua sob demanda pelo fluxo aprovado; não existe daemon oculto.
- A tendência só deve ser interpretada quando houver cobertura comparável entre
  as execuções.

## Aceite

O dashboard deve abrir offline, funcionar sem dependências externas e informar
claramente quando ainda não existem snapshots.
