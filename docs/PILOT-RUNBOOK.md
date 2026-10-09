# Runbook do piloto

## Objetivo

Executar o assessment em uma estação de trabalho autorizada, sem provisionar
VM e sem executar alterações no tenant.

## Antes da execução

1. Confirmar autorização do cliente e subscriptions incluídas.
2. Criar ou selecionar uma identidade dedicada somente leitura.
3. Confirmar `Reader` no escopo Azure e as permissões Graph documentadas na
   [matriz de permissões](PERMISSIONS-MATRIX.md).
4. Instalar Python 3.11 ou superior e Azure CLI.
5. Executar `az login` no tenant correto.

## Execução rápida no Windows

```powershell
az login --tenant <tenant-id>
.\scripts\run-consultant-flow.ps1 -ExpectedTenantId "<tenant-id>" -Subscriptions "<subscription-id>"
```

Antes de uma coleta longa, execute o diagnóstico operacional:

```powershell
.\scripts\run-doctor.ps1 -Subscriptions "<subscription-id>" -Profile full
```

## Execução rápida no Linux/macOS

```bash
az login --tenant <tenant-id>
chmod +x scripts/run-assessment.sh
./scripts/run-assessment.sh "<subscription-id>"
```

No Cloud Shell Linux, o diagnóstico equivalente é:

```bash
./scripts/run-doctor.sh "<subscription-id>" full
```

Para um piloto focado em segurança no Azure Cloud Shell Linux, use o perfil
`security`, um escopo de subscription aprovado e o wrapper serial com retomada:

```bash
python3 src/doctor.py --subscriptions "<subscription-id>" --profile security --output runtime/doctor.json
bash ./scripts/run-focused-pilot.sh "<subscription-id>"
```

O wrapper executa o Readiness Gate, a coleta focada, gera os artefatos e roda o
Release Gate local. O POST usado pelo Cost Management é uma operação `query`
somente leitura e só é permitido no endpoint Microsoft Cost Management
explicitamente validado. Nenhum `listKeys`, segredo, chave ou connection string
faz parte da coleta do assessment. O armazenamento persistente montado pelo
Cloud Shell é infraestrutura da própria sessão e deve ser distinguido das
operações dos coletores.

O doctor valida ferramentas, sessão, tenant selecionado, acesso mínimo às
subscriptions, sessão Graph, espaço/caminho local e o contrato read-only. Ele
não substitui o Readiness Gate e não concede permissões.

Se uma execução longa for interrompida, repita com `ASSESSMENT_RESUME=1` ou use `--resume` no runner Python. O engine reutiliza somente checkpoints cujo escopo de subscriptions e perfil coincidem; módulos incompatíveis são executados novamente. A gravação é atômica e checkpoints com erro, indisponibilidade total ou execução interrompida são ignorados. A duração e a tentativa de cada coletor ficam registradas no contrato para diagnóstico.

Os wrappers mostram seis etapas numeradas com tempo decorrido: Readiness Gate, coleta, importação Microsoft opcional, geração de relatórios, validação e manifesto/piloto. Durante a coleta, o runner informa cada módulo quando termina, sua duração e se foi retomado ou se o checkpoint foi gravado. O registro é texto simples e permanece legível em Cloud Shell, PowerShell 7, redirecionamento e logs. O tempo é indicativo e varia com paginação, throttling, licenças e volume do tenant.

Os contratos e checkpoints podem conter dados derivados do tenant. Em POSIX, o engine restringe permissões nos diretórios conhecidos `runtime/`, `dist/` e `dist-shareable/`; no Windows, a proteção depende das ACLs herdadas da conta. A limpeza local nunca ocorre automaticamente. Para revisar arquivos com mais de 30 dias, use `python3 src/cleanup_local.py --include-reports`; revise a prévia antes de acrescentar `--apply`. A rotina não apaga fora das três pastas permitidas e não equivale a apagamento seguro de blocos ou backups.

## Saídas

- `runtime/preflight.json`: validação inicial do ambiente e sessão.
- `runtime/doctor.json`: diagnóstico operacional antes da coleta longa.
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
- Valores exibidos no relatório e artefatos locais são tratados como dados
  confidenciais do tenant; para apresentação interna, usar o pacote sintético
  ou gerar uma cópia pseudonimizada e validá-la antes de compartilhar.
- `ready_for_pilot_review` e `beta_release_ready` confirmam gates técnicos; a
  autorização, validação consultiva e reconciliação com fontes do tenant são
  etapas operacionais separadas.

Para compartilhar artefatos fora do perímetro técnico, use sempre o fluxo
`scripts/generate-shareable-report.ps1` ou `.sh`. O relatório técnico original
contém detalhes derivados do tenant e permanece confidencial; a configuração de
mascaramento do relatório técnico não substitui a geração explícita da cópia
pseudonimizada. No PowerShell, o parâmetro de entrada é `-InputPath` para não
conflitar com a variável automática `$Input`.
