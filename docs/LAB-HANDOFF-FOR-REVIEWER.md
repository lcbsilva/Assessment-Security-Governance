# Handoff para execução autorizada em laboratório

Este documento acompanha uma execução de revisão feita por outro consultor ou
time. O Assessment Engine é somente leitura: não cria, altera, exclui ou
remedia objetos no tenant. A execução deve ocorrer somente depois de o
responsável pelo tenant aprovar o escopo, o perfil e as permissões de leitura.

## Antes de executar

1. Confirmar tenant e subscriptions autorizados.
2. Confirmar que a pessoa executora está autenticada no tenant correto.
3. Usar uma pasta local protegida e tratar `runtime/` e `dist/` como
   confidenciais.
4. Não fornecer ao engine credenciais, secrets, tokens ou PATs em arquivos de
   configuração.
5. Não enviar `assessment.json`, relatórios técnicos ou payloads brutos para
   ferramentas de IA, e-mail ou compartilhamento externo.

## Instalação

PowerShell 7:

```powershell
az login --tenant "<tenant-id>"
az account show --query "{tenantId:tenantId,subscriptionId:id}" -o table
```

O fluxo PowerShell instala as dependências em `.assessment-venv`; não é
necessário instalar pacotes no Python global.

Cloud Shell Linux:

```bash
python3 -m pip install -r requirements.txt
az login
az account set --subscription "<subscription-id>"
az account show --query '{tenantId:tenantId,subscriptionId:id}' -o table
```

## Readiness obrigatório

Os wrappers executam o Readiness Gate antes da coleta, dentro do ambiente
Python isolado no Windows. Ele não concede permissões nem altera o tenant.
Qualquer bloqueio interrompe o fluxo antes dos coletores.

## Execução recomendada

Começar com `security`, revisar o resultado e depois executar `full` somente
se o escopo ampliado estiver autorizado:

```powershell
.\scripts\run-focused-pilot.ps1 -ExpectedTenantId "<tenant-id>" -Subscriptions "<subscription-id>"
```

Ou, para a execução ampliada:

```powershell
.\scripts\run-assessment.ps1 -ExpectedTenantId "<tenant-id>" -Subscriptions "<subscription-id>" -Profile full
```

No Cloud Shell:

```bash
./scripts/run-focused-pilot.sh "<subscription-id>"
```

Os módulos sem licença, consentimento, retenção ou suporte devem permanecer
como `not_available`/`partial`. Isso é comportamento esperado e não deve ser
substituído manualmente.

## O que revisar no resultado

- `runtime/*/assessment.json`: evidência técnica confidencial.
- `runtime/*/pilot-validation.json`: contrato, integridade, read-only e
  limitações.
- `dist/*/assessment.html`: relatório offline para revisão autorizada.
- `dist/*/assessment-action-plan.xlsx`: plano de ação e owners sugeridos.
- `runtime/*/ai-payload.json`: somente agregados; ainda deve ser tratado como
  material controlado e validado antes de qualquer uso.

Comparar uma amostra dos achados com Portal, Graph Explorer e Azure Resource
Graph. Registrar divergências, tempo, throttling, módulos indisponíveis e
permissões efetivamente utilizadas no template de feedback. Não interpretar
um score provisório como certificação, auditoria ou evidência de incidente.

## Critério de encerramento da revisão

A revisão pode ser marcada como pronta para discussão interna quando:

- o preflight estiver pronto;
- o relatório e os artefatos tiverem integridade válida;
- os estados `partial`/`not_available` estiverem explicados;
- não houver chamadas de escrita;
- uma amostra tiver sido comparada com fontes Microsoft;
- as limitações e recomendações tiverem owner para validação humana.
