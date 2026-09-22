# Importação local do Microsoft Zero Trust Assessment

## Finalidade e limites

A integração compara metadados de verificações da saída do Microsoft Zero Trust Assessment com controles relacionados do Assessment Engine. É uma referência para análise conjunta, não uma equivalência entre metodologias nem uma validação independente da evidência. Os status e pontuações dos produtos ficam separados; não existe score combinado.

O importador processa localmente `ZeroTrustAssessmentReport.json` ou o ZIP exportado que contenha exatamente um `*/zt-export/ZeroTrustAssessmentReport.json`. Não autentica, não chama APIs Microsoft e não altera o tenant. O coletor do Assessment Engine continua read-only.

## Comando manual

Com os dois arquivos locais:

```bash
python3 src/import_zt_assessment.py \
  --source "/caminho/ZeroTrustAssessmentReport.zip" \
  --data runtime/assessment.json \
  --output runtime/assessment-combined.json
python3 src/generate_report.py --data runtime/assessment-combined.json --output dist/assessment.html
python3 src/export_artifacts.py --data runtime/assessment-combined.json --output-dir dist
```

O importador compara o tenant ID do relatório Microsoft com `metadata.tenant_id` ou com o prefixo de `metadata.tenant_id_masked` no assessment base. Se nenhum deles estiver disponível, só prossiga após confirmar por conta própria que os dois relatórios vieram do mesmo tenant:

```bash
python3 src/import_zt_assessment.py \
  --source "/caminho/ZeroTrustAssessmentReport.zip" \
  --data runtime/assessment.json \
  --output runtime/assessment-combined.json \
  --confirm-same-tenant
```

Uma divergência identificável de tenant sempre bloqueia a importação.

## Importação pelo wrapper

Bash/Cloud Shell:

```bash
export ASSESSMENT_ZERO_TRUST_REPORT="/caminho/ZeroTrustAssessmentReport.zip"
./scripts/run-assessment.sh "<subscription-id>" full
```

PowerShell 7:

```powershell
$env:ASSESSMENT_ZERO_TRUST_REPORT = "/caminho/ZeroTrustAssessmentReport.zip"
./scripts/run-assessment.ps1 -Subscriptions "<subscription-id>" -Profile full
```

Sem essa variável, o wrapper segue o fluxo usual. A importação combinada é gravada como `runtime/assessment-combined.json`; os artefatos executivos são gerados com ela. O payload agregado de IA e a validação do piloto continuam baseados apenas no assessment nativo.

## Minimização e manuseio

O contrato importado mantém ID e título da verificação, pilar, categoria, status Microsoft, risco do teste, licença mínima, custo de implementação, categoria generalizada de motivo de skip, vínculo de controle e SHA-256 do arquivo fonte. O importador descarta `TenantId`, nome/domínio/conta, `TenantInfo`, evidência detalhada `TestResult` e texto bruto de `SkippedReason`. Há limite de 25 MB para o JSON e 10.000 verificações.

O JSON combinado, os relatórios e o ZIP original continuam confidenciais: a minimização reduz identificadores e evidência granular, mas não transforma os artefatos em dados públicos. Para compartilhar fora do perímetro aprovado, siga o procedimento de pseudonimização e revisão local já documentado.

## Mapeamento e lacunas

O crosswalk versionado está em `catalog/zero_trust_crosswalk.yaml`. Um vínculo só é aplicado quando ID e título da verificação coincidem com a versão registrada. Títulos divergentes permanecem sem vínculo automático e são contados no relatório. Pilares podem se sobrepor.

O relatório Microsoft não cobre todos os domínios do engine e pode omitir infraestrutura, custos ou controles Azure. `Insufficient`, `Skipped`, `Planned` ou erro de um dos produtos nunca deve ser interpretado como conformidade do outro. As contagens externas não afetam score nem cobertura nativos.
