# Entrega Beta 62 — integração de evidência Zero Trust

## Entregas

- Corrigido o denominador de score e cobertura para considerar todos os controles do catálogo; controles sem resultado aparecem como evidência insuficiente.
- Criados três controles de Compliance: DLP, rótulos de sensibilidade e retenção. Não havendo evidência suficiente, o domínio fica sem score e com cobertura explicitamente limitada.
- Adicionada importação local do JSON/ZIP Microsoft Zero Trust com limite de tamanho/volume, correspondência de tenant, remoção de identidade e evidência bruta e crosswalk por ID mais título.
- Adicionada apresentação opcional dos status Microsoft por pilar e seu vínculo temático com controles do engine. Nenhum score ou status foi combinado.
- Incluída a informação externa no HTML offline, XLSX, PDF e PPTX.
- Agrupada a navegação do HTML para reduzir a extensão da barra técnica e manter detalhes progressivos.
- Adicionada opção de importação aos wrappers Bash e PowerShell. O payload de IA continua a usar somente o assessment nativo minimizado/agregado.

## Guardrails mantidos

- Execução e coletores do tenant permanecem somente leitura.
- Importador lê arquivos locais e não autentica ou chama Microsoft APIs.
- Nenhuma remediação automática foi adicionada.
- O ZIP original e dados granulares não entram no payload de IA.
- Não houve commit.

## Uso

Ver [`ZERO-TRUST-IMPORT.md`](ZERO-TRUST-IMPORT.md) para comandos, correspondência de tenant, fluxo PowerShell/Cloud Shell e limites de privacidade.

## Validação

Os testes existentes foram alinhados à nova cobertura do domínio Compliance. Não foram executados testes nesta entrega.
