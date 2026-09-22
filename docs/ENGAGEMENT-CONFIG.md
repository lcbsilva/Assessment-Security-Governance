# Configuração de engagement

O engine aceita metadados locais para personalizar os artefatos sem editar o código:

```bash
cp config/engagement.example.yaml config/engagement.yaml
python3 src/run_assessment.py --subscriptions "SUBSCRIPTION_ID" --profile full
```

Também é possível informar outro arquivo:

```bash
python3 src/run_assessment.py \
  --subscriptions "SUBSCRIPTION_ID" \
  --profile security \
  --engagement /caminho/engagement.yaml
```

Campos aceitos:

- `customer_name`: identificação apresentada nos relatórios;
- `engagement_name`: nome do assessment;
- `consultant_name`: papel ou consultor responsável;
- `classification`: classificação do artefato.

Guardrails:

- o arquivo é lido localmente;
- não altera subscriptions, permissões, coletores ou escopos;
- não concede autorização e não executa remediação;
- somente esses quatro campos são aceitos;
- os metadados de apresentação não são enviados ao payload agregado de IA;
- não armazene segredos, tokens, PATs, UPNs ou dados pessoais desnecessários nesse arquivo.

Se `config/engagement.yaml` não existir, o engine usa valores padrão seguros.
