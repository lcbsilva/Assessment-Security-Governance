# Comece aqui — teste do Assessment Engine 1.1.0

Obrigado por testar esta versão. A ideia deste teste é descobrir se outra pessoa consegue executar e interpretar o Assessment sem depender de quem desenvolveu a ferramenta.

## O que você vai testar

O Assessment Engine faz uma coleta **somente leitura** de sinais disponíveis no ambiente Microsoft/Azure, registra limitações de cobertura e gera artefatos técnicos e executivos. Ele não cria, altera, exclui nem remedia recursos no tenant.

Para uma primeira avaliação, o mais importante é observar se o fluxo é intuitivo e se o resultado ajuda uma consultoria: o que ficou claro, o que ficou confuso, o que faltou e o que pareceu desnecessário.

## Pré-requisitos

Use PowerShell 7, Python 3.10+ e Azure CLI. Você precisa estar autenticada em um tenant de teste/autorizado e possuir acesso de leitura suficiente para o escopo que pretende avaliar. Módulos opcionais podem aparecer como `partial` ou `not_available`; isso é esperado quando faltam licença, consentimento, retenção, configuração ou cobertura da API e **não significa conformidade**.

Clone o repositório e instale as dependências:

```powershell
git clone https://github.com/lcbsilva/Assessment-Security-Governance.git assessment-swo
cd assessment-swo
python -m pip install -r requirements.txt
az login
```

Confirme explicitamente onde está autenticada:

```powershell
az account show --query "{tenantId:tenantId,subscription:id,user:user.name}" -o json
```

Anote o `tenantId` e a subscription que você realmente está autorizada a testar. Não prossiga se o resultado mostrar outro tenant.

## Executar o teste

Use o fluxo guiado abaixo substituindo apenas os dois IDs pelos valores autorizados que você acabou de conferir:

```powershell
.\scripts\run-consultant-flow.ps1 -Subscriptions "<subscription-id>" -ExpectedTenantId "<tenant-id>" -Profile full
```

O runner bloqueia a execução se o tenant não for o esperado ou se a subscription informada não estiver visível naquele tenant. Depois executa readiness, coleta read-only, geração/validação dos artefatos, Delivery Gate e Release Gate.

## O que olhar no final

Comece por `dist/assessment.html`. Depois abra `dist/assessment-executive-summary.pdf`, `dist/assessment-executive-summary.pptx` e `dist/assessment-action-plan.xlsx`. Não é necessário compartilhar `runtime/assessment.json`, tokens, logs brutos ou payload de IA para dar feedback de experiência.

Se algum módulo ficar `partial` ou `not_available`, não tente conceder permissões extras apenas para fazer o teste ficar verde. Registre o que apareceu e continue se o próprio fluxo permitir.

## Feedback que eu gostaria de receber

Depois do teste, conte com suas palavras: se conseguiu começar sem ajuda; onde teve dúvida; se o relatório executivo faz sentido; quais informações foram mais úteis; o que sentiu falta; o que removeria; se confiaria em usar esse material como apoio em um assessment; e qualquer erro ou comportamento estranho que encontrou.

Se a execução parar, envie o texto do erro e diga em qual etapa ocorreu. Antes de compartilhar arquivos técnicos, confira se não contêm informações do tenant que não deveriam sair do ambiente.

> Este teste avalia produto, experiência e qualidade da entrega. O resultado não é certificação de conformidade e não autoriza mudanças no ambiente.
