# Entrega Beta 63 — progresso visível de execução

## O que mudou

- Wrappers Bash e PowerShell 7 mostram seis etapas numeradas e tempo decorrido desde o começo.
- O runner imprime progresso da coleta e do processamento, incluindo etapa atual do contrato.
- Cada coletor concluído informa status e duração; checkpoints gravados e retomados são identificados.
- A importação Microsoft aparece como etapa local opcional e continua fora do payload de IA.
- O progresso usa linhas simples para permanecer útil no Cloud Shell, console e logs redirecionados.

## Retomada

O resume continua condicionado ao mesmo perfil e conjunto de subscriptions. Checkpoints elegíveis são listados no começo; falhas e indisponibilidades totais são coletadas novamente. O contrato registra a lista de coletores retomados em `metadata.execution.resumed_collectors`.

## Guardrails

- Nenhum escopo ou permissão foi ampliado.
- Coletores permanecem read-only e a gravação de progresso ocorre somente nos arquivos locais de runtime.
- Nenhum dado do tenant é colocado nas mensagens de progresso além do status/duração de módulo já refletido no relatório.
- Não houve commit.

## Validação pendente

Foi feita validação sintática local. A experiência visual final precisa ser conferida no Cloud Shell Linux e no PowerShell 7 do laboratório; esta sprint não foi marcada como operacionalmente validada nesses ambientes.
