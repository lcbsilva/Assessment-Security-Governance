# Plano de dogfooding interno

## Objetivo

Validar o engine em ambientes reais antes de qualquer piloto externo, sem tratar a execução interna como evidência comercial.

## Cada execução deve registrar

- data, versão do engine e versão do schema;
- tenant e escopo autorizados, sem publicar identificadores no relatório executivo;
- duração total e duração aproximada por módulo;
- quantidade de subscriptions, usuários, recursos e registros;
- cobertura de controles e qualidade da evidência;
- módulos `success`, `partial`, `not_available` e `error`;
- quantidade de retries e sinais de throttling;
- checkpoints utilizados e módulos retomados;
- divergências encontradas no Portal, Graph Explorer, ARG ou consoles oficiais;
- esforço do consultor e pontos de atrito;
- falso positivo, falso negativo ou achado que exigiu revisão;
- decisão: repetir, corrigir, aceitar limitação ou abrir defeito.

## Diversidade mínima

Priorizar pelo menos cinco ambientes distintos:

1. tenant pequeno com poucas subscriptions;
2. tenant com Microsoft 365 sem Defender completo;
3. tenant com Intune e Defender ativos;
4. tenant com Power Platform e workloads de dados;
5. tenant grande ou com histórico de throttling.

O tenant da SoftwareOne é importante para dogfooding, mas não deve ser a única referência: um ambiente bem governado não representa os modos de falha de clientes.

## Critério de saída para pilotos controlados

- três hardenings do núcleo concluídos: retomada, estados de evidência e gating de licença;
- pelo menos 10 execuções bem-sucedidas;
- pelo menos cinco tenants distintos;
- score determinístico em reexecuções equivalentes;
- zero defeitos P1 nas três últimas execuções;
- consultor executando ponta a ponta sem ajuda de engenharia;
- limitações exibidas na primeira camada executiva;
- pacote LGPD, retenção e responsabilidade revisado internamente.

## Critério de saída para uso comercial

Além dos critérios acima:

- metodologia de scoring publicada;
- matriz de permissões aprovada;
- teste em tenant grande concluído;
- procedimento de suporte definido;
- política de retenção e descarte dos artefatos definida;
- revisão de segurança e privacidade concluída;
- piloto controlado acompanhado e documentado.
