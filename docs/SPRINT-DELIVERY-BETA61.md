# Entrega das quatro sprints — Beta 61

## Sprint 1 — Confiabilidade e segurança da coleta

- O modo read-only documenta operações por semântica, não apenas por verbo HTTP.
- O POST de Cost Management é aceito somente para a operação `query` HTTPS no
  host `management.azure.com`, com contrato mínimo de consulta.
- O Release Gate inspeciona chamadas explícitas e falha para métodos de escrita
  fora da allowlist.
- `listKeys`, segredos e connection strings ficam explicitamente fora dos
  coletores e da camada de IA.

**Aceite técnico:** a allowlist de consulta passa; chamadas fora dela são
recusadas antes de qualquer requisição de rede; o gate local permanece
read-only.

## Sprint 2 — Qualidade dos dados e do score

- `small`, `limited`, `full` e `large` recalculam controles, achados, score e
  cobertura a partir das evidências sintéticas que realmente contêm.
- Escopo sintético acompanha as quantidades de registros produzidos.
- O cenário `limited` remove dados herdados de módulos simulados como
  indisponíveis, evitando que o score trate evidência antiga como atual.
- Textos de exclusão do Conditional Access, como `2 break-glass`, são
  interpretados sem interromper a geração do relatório.
- Sem controles avaliados, o score geral é `N/D`; a cobertura continua em 0%.

**Aceite técnico:** cenários têm score/cobertura derivados dos dados e o
contrato sintético passa na validação. Reconciliação de resultados reais com o
Portal, Graph e Resource Graph permanece uma atividade humana do piloto.

## Sprint 3 — Relatório e utilidade consultiva

- O resumo executivo diferencia score calculado de ausência de evidência.
- Achados derivados dos cenários são reordenados com justificativa, confiança e
  sinal financeiro conservador.
- A validação do payload agregado detecta chaves de identidade camelCase,
  emails, UUIDs, IPs e caminhos de recursos Azure.
- A IA continua sem chamada externa; somente o payload agregado local é gerado.

**Aceite técnico:** o payload sintético passa na validação; identificadores
plantados são rejeitados; o score indisponível aparece como `N/D`.

## Sprint 4 — Operação do piloto

- O runbook descreve diagnóstico, perfil de segurança, wrapper Cloud Shell,
  artefatos, confidencialidade e uso de saída pseudonimizada para compartilhar.
- A matriz de permissões documenta as operações de consulta permitidas e
  confirma que `listKeys` não faz parte dos coletores.
- Os gates técnicos são descritos separadamente de autorização, revisão humana
  e reconciliação de evidências.

**Aceite operacional:** outro consultor consegue preparar, executar e revisar
um piloto de laboratório seguindo a documentação. Um piloto de cliente exige
autorização e validação consultiva próprias.

## Demonstração interna

Usar `python src/build_demo_package.py --scenario full --output-root
runtime/demo-internal` para gerar a demonstração offline. Identificar os dados
como sintéticos e não apresentar esse pacote como evidência de cliente. O
relatório técnico de uma execução real deve permanecer confidencial; compartilhar
somente a cópia pseudonimizada depois de validar seu manifesto.
