# Guardrails da camada de IA

A IA é opcional e só pode receber o payload produzido por `src/ai_payload.py`.
Esse payload contém contagens e métricas agregadas, status dos módulos, riscos
por domínio e limitações. Ele não contém UPN, nome de usuário, nome de recurso,
ID, e-mail, evidência textual ou conteúdo bruto do tenant.

O modelo pode ajudar a escrever resumo executivo e organizar recomendações, mas
não pode:

- afirmar que ocorreu um incidente sem evidência de incidente;
- identificar ou atribuir culpa a uma pessoa;
- recomendar exclusão ou alteração automática;
- transformar ausência de dados em conformidade;
- substituir a evidência técnica ou a validação do owner.

Toda saída gerada deve ser marcada como conteúdo assistido por IA, revisada
quando fizer parte de uma entrega ao cliente e acompanhada do run ID e das
limitações da coleta.
