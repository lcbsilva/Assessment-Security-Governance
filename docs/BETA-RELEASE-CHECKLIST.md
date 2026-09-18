# Checklist de fechamento da Beta 1.0

## Gate técnico local

- [ ] Código compila em Python suportado.
- [ ] Testes automatizados passam.
- [ ] Cenários `small`, `limited` e `full` passam.
- [ ] HTML é autocontido e abre offline.
- [ ] PDF, PPTX e XLSX são válidos.
- [ ] Payload de IA não contém PII, IDs ou segredos.
- [ ] Guardrails read-only permanecem ativos.

## Gate operacional

- [ ] Readiness Gate executado antes do tenant.
- [ ] Subscription e tenant foram confirmados.
- [ ] Reader aplicado somente ao escopo autorizado.
- [ ] Permissões Graph opcionais foram aprovadas separadamente.
- [ ] Resultado `not_available`/`partial` foi preservado.
- [ ] Tempo e throttling foram registrados.
- [x] Checkpoints são atômicos; falhas e indisponibilidade total não são reutilizadas.
- [x] Duração e tentativa ficam registradas por coletor.
- [ ] Artefatos foram gerados localmente.

## Gate consultivo

- [ ] Achados possuem evidência e limitação.
- [ ] Cada achado possui owner e ação 30/60/90.
- [ ] Nenhum achado é apresentado como incidente sem investigação.
- [ ] Recomendações são validadas pelo owner antes de qualquer mudança.

O `release_gate.py` valida automaticamente o gate técnico. O gate operacional e consultivo dependem do piloto autorizado e da revisão humana.
