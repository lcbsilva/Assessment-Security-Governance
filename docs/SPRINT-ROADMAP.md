# Roadmap de sprints — Assessment Security & Governance

## Sprint atual — Qualidade e segurança do discovery

- [x] Barreira técnica permanente read-only.
- [x] PIM elegível versus ativo/permanente.
- [x] Usuários, convidados e inatividade com tratamento de dado desconhecido.
- [x] Enterprise Applications e App Registrations.
- [x] Defender e endpoints como módulos opcionais.
- [x] Priorização por risco, esforço e custo potencial.
- [ ] Validar consentimento de permissões em tenant de laboratório.

## Próxima sprint — Piloto controlado

- [x] Integrar recomendações ativas do Azure Advisor (categoria, impacto, recurso e economia quando publicada).
- [x] Exibir recomendações Advisor no HTML com fonte e status.
- [x] Ampliar RBAC com classificação de nível, escopo e herança não presumida.
- [x] Detalhar alertas e vulnerabilidades Defender quando disponíveis.
- [x] Criar matriz de priorização com risco, impacto, esforço e sinal financeiro.
- [x] Registrar histórico mínimo e comparar execuções automaticamente.
- [x] Expandir discovery para grupos, licenças M365 e custos por recurso.
- [x] Classificar qualidade da evidência por permissão, licença, throttling, suporte e execução.
- [x] Exibir score de qualidade e causa da limitação no dashboard e manifesto técnico.
- [x] Validar regressão automatizada com 22 testes e pacote sem caches.

- Validar execução com uma subscription de laboratório e um tenant M365 de teste.
- Comparar amostras do relatório com Portal, Graph Explorer e Azure Resource Graph.
- Registrar cobertura por módulo, tempo de coleta, erros e limitações.
- Ajustar regras de falso positivo antes de apresentar a clientes.

## Sprint seguinte — Produto para consultoria

- Histórico de execuções e comparação de tendência.
- Benchmark anônimo por vertical somente com consentimento e dados agregados.
- Branding configurável por oferta, sem alterar o núcleo técnico.
- Exportação de evidências para workshop e plano de ação.
- Pipeline CI com testes, lint, validação do contrato e verificação de read-only.

## Critério de aceite

O assessment só pode ser considerado pronto para piloto quando todos os módulos
indisponíveis continuarem em `not_available`/`partial`, nenhum coletor usar método
de escrita no tenant e cada recomendação tiver evidência, limitação e owner.
