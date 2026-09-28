# Kit para demonstração interna e revisão do time

## Objetivo

Apresentar o Assessment Engine como ferramenta consultiva de discovery Azure/M365 e receber feedback sobre utilidade, cobertura, experiência e requisitos de segurança. Esta sessão não é aprovação para executar em clientes.

## Geração e arquivos

Se a pessoa já tiver acesso ao Git, primeiro clone o repositório e entre na
raiz do projeto:

```bash
git clone <URL_DO_REPOSITORIO> assessment-engine
cd assessment-engine
```

No PowerShell 7, na raiz do projeto:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
python -m pip install -r requirements.txt
.\scripts\run-beta-demo.ps1 -Scenario medium
```

Abra `dist/demo-package/assessment.html` no navegador. Use `small` para uma leitura rápida, `medium` para representar um ambiente intermediário, `limited` para explicar lacunas de evidência e `full` para percorrer um exemplo sintético mais completo. Para stress visual, use `large` com escala controlada. O pacote também inclui PDF executivo, briefing de uma página, PPTX, XLSX, guia e template de feedback.

## Roteiro sugerido — 30 minutos

1. **Contexto (3 min):** problema que o assessment resolve e fronteiras de escopo.
2. **Experiência executiva (7 min):** briefing de uma página e resumo HTML; explicar que cobertura é cobertura de controles e score pode ser provisório.
3. **Evidência e lacunas (8 min):** abrir mapa de módulos; diferenciar sucesso, parcial, indisponível e fora do perfil; revisar causas prováveis e próximos passos.
4. **Ação consultiva (7 min):** riscos, prioridades, owners sugeridos e plano 30/60/90; nenhuma ação é executada pelo engine.
5. **Feedback (5 min):** preencher `team-feedback-template.md` e indicar responsável/data para itens de seguimento.

## Mensagens de segurança

- A demonstração usa dados sintéticos e não comprova resultados de cliente.
- A coleta real é somente leitura; o engine não cria, altera, exclui ou remedia objetos.
- O HTML é offline/autocontido; artefatos reais podem conter dados confidenciais e devem circular apenas conforme classificação e política interna.
- Não inserir relatórios reais, UPNs, IDs, IPs, nomes de recursos ou dados de clientes em ferramentas de IA.
- A sessão recolhe opiniões; não solicita consentimento para tenant, concessão de permissões ou expansão de escopo.

## Perguntas para a revisão

- O resumo permite entender rapidamente escopo, score, cobertura e limitações?
- As causas prováveis estão claramente separadas de causas confirmadas?
- Que evidência ou domínio é indispensável para um primeiro piloto?
- Algum achado parece exagerado, ambíguo ou difícil de validar?
- Que permissões mínimas e processo de consentimento a equipe exige?
- Que artefato é mais útil: HTML, briefing, PPTX ou XLSX?
- Quais requisitos de confidencialidade, retenção e ownership devem ser formalizados?
