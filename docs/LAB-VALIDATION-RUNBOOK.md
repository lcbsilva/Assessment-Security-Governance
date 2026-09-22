# Runbook de validação no tenant de laboratório

O piloto controlado executa os três perfis do engine em sequência:

```bash
./scripts/run-lab-validation.sh "SUBSCRIPTION_ID"
```

No PowerShell:

```powershell
.\scripts\run-lab-validation.ps1 -Subscriptions "SUBSCRIPTION_ID"
```

Saídas:

- `runtime/lab-validation/security/`;
- `runtime/lab-validation/governance/`;
- `runtime/lab-validation/full/`;
- `runtime/lab-validation/summary.json`;
- `dist/lab-validation/<perfil>/` com HTML, PDF, PPTX e XLSX.

O script executa somente chamadas de leitura. Cada perfil passa por Readiness Gate,
coleta, renderização, validação de artefatos, manifesto SHA-256 e validação do piloto.
Módulos sem permissão, licença ou suporte continuam como `not_available`/`partial`.

Critérios para revisão interna:

1. `summary.json` confirma `read_only: true`;
2. cada perfil possui `artifact_integrity: valid`;
3. limitações são revisadas antes de interpretar o score;
4. amostras são comparadas com Portal Azure, Microsoft Graph e Resource Graph;
5. nenhum achado é tratado como incidente sem investigação adicional.

O `summary.json` também consolida:

- `overall_status`: `pass`, `warning`, `blocked` ou `not_run`;
- `profiles.<perfil>.readiness`: decisão operacional do perfil;
- cobertura, score, módulos indisponíveis, parciais, não executados, warnings e erros.

`warning` exige revisão consultiva; `blocked` impede tratar o pacote como pronto para
revisão do piloto; `not_run` significa que o perfil não foi executado e não representa
conformidade nem falha no tenant.
