# Beta 64 — confidencialidade e ciclo de vida local

- Diretórios locais conhecidos de runtime e relatórios recebem permissão owner-only em POSIX; chamadas fora de `runtime/`, `dist/` e `dist-shareable/` não têm permissões alteradas pelo helper.
- Checkpoints são gravados atomicamente com modo restrito em POSIX e permanecem reutilizáveis para resume.
- `dist-shareable/` foi incluído no `.gitignore`.
- `src/cleanup_local.py` lista candidatos com mais que a retenção configurada (30 dias padrão); exclusão exige `--apply` e pode incluir relatórios somente com `--include-reports`.
- A limpeza não roda automaticamente e não promete apagamento físico seguro.
- No Windows, os artefatos herdam ACLs da conta; o runbook orienta guardar outputs em local privado.

Não foi executada remoção de arquivos durante esta sprint.
