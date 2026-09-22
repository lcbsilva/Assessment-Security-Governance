#!/usr/bin/env python3
"""Pré-visualiza ou remove artefatos locais antigos em diretórios conhecidos."""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import yaml

from local_privacy import PROJECT_ROOT, PRIVATE_OUTPUT_ROOTS


def collect_old_files(roots: list[str], older_than_days: int) -> list[Path]:
    cutoff = time.time() - older_than_days * 86400
    found: list[Path] = []
    for name in roots:
        base = PROJECT_ROOT / name
        if base.is_symlink() or not base.exists():
            continue
        for current, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = [item for item in dirs if not (Path(current) / item).is_symlink()]
            for filename in files:
                path = Path(current) / filename
                if path.is_symlink():
                    continue
                try:
                    if path.stat().st_mtime < cutoff:
                        found.append(path)
                except OSError:
                    continue
    return sorted(found)


def main() -> None:
    parser = argparse.ArgumentParser(description="Pré-visualiza ou remove arquivos antigos do assessment")
    config = yaml.safe_load((PROJECT_ROOT / "config" / "assessment.yaml").read_text(encoding="utf-8")) or {}
    retention_default = int(config.get("privacy", {}).get("local_artifact_retention_days", 30))
    parser.add_argument("--older-than-days", type=int, default=retention_default, help=f"Idade mínima; padrão configurado: {retention_default} dias")
    parser.add_argument("--include-reports", action="store_true", help="Inclui dist/ e dist-shareable/ além de runtime/")
    parser.add_argument("--apply", action="store_true", help="Executa a remoção; sem esta opção somente lista os candidatos")
    args = parser.parse_args()
    if args.older_than_days < 1:
        parser.error("--older-than-days precisa ser pelo menos 1")
    roots = ["runtime"]
    if args.include_reports:
        roots.extend(["dist", "dist-shareable"])
    if not set(roots) <= PRIVATE_OUTPUT_ROOTS:
        parser.error("Raiz de saída não permitida")
    candidates = collect_old_files(roots, args.older_than_days)
    action = "Removidos" if args.apply else "Candidatos"
    if not candidates:
        print(f"{action}: nenhum arquivo com mais de {args.older_than_days} dia(s).")
        return
    for path in candidates:
        relative = path.relative_to(PROJECT_ROOT)
        size = path.stat().st_size
        print(f"{relative} · {size} bytes")
        if args.apply:
            path.unlink()
    if args.apply:
        for name in roots:
            base = PROJECT_ROOT / name
            if base.exists() and not base.is_symlink():
                for current, dirs, _ in os.walk(base, topdown=False, followlinks=False):
                    for directory in dirs:
                        target = Path(current) / directory
                        if not target.is_symlink():
                            try:
                                target.rmdir()
                            except OSError:
                                pass
        print(f"Remoção concluída · {len(candidates)} arquivo(s). A rotina não promete apagamento físico seguro do armazenamento.")
    else:
        print(f"Pré-visualização: {len(candidates)} arquivo(s). Acrescente --apply para remover os listados.")


if __name__ == "__main__":
    main()
