"""Proteções locais de diretórios de saída; não aplicam ACLs no tenant."""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_OUTPUT_ROOTS = {"runtime", "dist", "dist-shareable"}


def protect_output_directory(path: Path) -> None:
    """Aplica modo owner-only em saídas do projeto em POSIX, sem tocar fora dele."""
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        return
    if not relative.parts or relative.parts[0] not in PRIVATE_OUTPUT_ROOTS:
        return
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        resolved.chmod(0o700)


def protect_output_parent(file_path: Path) -> None:
    protect_output_directory(file_path.parent)
