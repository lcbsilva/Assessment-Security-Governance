"""Versão única do engine para metadados, relatórios e artefatos."""

from pathlib import Path


def engine_version() -> str:
    return (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()

