#!/usr/bin/env python3
"""Valida artefatos offline antes da entrega ao cliente."""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from html.parser import HTMLParser
from pathlib import Path


class StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.ids: set[str] = set()
        self.external_assets: list[str] = []
        self.inputs_without_label: list[str] = []
        self._labels: set[str] = set()
        self.anchor_targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = dict(attrs)
        self.tags.append(tag)
        if attrs_map.get("id"):
            self.ids.add(str(attrs_map["id"]))
        if tag == "a" and str(attrs_map.get("href", "")).startswith("#"):
            self.anchor_targets.append(str(attrs_map["href"])[1:])
        if tag in {"script", "link", "img"}:
            source = attrs_map.get("src") or attrs_map.get("href") or attrs_map.get("content")
            if source and (str(source).startswith("http://") or str(source).startswith("https://")):
                self.external_assets.append(str(source))
        if tag == "label" and attrs_map.get("for"):
            self._labels.add(str(attrs_map["for"]))
        if tag == "input" and attrs_map.get("id"):
            if str(attrs_map["id"]) not in self._labels:
                self.inputs_without_label.append(str(attrs_map["id"]))


def validate_html(path: Path) -> list[str]:
    errors: list[str] = []
    html = path.read_text(encoding="utf-8")
    parser = StructureParser()
    parser.feed(html)
    required_ids = {"executive-summary", "coverage", "discovery", "transparency"}
    missing = sorted(required_ids - parser.ids)
    if missing:
        errors.append(f"HTML sem seções obrigatórias: {', '.join(missing)}")
    if parser.external_assets:
        errors.append("HTML não é autocontido; possui assets externos")
    if not re.search(r'<html[^>]+lang=["\']pt-BR["\']', html, re.IGNORECASE):
        errors.append("HTML sem idioma pt-BR declarado")
    if len(re.findall(r"<h1\b", html, re.IGNORECASE)) != 1:
        errors.append("HTML deve possuir exatamente um h1")
    missing_targets = sorted(set(parser.anchor_targets) - parser.ids)
    if missing_targets:
        errors.append(f"Links internos sem destino: {', '.join(missing_targets)}")
    if parser.inputs_without_label:
        errors.append(f"Inputs sem label: {', '.join(parser.inputs_without_label)}")
    if "SoftwareOne" not in html:
        errors.append("Branding SoftwareOne ausente")
    return errors


def validate_zip(path: Path, required_parts: tuple[str, ...]) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            missing = [part for part in required_parts if part not in names]
            if missing:
                errors.append(f"{path.name} sem partes obrigatórias: {', '.join(missing)}")
            bad = archive.testzip()
            if bad:
                errors.append(f"{path.name} contém parte corrompida: {bad}")
    except (OSError, zipfile.BadZipFile) as exc:
        errors.append(f"{path.name} inválido: {type(exc).__name__}")
    return errors


def validate_payload(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Payload IA inválido: {type(exc).__name__}"]
    forbidden_keys = {"user_principal_name", "principal_id", "resource_id", "subscription_id", "tenant_id", "app_id", "ip_address", "secret", "token"}
    serialized = json.dumps(payload, ensure_ascii=False)
    if re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", serialized):
        errors.append("Payload IA contém padrão de e-mail")

    def walk(value: object, path_text: str = "payload") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in forbidden_keys:
                    errors.append(f"Payload IA contém campo proibido: {path_text}.{key}")
                walk(child, f"{path_text}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path_text}[{index}]")
    walk(payload)
    return sorted(set(errors))


def validate(output_dir: Path, ai_payload: Path | None = None) -> dict:
    pdf_path = output_dir / "assessment-executive-summary.pdf"
    checks = {
        "html": validate_html(output_dir / "assessment.html") if (output_dir / "assessment.html").exists() else ["assessment.html ausente"],
        "pdf": [] if pdf_path.exists() and pdf_path.read_bytes()[:4] == b"%PDF" and pdf_path.read_bytes().rstrip().endswith(b"%%EOF") else ["PDF ausente, sem assinatura ou incompleto"],
        "xlsx": validate_zip(output_dir / "assessment-action-plan.xlsx", ("[Content_Types].xml", "xl/workbook.xml")) if (output_dir / "assessment-action-plan.xlsx").exists() else ["XLSX ausente"],
        "pptx": validate_zip(output_dir / "assessment-executive-summary.pptx", ("[Content_Types].xml", "ppt/presentation.xml")) if (output_dir / "assessment-executive-summary.pptx").exists() else ["PPTX ausente"],
        "ai_payload": validate_payload(ai_payload) if ai_payload else [],
    }
    errors = [error for values in checks.values() for error in values]
    return {"status": "valid" if not errors else "invalid", "checks": checks, "errors": errors,
            "read_only": True, "note": "Validação local; nenhuma chamada ao tenant e nenhuma alteração de ambiente."}


def main() -> int:
    parser = argparse.ArgumentParser(description="Valida artefatos gerados sem acessar o tenant")
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--ai-payload", type=Path, default=Path("runtime/ai-payload.json"))
    parser.add_argument("--output", type=Path, default=Path("runtime/artifact-validation.json"))
    args = parser.parse_args()
    result = validate(args.output_dir, args.ai_payload if args.ai_payload.exists() else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
