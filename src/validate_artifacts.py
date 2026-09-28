#!/usr/bin/env python3
"""Valida artefatos offline antes da entrega ao cliente."""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from ai_payload import privacy_violations


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
    if "Não configurado" not in html and "N/D" not in html:
        errors.append("HTML não sinaliza domínios sem configuração ou score não disponível")
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
    errors.extend(f"Payload IA contém {item}" for item in privacy_violations(payload))
    return sorted(set(errors))


def validate(output_dir: Path, ai_payload: Path | None = None, assessment: Path | None = None) -> dict:
    pdf_path = output_dir / "assessment-executive-summary.pdf"
    brief_path = output_dir / "assessment-one-page-brief.pdf"
    brief_errors = []
    try:
        from pypdf import PdfReader
        if not brief_path.exists():
            brief_errors.append("Briefing PDF de uma página ausente")
        elif len(PdfReader(str(brief_path)).pages) != 1:
            brief_errors.append("Briefing executivo deve conter exatamente uma página")
    except Exception as exc:
        brief_errors.append(f"Briefing PDF não pôde ser validado: {type(exc).__name__}")
    contract_errors: list[str] = []
    if assessment is not None and assessment.exists():
        try:
            assessment_data = json.loads(assessment.read_text(encoding="utf-8"))
            if assessment_data.get("metadata", {}).get("contract_status") == "invalid":
                contract_errors.append("Assessment com metadata.contract_status=invalid")
        except (OSError, json.JSONDecodeError) as exc:
            contract_errors.append(f"Assessment não pôde ser lido: {type(exc).__name__}")
    checks = {
        "contract": contract_errors,
        "html": validate_html(output_dir / "assessment.html") if (output_dir / "assessment.html").exists() else ["assessment.html ausente"],
        "pdf": [] if pdf_path.exists() and pdf_path.read_bytes()[:4] == b"%PDF" and pdf_path.read_bytes().rstrip().endswith(b"%%EOF") else ["PDF ausente, sem assinatura ou incompleto"],
        "one_page_brief": brief_errors,
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
    parser.add_argument("--assessment", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("runtime/artifact-validation.json"))
    args = parser.parse_args()
    result = validate(args.output_dir, args.ai_payload if args.ai_payload.exists() else None, args.assessment)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
