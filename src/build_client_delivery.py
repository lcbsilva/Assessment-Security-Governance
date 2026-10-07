#!/usr/bin/env python3
"""Monta pacote de entrega ao cliente somente a partir de artefatos validados."""
from __future__ import annotations
import argparse, hashlib, json, shutil
from pathlib import Path

ALLOWED = {
    "assessment.html", "assessment.pdf", "assessment.pptx", "assessment.xlsx",
    "assessment-one-page-brief.pdf",
}

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def build(dist: Path, runtime: Path, output: Path) -> dict:
    gate_path = runtime / "delivery-gate.json"
    if not gate_path.exists():
        raise RuntimeError("Delivery Gate ausente; pacote de cliente não será criado.")
    gate = json.loads(gate_path.read_text(encoding="utf-8"))
    if gate.get("status") != "ready_for_client_review":
        raise RuntimeError("Delivery Gate não aprovou a revisão de cliente.")
    output.mkdir(parents=True, exist_ok=True)
    files = []
    for name in sorted(ALLOWED):
        source = dist / name
        if source.exists():
            target = output / name
            shutil.copy2(source, target)
            files.append({"name": name, "sha256": digest(target), "bytes": target.stat().st_size})
    if not files:
        raise RuntimeError("Nenhum artefato de cliente permitido foi encontrado.")
    manifest = {
        "package_type": "client_delivery_review",
        "branding": "SoftwareOne",
        "delivery_gate_status": gate.get("status"),
        "files": files,
        "excluded_by_design": ["assessment.json", "ai-payload.json", "collection logs", "tokens", "credentials", "raw runtime evidence"],
        "guardrail": "Pacote para revisão de entrega; limitações e evidências do relatório permanecem autoritativas. Não implica conformidade nem aprovação de mudanças.",
    }
    (output / "delivery-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--dist", type=Path, default=Path("dist"))
    p.add_argument("--runtime", type=Path, default=Path("runtime"))
    p.add_argument("--output", type=Path, default=Path("client-delivery"))
    a=p.parse_args()
    print(json.dumps(build(a.dist,a.runtime,a.output), ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
