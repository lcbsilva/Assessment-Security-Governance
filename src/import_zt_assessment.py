#!/usr/bin/env python3
"""Importa resultados resumidos do Zero Trust Assessment sem copiar PII/evidência bruta."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml
from local_privacy import protect_output_parent


ROOT = Path(__file__).resolve().parents[1]
STATUS_ALLOWLIST = {"Passed", "Failed", "Investigate", "Skipped", "Planned", "Error"}
RISK_ALLOWLIST = {"High", "Medium", "Low"}
PILLAR_ALLOWLIST = {"Identity", "Devices", "Network", "Data", "Infrastructure", "SecOps", "AI"}
MAX_SOURCE_BYTES = 25 * 1024 * 1024
MAX_TESTS = 10_000


def _read_report(path: Path) -> bytes:
    if path.suffix.lower() != ".zip":
        raw = path.read_bytes()
    else:
        with zipfile.ZipFile(path) as archive:
            candidates = [
                info for info in archive.infolist()
                if info.filename.lstrip("./").endswith("zt-export/ZeroTrustAssessmentReport.json")
            ]
            if len(candidates) != 1:
                raise ValueError("O ZIP precisa conter exatamente um ZeroTrustAssessmentReport.json em zt-export.")
            if candidates[0].file_size > MAX_SOURCE_BYTES:
                raise ValueError("O relatório JSON do ZIP excede o limite local de 25 MB.")
            raw = archive.read(candidates[0])
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("O relatório JSON excede o limite local de 25 MB.")
    return raw


def _normalized_title(value: object) -> str:
    return "".join(character for character in str(value or "").casefold() if character.isalnum())


def _strings(value: object, limit: int = 20) -> list[str]:
    values = value if isinstance(value, list) else [value]
    output = []
    for item in values:
        if item is None:
            continue
        clean = re.sub(r"\s+", " ", str(item)).strip()[:160]
        if clean and clean not in output:
            output.append(clean)
        if len(output) >= limit:
            break
    return output


def _pillars(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    normalized = []
    for item in values:
        if item is None:
            continue
        name = str(item).strip()
        if name in PILLAR_ALLOWLIST and name not in normalized:
            normalized.append(name)
    return normalized or ["Other"]


def _skip_category(value: object) -> str | None:
    if not value:
        return None
    text = str(value).casefold()
    if any(term in text for term in ("license", "licensed", "licensing")):
        return "Licença"
    if "not connected" in text or "disconnected" in text:
        return "Conexão de serviço ausente"
    if "not supported" in text or "capabilities not currently available" in text or "underconstruction" in text:
        return "Suporte ou implementação indisponível"
    if "no access" in text or "does not have access" in text:
        return "Acesso insuficiente"
    if "not applicable" in text:
        return "Não aplicável"
    return "Outro motivo reportado"


def _verify_tenant(source_tenant_id: object, base: dict, confirmed: bool) -> None:
    source_id = str(source_tenant_id or "").strip().casefold()
    metadata = base.get("metadata", {})
    base_id = str(metadata.get("tenant_id", "") or "").strip().casefold()
    masked = str(metadata.get("tenant_id_masked", "") or "").strip().casefold()
    prefix = re.sub(r"[^a-f0-9].*$", "", masked)
    if source_id and base_id:
        if source_id != base_id:
            raise ValueError("O tenant ID do relatório Microsoft não corresponde ao tenant do assessment base.")
        return
    if source_id and prefix and len(prefix) >= 8:
        if not source_id.startswith(prefix):
            raise ValueError("O prefixo de tenant do relatório Microsoft não corresponde ao assessment base.")
        return
    if not confirmed:
        raise ValueError("Não foi possível validar automaticamente o tenant. Confirme o mesmo tenant com --confirm-same-tenant.")


def build_import(source_data: dict, base: dict, crosswalk: dict, source_hash: str, confirmed_same_tenant: bool = False) -> dict:
    """Cria uma seção minimizada; deliberadamente ignora TenantInfo e TestResult."""
    _verify_tenant(source_data.get("TenantId"), base, confirmed_same_tenant)
    raw_tests = source_data.get("Tests")
    if not isinstance(raw_tests, list) or len(raw_tests) > MAX_TESTS:
        raise ValueError("O relatório não contém uma lista de testes suportada (limite: 10.000).")

    maps = crosswalk.get("tests", {})
    controls_by_id: dict[str, list[dict]] = {}
    tests = []
    pillars: dict[str, Counter] = defaultdict(Counter)
    overall = Counter()
    map_mismatches = 0

    for raw in raw_tests:
        if not isinstance(raw, dict):
            continue
        test_id = str(raw.get("TestId", "")).strip()[:40]
        title = re.sub(r"\s+", " ", str(raw.get("TestTitle", "Teste sem título"))).strip()[:240]
        status_raw = str(raw.get("TestStatus", "")).strip()
        status = next((item for item in STATUS_ALLOWLIST if item.casefold() == status_raw.casefold()), "Other")
        if status == "Other":
            status = "Investigate"
        test_pillars = _pillars(raw.get("TestPillar"))
        risk_raw = str(raw.get("TestRisk", "")).strip().title()
        risk = risk_raw if risk_raw in RISK_ALLOWLIST else "Unknown"
        mapping = maps.get(test_id, {})
        expected_title = _normalized_title(mapping.get("title")) if mapping else ""
        actual_title = _normalized_title(title)
        mapped_ids = list(mapping.get("control_ids", [])) if mapping and expected_title == actual_title else []
        if mapping and expected_title != actual_title:
            map_mismatches += 1

        row = {
            "test_id": test_id,
            "title": title,
            "pillars": test_pillars,
            "category": re.sub(r"\s+", " ", str(raw.get("TestCategory", ""))).strip()[:100],
            "status": status,
            "risk": risk,
            "minimum_license": _strings(raw.get("TestMinimumLicense")),
            "implementation_cost": _strings(raw.get("TestImplementationCost"), limit=4),
            "skip_category": _skip_category(raw.get("SkippedReason")) if status == "Skipped" else None,
            "mapped_control_ids": mapped_ids,
        }
        tests.append(row)
        overall[status] += 1
        for pillar in test_pillars:
            pillars[pillar][status] += 1
        for control_id in mapped_ids:
            controls_by_id.setdefault(control_id, []).append({
                "test_id": test_id,
                "title": title,
                "pillar": ", ".join(test_pillars),
                "status": status,
                "risk": risk,
                "minimum_license": row["minimum_license"],
            })

    pillar_rows = [
        {"name": name, "tests": sum(counts.values()), "statuses": dict(sorted(counts.items()))}
        for name, counts in sorted(pillars.items())
    ]
    imported = {
        "source": "Microsoft Zero Trust Assessment",
        "source_version": str(source_data.get("CurrentVersion", "unknown"))[:40],
        "executed_at": str(source_data.get("ExecutedAt", ""))[:80],
        "source_report_sha256": source_hash,
        "crosswalk_version": str(crosswalk.get("crosswalk_version", "unknown")),
        "score_combined": False,
        "privacy_minimized": True,
        "tests_total": len(tests),
        "status_counts": dict(sorted(overall.items())),
        "pillars": pillar_rows,
        "mapped_test_count": sum(1 for item in tests if item["mapped_control_ids"]),
        "unmapped_test_count": sum(1 for item in tests if not item["mapped_control_ids"]),
        "mapping_title_mismatch_count": map_mismatches,
        "mapped_controls": [
            {"control_id": control_id, "tests": rows}
            for control_id, rows in sorted(controls_by_id.items())
        ],
        "tests": sorted(tests, key=lambda item: (item["pillars"][0], item["test_id"])),
        "excluded_source_fields": ["TenantId", "TenantName", "Domain", "Account", "TenantInfo", "TestResult", "SkippedReason raw text"],
        "interpretation": "Referência externa. Os estados não alteram o score nativo do Assessment Engine; pilares e contagens podem se sobrepor.",
    }
    # Do not retain source identity fields or raw evidence. Only the minimized
    # test metadata above is added to the local assessment JSON.
    result = copy.deepcopy(base)
    discovery = result.setdefault("discovery", {})
    discovery.setdefault("external_assessments", {})["microsoft_zero_trust"] = imported
    result.setdefault("metadata", {}).setdefault("external_assessments", []).append({
        "source": imported["source"],
        "version": imported["source_version"],
        "executed_at": imported["executed_at"],
        "tests_total": imported["tests_total"],
        "score_combined": False,
    })
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Importa localmente um relatório Microsoft Zero Trust, sem copiar PII/evidência bruta")
    parser.add_argument("--source", required=True, type=Path, help="ZeroTrustAssessmentReport.json ou ZIP exportado")
    parser.add_argument("--data", required=True, type=Path, help="Assessment Engine JSON base")
    parser.add_argument("--output", required=True, type=Path, help="Contrato JSON combinado de saída")
    parser.add_argument("--confirm-same-tenant", action="store_true", help="Confirma manualmente que ambos os relatórios são do mesmo tenant quando os IDs mascarados não permitem validação automática")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    protect_output_parent(args.output)
    source_bytes = _read_report(args.source)
    source_data = json.loads(source_bytes.decode("utf-8"))
    base = json.loads(args.data.read_text(encoding="utf-8"))
    crosswalk = yaml.safe_load((ROOT / "catalog" / "zero_trust_crosswalk.yaml").read_text(encoding="utf-8")) or {}
    imported = build_import(source_data, base, crosswalk, hashlib.sha256(source_bytes).hexdigest(), args.confirm_same_tenant)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(imported, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = imported["discovery"]["external_assessments"]["microsoft_zero_trust"]
    print(json.dumps({
        "status": "imported_minimized",
        "source_version": summary["source_version"],
        "tests": summary["tests_total"],
        "mapped_tests": summary["mapped_test_count"],
        "unmapped_tests": summary["unmapped_test_count"],
        "title_mismatches": summary["mapping_title_mismatch_count"],
        "score_combined": False,
        "output": str(args.output),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
