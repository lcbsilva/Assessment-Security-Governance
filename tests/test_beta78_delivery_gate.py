import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from delivery_gate import assess


def _catalog():
    return yaml.safe_load((ROOT / "catalog" / "controls.yaml").read_text(encoding="utf-8"))


def _mock():
    return json.loads((ROOT / "mock" / "assessment.json").read_text(encoding="utf-8"))


def test_delivery_gate_accepts_complete_mock_contract():
    data = _mock()
    result = assess(data, _catalog(), {"status": "valid"})
    assert result["status"] == "ready_for_client_review"
    assert result["read_only"] is True
    assert result["blockers"] == []


def test_delivery_gate_warns_when_traceability_is_not_materialized_yet():
    data = _mock()
    data["metadata"]["evidence_by_control"] = []
    data.get("discovery", {}).pop("control_evidence", None)
    result = assess(data, _catalog(), {"status": "valid"})
    assert result["status"] == "ready_for_client_review"
    assert any("rastreabilidade" in item for item in result["warnings"])


def test_delivery_gate_blocks_invalid_artifacts_and_non_readonly():
    data = _mock()
    data["metadata"]["execution"] = {"mode": "write", "tenant_mutation": True}
    result = assess(data, _catalog(), {"status": "invalid"})
    assert result["status"] == "blocked"
    assert any("read-only" in item for item in result["blockers"])
    assert any("artefatos" in item for item in result["blockers"])


def test_delivery_gate_keeps_conditional_findings_as_warning_not_confirmed_action():
    data = _mock()
    if data.get("findings"):
        data["findings"][0]["evidence_state"] = "INSUFFICIENT_EVIDENCE"
        data["findings"][0]["control_confidence"] = "low"
    result = assess(data, _catalog(), {"status": "valid"})
    assert result["status"] == "ready_for_client_review"
    assert result["executive_summary"]["conditional_review"] >= 1
    assert any("condicionais" in item for item in result["warnings"])
