import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import json
from ai_advisory import run


def test_ai_advisor_structures_approved_output_without_score_mutation():
    payload = {"finding_count": 2, "limitations": ["aggregated only"]}
    raw = json.dumps({"executive_summary": "Resumo", "attention_points": ["A", "B"], "consultant_questions": ["Validar owner?"]})
    result = run(payload, enabled=True, transport=lambda _: raw)
    assert result["status"] == "completed"
    assert result["advisory"]["executive_summary"] == "Resumo"
    assert result["advisory"]["attention_points"] == ["A", "B"]
    assert result["score_mutation_allowed"] is False


def test_ai_advisor_keeps_text_transport_backward_compatible():
    result = run({"finding_count": 1}, enabled=True, transport=lambda _: "Resumo simples")
    assert result["status"] == "completed"
    assert result["summary"] == "Resumo simples"
    assert result["advisory"]["attention_points"] == []
