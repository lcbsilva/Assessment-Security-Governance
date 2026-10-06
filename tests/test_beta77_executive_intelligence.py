from executive_intelligence import build


def test_executive_intelligence_separates_conditional_findings_from_actions():
    result = build([
        {"title": "Confirmed", "control_id": "SEC-001", "priority": "P1", "risk_score": 90, "effort": 2, "effort_band": "Baixo", "owner": "Security", "priority_eligibility": "eligible", "action_30_60_90": {"30": "Validar owner", "60": "Aplicar plano", "90": "Reavaliar"}},
        {"title": "Needs evidence", "control_id": "CMP-001", "priority": "P2", "risk_score": 95, "effort": 1, "owner": "Compliance", "priority_eligibility": "conditional_review", "priority_rationale": "Evidência insuficiente"},
    ])
    assert result["summary"]["confirmed_for_action"] == 1
    assert result["summary"]["conditional_review"] == 1
    assert result["summary"]["quick_wins"] == 1
    assert result["quick_wins"][0]["title"] == "Confirmed"
    assert result["conditional_reviews"][0]["title"] == "Needs evidence"
    assert all(item["finding"] != "Needs evidence" for actions in result["roadmap"].values() for item in actions)


def test_executive_intelligence_groups_workstreams_and_roadmap():
    result = build([
        {"title": "Identity", "control_id": "ID-001", "priority": "P2", "risk_score": 75, "effort": 3, "owner": "IAM", "priority_eligibility": "eligible", "action_30_60_90": {"30": "Planejar"}},
        {"title": "Governance", "control_id": "GOV-003", "priority": "P1", "risk_score": 88, "effort": 4, "owner": "Cloud", "priority_eligibility": "eligible", "action_30_60_90": {"60": "Executar"}},
    ])
    names = {item["name"] for item in result["workstreams"]}
    assert "Identity & Access" in names
    assert "Cloud Governance" in names
    assert result["roadmap"]["30"][0]["action"] == "Planejar"
    assert result["roadmap"]["60"][0]["action"] == "Executar"


def test_html_decision_layer_renders_executive_intelligence():
    from generate_report import render_decision_layer
    html = render_decision_layer({
        "metadata": {"evidence_quality": {"score": 90}, "evidence_by_control": []},
        "discovery": {"lifecycle": {"summary": {}}},
        "findings": [{
            "title": "Quick win security", "control_id": "SEC-001", "priority": "P1",
            "risk_score": 90, "effort": 2, "owner": "Security",
            "priority_eligibility": "eligible", "action_30_60_90": {"30": "Validar owner"},
        }],
    })
    assert "Quick wins confirmados" in html
    assert "Roadmap executivo 30 / 60 / 90" in html
    assert "Quick win security" in html
    assert "Revisões condicionais" in html
