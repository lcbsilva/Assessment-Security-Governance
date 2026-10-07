from cross_domain_intelligence import build


def test_correlates_identity_security_without_claiming_incident():
    discovery = {"security_identity_intelligence": {"identity_posture": {"privileged_without_mfa": 2}, "privileged_access": {"broad_scope_assignments": 3}}}
    result = build(discovery, [])
    assert result[0]["id"] == "XDI-001"
    assert result[0]["priority"] == "P1"
    assert "não prova comprometimento" in result[0]["interpretation"]


def test_finops_governance_correlation_is_not_realizable_savings():
    discovery = {"lifecycle_finops": {"signals": {"orphan_resources": 2, "advisor_recommendations": 4}, "optimization": {"rightsizing_candidates": 1, "anomaly_days": 2}}}
    result = build(discovery, [{"module": "cost", "status": "partial"}])
    ids = {item["id"] for item in result}
    assert {"XDI-002", "XDI-003"} <= ids
    assert all(item["limited_modules_present"] for item in result)
    assert "não representa economia realizável" in next(item for item in result if item["id"] == "XDI-002")["interpretation"]


def test_no_signal_no_invented_insight():
    assert build({}, []) == []
