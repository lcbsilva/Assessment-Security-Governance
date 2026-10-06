import sys
from pathlib import Path

# Permite importar os módulos do diretório src durante a execução isolada do teste.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from execution_health import coverage_map


def test_coverage_map_falls_back_to_collection_log_when_preflight_manifest_is_missing():
    logs = [
        {
            "module": "Azure Policy",
            "status": "success",
            "records": 36,
            "source": "PolicyResources / Azure Resource Graph",
            "note": "",
        },
        {
            "module": "Secure Score",
            "status": "not_available",
            "records": 0,
            "source": "Microsoft Graph",
            "note": "HTTP 403; SecurityEvents.Read.All",
        },
    ]

    result = coverage_map(logs, [])

    assert len(result) == 2

    policy = next(
        item
        for item in result
        if item["module"] == "Azure Policy"
    )
    assert policy["status"] == "success"
    assert policy["records"] == 36

    secure_score = next(
        item
        for item in result
        if item["module"] == "Secure Score"
    )
    assert secure_score["status"] == "not_available"
    assert secure_score["records"] == 0


def test_coverage_map_prefers_explicit_preflight_manifest_when_available():
    logs = [
        {
            "module": "Azure Policy",
            "status": "success",
            "records": 36,
            "source": "PolicyResources / Azure Resource Graph",
            "note": "",
        }
    ]

    manifest = [
        {
            "module": "Azure Policy",
            "domain": "governance",
            "expected_read_scope": "PolicyResources",
            "status": "ready",
        },
        {
            "module": "Secure Score",
            "domain": "security",
            "expected_read_scope": "Microsoft Graph",
            "status": "not_ready",
            "detail": "Permissão ausente",
        },
    ]

    result = coverage_map(logs, manifest)

    assert len(result) == 2
    assert {
        item["module"]
        for item in result
    } == {
        "Azure Policy",
        "Secure Score",
    }


def test_diagnostics_classify_http_403_as_permission():
    from module_diagnostics import diagnose

    result = diagnose(
        "PIM active assignments",
        "not_available",
        "HTTP 403; RoleAssignmentSchedule.Read.Directory",
    )

    assert result["limitation_category"] == "permission_or_role"


def test_diagnostics_classify_timeout_separately_from_throttling():
    from module_diagnostics import diagnose

    result = diagnose(
        "Sign-ins / legacy auth",
        "not_available",
        "TimeoutError: read operation timed out",
    )

    assert result["limitation_category"] == "timeout"


def test_diagnostics_classify_http_429_as_throttling():
    from module_diagnostics import diagnose

    result = diagnose(
        "Microsoft Graph",
        "not_available",
        "HTTP 429; too many requests",
    )

    assert result["limitation_category"] == "throttling"


def test_evidence_quality_keeps_aggregate_permission_taxonomy():
    from evidence_quality import classify

    assert (
        classify(
            "not_available",
            "HTTP 403; SecurityEvents.Read.All",
        )
        == "permission"
    )


def test_collection_pipeline_preserves_operational_diagnostics():
    """
    Garante que a função usada pelo pipeline preserve a taxonomia
    operacional detalhada de module_diagnostics.diagnose().
    """
    from run_assessment import apply_collection_diagnostics

    logs = [
        {
            "module": "PIM active assignments",
            "status": "not_available",
            "records": 0,
            "note": "HTTP 403; RoleAssignmentSchedule.Read.Directory",
        },
        {
            "module": "Sign-ins / legacy auth",
            "status": "not_available",
            "records": 0,
            "note": "TimeoutError: read operation timed out",
        },
        {
            "module": "Microsoft Graph",
            "status": "not_available",
            "records": 0,
            "note": "HTTP 429; too many requests",
        },
    ]

    apply_collection_diagnostics(logs)

    assert logs[0]["limitation_category"] == "permission_or_role"
    assert logs[1]["limitation_category"] == "timeout"
    assert logs[2]["limitation_category"] == "throttling"

    # O diagnóstico operacional deve também produzir orientação
    # consultiva para módulos que não puderam ser coletados.
    assert logs[0]["likely_cause"]
    assert logs[0]["next_step"]


def test_diagnostics_classify_not_configured_as_configuration():
    from module_diagnostics import diagnose

    result = diagnose(
        "Purview DLP policies",
        "not_available",
        "Integration not configured; Purview read-only adapter not provided.",
    )

    assert result["limitation_category"] == "configuration"


def test_diagnostics_classify_license_before_generic_permission_text():
    from module_diagnostics import diagnose

    result = diagnose(
        "Defender vulnerabilities",
        "not_available",
        "HTTP 403; license or entitlement unavailable; permission may be valid.",
    )

    assert result["limitation_category"] == "license_or_entitlement"



def test_m365_collector_declares_compliance_gaps_explicitly():
    from collect_m365_posture import collect

    result = collect(domains=[])
    logs = result["discovery"]["collection_log"]
    modules = {item["module"]: item for item in logs}

    for module in (
        "Purview DLP policies",
        "Purview sensitivity labels",
        "Purview retention policies",
    ):
        assert modules[module]["status"] == "not_available"
        assert modules[module]["records"] == 0
        assert "not configured" in modules[module]["note"].lower()


def test_m365_capability_manifest_maps_purview_controls():
    from collect_m365_posture import capability_manifest

    manifest = capability_manifest()
    mapping = {
        item["module"]: item.get("controls", [])
        for item in manifest
    }

    assert mapping["Purview DLP policies"] == ["CMP-001"]
    assert mapping["Purview sensitivity labels"] == ["CMP-002"]
    assert mapping["Purview retention policies"] == ["CMP-003"]



def test_graph_failure_notes_do_not_guess_license_on_permission_error():
    from collect_graph import graph_failure_note

    note = graph_failure_note(403, "SecurityIncident.Read.All")
    assert "403 Forbidden" in note
    assert "read-only" in note
    assert "licen" not in note.lower()


def test_graph_failure_note_400_avoids_permission_escalation():
    from collect_graph import graph_failure_note

    note = graph_failure_note(400, "Vulnerability.Read.All")
    assert "400 Bad Request" in note
    assert "endpoint" in note.lower()
    assert "entitlement" in note.lower()
    assert "antes de ampliar permissões" in note


def test_graph_failure_note_preserves_throttling_signal():
    from collect_graph import graph_failure_note

    note = graph_failure_note(429, "AuditLog.Read.All")
    assert "429 Too Many Requests" in note
    assert "throttling" in note.lower()
