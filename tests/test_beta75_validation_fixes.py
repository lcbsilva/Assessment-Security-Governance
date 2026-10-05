import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from collect_arg import enrich_policy_assignments, hygiene_summary
from score_normalized import derive


def test_beta75_legacy_auth_without_signin_evidence_is_insufficient():
    """CA policy não pode provar ausência de autenticação legada."""
    data = {
        "discovery": {
            "users": [],
            "conditional_access": [
                {
                    "display_name": "Block legacy authentication",
                    "state": "enabled",
                }
            ],
            "legacy_auth_summary": {},
        }
    }

    catalog = {
        "controls": [
            {
                "id": "ID-005",
                "license_gate": "not_required_or_not_declared",
            }
        ]
    }

    result = derive(data, catalog)
    control = next(
        item for item in result["controls"]
        if item["id"] == "ID-005"
    )

    assert control["status"] == "not_available"
    assert control["evidence_state"] == "INSUFFICIENT_EVIDENCE"
    assert control["score"] == 0


def test_beta75_resource_group_with_resources_is_not_empty():
    """Normalização de campos/case não pode gerar falso Empty RG."""
    resources = [
        {
            "subscription": "SUB-001",
            "resource_group": "NetworkWatcherRG",
            "name": "NetworkWatcher_brazilsouth",
        }
    ]

    resource_groups = [
        {
            "subscriptionId": "sub-001",
            "name": "networkwatcherrg",
            "location": "brazilsouth",
        },
        {
            "subscriptionId": "sub-001",
            "name": "rg-realmente-vazio",
            "location": "eastus",
        },
    ]

    result = hygiene_summary(
        resources,
        [],
        resource_groups,
        [],
    )

    empty_names = {
        item["name"].lower()
        for item in result["empty_resource_groups"]
    }

    assert "networkwatcherrg" not in empty_names
    assert "rg-realmente-vazio" in empty_names
    assert len(result["empty_resource_groups"]) == 1


def test_beta75_unresolved_policy_definition_is_not_classified_as_policy():
    """Definition desconhecida deve permanecer explicitamente unresolved."""
    assignments = [
        {
            "assignment": "ASC Default",
            "assignment_name": "SecurityCenterBuiltIn",
            "assignment_id": "/subscriptions/sub-001/providers/Microsoft.Authorization/policyAssignments/SecurityCenterBuiltIn",
            "definition_id": "/providers/Microsoft.Authorization/policySetDefinitions/unknown",
            "scope": "/subscriptions/sub-001",
            "scope_type": "Subscription",
            "enforcement_mode": "Default",
            "not_scopes": [],
            "parameters": [],
            "parameter_count": 0,
            "subscription": "sub-001",
        }
    ]

    result = enrich_policy_assignments(assignments, [])

    assert len(result) == 1
    assert result[0]["definition_resolved"] is False
    assert result[0]["definition_type"] == "Unresolved"
    assert result[0]["definition_display_name"] == "—"


def test_beta75_resolved_policy_set_is_identified():
    """PolicySet resolvido continua sendo identificado corretamente."""
    definition_id = (
        "/providers/Microsoft.Authorization/"
        "policySetDefinitions/test-initiative"
    )

    assignments = [
        {
            "assignment": "Test Initiative",
            "definition_id": definition_id,
            "parameters": [],
        }
    ]

    definitions = [
        {
            "id": definition_id,
            "name": "test-initiative",
            "displayName": "Test Initiative Definition",
            "type": "Microsoft.Authorization/policySetDefinitions",
            "parameters": {},
        }
    ]

    result = enrich_policy_assignments(assignments, definitions)

    assert result[0]["definition_resolved"] is True
    assert result[0]["definition_type"] == "PolicySet"
    assert result[0]["definition_display_name"] == "Test Initiative Definition"


def _id005_catalog():
    return {
        "controls": [
            {
                "id": "ID-005",
                "license_gate": "not_required_or_not_declared",
            }
        ]
    }


def test_legacy_auth_summary_without_reviewed_signins_is_insufficient_evidence():
    data = {
        "discovery": {
            "legacy_auth_summary": {
                "lookback_days": 30,
                "max_pages": 20,
                "signins_reviewed": 0,
                "legacy_signins": 0,
                "affected_users": 0,
            }
        }
    }

    result = derive(data, _id005_catalog())
    control = next(item for item in result["controls"] if item["id"] == "ID-005")

    assert control["status"] == "not_available"
    assert control["evidence_state"] == "INSUFFICIENT_EVIDENCE"
    assert control["score"] == 0
    assert control["confidence"] == "low"


def test_legacy_auth_reviewed_signins_without_legacy_auth_is_conformant():
    data = {
        "discovery": {
            "legacy_auth_summary": {
                "lookback_days": 30,
                "max_pages": 20,
                "signins_reviewed": 100,
                "legacy_signins": 0,
                "affected_users": 0,
            }
        }
    }

    result = derive(data, _id005_catalog())
    control = next(item for item in result["controls"] if item["id"] == "ID-005")

    assert control["status"] == "pass"
    assert control["evidence_state"] == "CONFORMANT"
    assert control["score"] == 95
    assert control["confidence"] == "high"
