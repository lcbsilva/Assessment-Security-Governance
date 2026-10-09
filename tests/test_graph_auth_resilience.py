import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_graph import collect


class GraphAuthenticationResilienceTests(unittest.TestCase):
    def test_graph_collection_preserves_null_optional_fields_and_empty_success(self):
        import io
        import json

        user = {
            "id": "user-1",
            "displayName": "Synthetic User",
            "userPrincipalName": "synthetic@example.invalid",
            "userType": None,
            "accountEnabled": True,
            "signInActivity": None,
        }
        payloads = {
            "/users?": {"value": [user]},
            "/reports/authenticationMethods": {
                "value": [{
                    "userPrincipalName": user["userPrincipalName"],
                    "isMfaRegistered": False,
                    "methodsRegistered": None,
                }]
            },
            "/identity/conditionalAccess/policies": {
                "value": [{
                    "displayName": "Synthetic policy",
                    "state": "enabled",
                    "conditions": {"users": {
                        "includeUsers": None, "excludeUsers": None,
                        "excludeGroups": None, "excludeRoles": None,
                    }},
                    "grantControls": {"builtInControls": None},
                }]
            },
            "/groups?": {"value": [{
                "displayName": "Synthetic group",
                "groupTypes": None,
            }]},
        }

        def response_for(request, timeout=None):
            url = request.full_url
            payload = next(
                (value for marker, value in payloads.items() if marker in url),
                {"value": []},
            )
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        with patch("azure.identity.AzureCliCredential") as credential_type, patch(
            "urllib.request.urlopen", side_effect=response_for
        ):
            credential_type.return_value.get_token.return_value = SimpleNamespace(
                token="synthetic-token"
            )
            result = collect()

        discovery = result["discovery"]
        self.assertEqual(result["metadata"]["modules"]["identity"], "success")
        self.assertEqual(result["metadata"]["modules"]["security"], "success")
        self.assertEqual(discovery["users"][0]["account_type"], "Unknown")
        self.assertEqual(discovery["users"][0]["mfa_methods"], "—")
        self.assertEqual(discovery["conditional_access"][0]["excluded"], 0)
        self.assertEqual(discovery["groups"][0]["group_type"], "Security/M365")
        self.assertTrue(all(
            item["status"] == "success"
            for item in discovery["collection_log"]
        ))

    def test_graph_domain_status_uses_endpoint_states_not_record_counts(self):
        from collect_graph import aggregate_graph_status

        endpoints = {"Identity", "MFA"}
        self.assertEqual(aggregate_graph_status([
            {"module": "Identity", "status": "success", "records": 0},
            {"module": "MFA", "status": "success", "records": 0},
        ], endpoints), "success")
        self.assertEqual(aggregate_graph_status([
            {"module": "Identity", "status": "success", "records": 2},
            {"module": "MFA", "status": "not_available", "records": 0},
        ], endpoints), "partial")
        self.assertEqual(aggregate_graph_status([
            {"module": "Identity", "status": "not_available", "records": 0},
            {"module": "MFA", "status": "not_available", "records": 0},
        ], endpoints), "not_available")

    def test_401_stops_redundant_graph_requests_and_records_skipped_modules(self):
        unauthorized = urllib.error.HTTPError(
            "https://graph.microsoft.com/v1.0/users",
            401,
            "Unauthorized",
            None,
            None,
        )
        with patch("azure.identity.AzureCliCredential") as credential_type, patch(
            "urllib.request.urlopen", side_effect=unauthorized
        ) as urlopen:
            credential_type.return_value.get_token.return_value = SimpleNamespace(
                token="test-token"
            )
            result = collect()

        self.assertEqual(urlopen.call_count, 1)
        logs = result["discovery"]["collection_log"]
        self.assertGreater(len(logs), 1)
        self.assertIn("HTTP 401", logs[0]["note"])
        self.assertTrue(all(log["status"] == "not_available" for log in logs))
        self.assertTrue(
            all("Consulta não executada" in log["note"] for log in logs[1:])
        )


if __name__ == "__main__":
    unittest.main()
