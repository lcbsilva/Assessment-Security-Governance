import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_graph import collect, profile_allows_module


class GraphAuthenticationResilienceTests(unittest.TestCase):
    def test_governance_profile_allows_only_entra_pim_graph_endpoints(self):
        self.assertTrue(profile_allows_module("governance", "PIM active assignments"))
        self.assertTrue(profile_allows_module("governance", "PIM eligible assignments"))
        self.assertTrue(profile_allows_module("governance", "Directory roles"))
        self.assertFalse(profile_allows_module("governance", "Identity"))
        self.assertFalse(profile_allows_module("governance", "MFA"))
        self.assertFalse(profile_allows_module("governance", "Defender alerts"))
        self.assertTrue(profile_allows_module("security", "Identity"))
        self.assertTrue(profile_allows_module("full", "Defender alerts"))

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
            "/directoryRoles": {"value": [{
                "id": "role-1",
                "displayName": "Global Administrator",
            }]},
        }

        def response_for(request, timeout=None):
            url = request.full_url
            if "/directoryRoles/role-1/members" in url:
                from urllib.error import HTTPError
                raise HTTPError(url, 403, "Forbidden", {}, None)
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
        self.assertEqual(result["metadata"]["modules"]["identity"], "partial")
        self.assertEqual(result["metadata"]["modules"]["security"], "success")
        self.assertEqual(discovery["users"][0]["account_type"], "Unknown")
        self.assertEqual(discovery["users"][0]["mfa_methods"], "—")
        self.assertEqual(discovery["conditional_access"][0]["excluded"], 0)
        self.assertEqual(discovery["groups"][0]["group_type"], "Security/M365")
        role_member_log = next(
            item for item in discovery["collection_log"]
            if item["module"] == "Role members: Global Administrator"
        )
        self.assertEqual(role_member_log["status"], "not_available")
        self.assertIn("HTTP 403", role_member_log["note"])

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



    def test_repeated_next_link_stops_and_preserves_partial_evidence(self):
        import io
        import json

        requested = []
        first = "https://graph.microsoft.com/v1.0/users?page=2"

        def response_for(request, timeout=None):
            url = request.full_url
            requested.append(url)
            if "/users?" in url and "page=2" not in url:
                payload = {"value": [{"id": "user-1", "displayName": "User 1", "userPrincipalName": "u1@example.invalid", "userType": "Member", "accountEnabled": True}], "@odata.nextLink": first}
            elif url == first:
                payload = {"value": [{"id": "user-2", "displayName": "User 2", "userPrincipalName": "u2@example.invalid", "userType": "Member", "accountEnabled": True}], "@odata.nextLink": first}
            else:
                payload = {"value": []}
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        with patch("azure.identity.AzureCliCredential") as credential_type, patch(
            "urllib.request.urlopen", side_effect=response_for
        ):
            credential_type.return_value.get_token.return_value = SimpleNamespace(token="test-token")
            result = collect()

        identity = next(item for item in result["discovery"]["collection_log"] if item["module"] == "Identity")
        self.assertEqual(identity["status"], "partial")
        self.assertEqual(identity["records"], 2)
        self.assertIn("repetiu o nextLink", identity["note"])
        self.assertEqual(requested.count(first), 1)

    def test_graph_next_link_host_is_validated_before_bearer_token_is_sent(self):
        import io
        import json

        requested = []

        def response_for(request, timeout=None):
            url = request.full_url
            requested.append(url)
            if "/users?" in url:
                payload = {"value": [], "@odata.nextLink": "https://unexpected.example/collect"}
            else:
                payload = {"value": []}
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        with patch("azure.identity.AzureCliCredential") as credential_type, patch(
            "urllib.request.urlopen", side_effect=response_for
        ):
            credential_type.return_value.get_token.return_value = SimpleNamespace(token="test-token")
            result = collect()

        identity = next(item for item in result["discovery"]["collection_log"] if item["module"] == "Identity")
        self.assertEqual(identity["status"], "partial")
        self.assertIn("host Microsoft Graph esperado", identity["note"])
        self.assertNotIn("https://unexpected.example/collect", requested)

    def test_graph_page_budget_stops_and_preserves_partial_evidence(self):
        import io
        import json

        requested = []

        def response_for(request, timeout=None):
            url = request.full_url
            requested.append(url)
            if "/users?" in url and "page=2" not in url:
                payload = {"value": [{"id": "user-1", "displayName": "User 1", "userPrincipalName": "u1@example.invalid", "userType": "Member", "accountEnabled": True}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2"}
            elif "page=2" in url:
                payload = {"value": [{"id": "user-2", "displayName": "User 2", "userPrincipalName": "u2@example.invalid", "userType": "Member", "accountEnabled": True}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=3"}
            else:
                payload = {"value": []}
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        with patch.dict("os.environ", {"ASSESSMENT_GRAPH_MAX_PAGES": "2"}), patch(
            "azure.identity.AzureCliCredential"
        ) as credential_type, patch("urllib.request.urlopen", side_effect=response_for):
            credential_type.return_value.get_token.return_value = SimpleNamespace(token="test-token")
            result = collect()

        identity = next(item for item in result["discovery"]["collection_log"] if item["module"] == "Identity")
        self.assertEqual(identity["status"], "partial")
        self.assertEqual(identity["records"], 2)
        self.assertIn("Limite de 2 páginas", identity["note"])
        self.assertNotIn("https://graph.microsoft.com/v1.0/users?page=3", requested)

if __name__ == "__main__":
    unittest.main()
