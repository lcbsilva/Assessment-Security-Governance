import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_rbac import ASSIGNMENTS_QUERY, ROLES_QUERY, collect, query_all_pages, query_arg_with_retry


class QueryRequest:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class QueryRequestOptions:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class Response:
    def __init__(self, data, skip_token=None):
        self.data = data
        self.skip_token = skip_token
        self.result_truncated = False


class FakeClient:
    def __init__(self, role_failure=False, empty_assignments=False, missing_roles=False):
        self.role_failure = role_failure
        self.empty_assignments = empty_assignments
        self.missing_roles = missing_roles
        self.calls = []

    def resources(self, request):
        self.calls.append(request)
        if "roleassignments" in request.query.lower():
            if self.empty_assignments:
                return Response([])
            if request.options.skip_token is None:
                return Response([{
                    "principalId": "user-1",
                    "principalType": "User",
                    "roleDefinitionId": "owner-id",
                    "assignmentScope": "/subscriptions/sub-1",
                    "subscriptionId": "sub-1",
                }], skip_token="page-2")
            return Response([{
                "principalId": "user-2",
                "principalType": "ServicePrincipal",
                "roleDefinitionId": "owner-id",
                "assignmentScope": "/subscriptions/sub-1/resourceGroups/rg-1",
                "subscriptionId": "sub-1",
            }])
        if self.role_failure:
            raise RuntimeError("role definitions unavailable")
        if self.missing_roles:
            return Response([])
        return Response([{"roleDefinitionId": "owner-id", "roleName": "Owner"}])


def fake_azure_modules(client):
    azure = types.ModuleType("azure")
    azure.__path__ = []
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = lambda **kwargs: object()
    mgmt = types.ModuleType("azure.mgmt")
    mgmt.__path__ = []
    resourcegraph = types.ModuleType("azure.mgmt.resourcegraph")
    resourcegraph.ResourceGraphClient = lambda credential: client
    models = types.ModuleType("azure.mgmt.resourcegraph.models")
    models.QueryRequest = QueryRequest
    models.QueryRequestOptions = QueryRequestOptions
    return {
        "azure": azure,
        "azure.identity": identity,
        "azure.mgmt": mgmt,
        "azure.mgmt.resourcegraph": resourcegraph,
        "azure.mgmt.resourcegraph.models": models,
    }


class RbacArgPaginationTests(unittest.TestCase):

    def test_transient_arg_throttling_is_retried(self):
        class ThrottledClient:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                if self.calls == 1:
                    error = RuntimeError("throttled")
                    error.status_code = 429
                    raise error
                return Response([{"ok": True}])

        client = ThrottledClient()
        with patch("collect_rbac.time.sleep") as sleep:
            response = query_arg_with_retry(client, object(), attempts=3)
        self.assertEqual(response.data, [{"ok": True}])
        self.assertEqual(client.calls, 2)
        sleep.assert_called_once_with(1)

    def test_collect_paginates_assignments_and_logs_complete_count(self):
        client = FakeClient()
        with patch.dict(sys.modules, fake_azure_modules(client)):
            result = collect(["sub-1"])
        self.assertEqual(len(result["discovery"]["rbac"]), 2)
        self.assertEqual([call.options.skip_token for call in client.calls[:2]], [None, "page-2"])
        self.assertTrue(all(call.options.top == 1000 for call in client.calls))
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "success")
        self.assertEqual(result["discovery"]["collection_log"][0]["records"], 2)
        self.assertEqual(result["metadata"]["modules"]["governance"], "success")
        self.assertEqual(result["discovery"]["rbac"][0]["access_risk"], "Crítico")

    def test_role_definition_failure_preserves_assignments_as_partial(self):
        client = FakeClient(role_failure=True)
        with patch.dict(sys.modules, fake_azure_modules(client)):
            result = collect(["sub-1"])
        self.assertEqual(len(result["discovery"]["rbac"]), 2)
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "partial")
        self.assertIn("classificação de funções incompletos", result["discovery"]["collection_log"][0]["note"])
        self.assertEqual(result["metadata"]["modules"]["governance"], "partial")


    def test_unresolved_role_is_not_labeled_moderate(self):
        client = FakeClient(missing_roles=True)
        with patch.dict(sys.modules, fake_azure_modules(client)):
            result = collect(["sub-1"])
        row = result["discovery"]["rbac"][0]
        self.assertEqual(row["access_risk"], "Não classificado")
        self.assertIn("não foi resolvida", row["review_reason"])
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "partial")
        self.assertIn("2 atribuições", result["discovery"]["collection_log"][0]["note"])

    def test_missing_subscription_scope_is_not_reported_as_success(self):
        with patch.dict(sys.modules, fake_azure_modules(FakeClient())):
            result = collect([])
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "not_available")
        self.assertEqual(result["discovery"]["rbac"], [])

    def test_empty_assignment_result_can_be_a_verified_zero(self):
        client = FakeClient(empty_assignments=True, role_failure=True)
        with patch.dict(sys.modules, fake_azure_modules(client)):
            result = collect(["sub-1"])
        self.assertEqual(result["discovery"]["rbac"], [])
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "success")

    def test_repeated_skip_token_stops_pagination_with_partial_rows(self):
        class RepeatingClient:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                return Response([{"row": self.calls}], skip_token="same-token")

        client = RepeatingClient()
        rows, error = query_all_pages(client, "query", ["sub-1"], QueryRequest, QueryRequestOptions)
        self.assertEqual(len(rows), 2)
        self.assertIn("repetiu o skip_token", error)
        self.assertEqual(client.calls, 2)



    def test_rbac_queries_order_pages_by_unique_resource_id(self):
        import collect_rbac as rbac_collector

        self.assertIn("| order by id asc", rbac_collector.ASSIGNMENTS_QUERY.lower())
        self.assertIn("| order by id asc", rbac_collector.ROLES_QUERY.lower())


    def test_truncated_assignment_response_without_skip_token_is_partial(self):
        class TruncatedClient:
            def resources(self, request):
                if "roleassignments" in request.query.lower():
                    response = Response([{
                        "principalId": "user-1",
                        "principalType": "User",
                        "roleDefinitionId": "owner-id",
                        "assignmentScope": "/subscriptions/sub-1",
                        "subscriptionId": "sub-1",
                    }])
                    response.result_truncated = True
                    return response
                return Response([{"roleDefinitionId": "owner-id", "roleName": "Owner"}])

        with patch.dict(sys.modules, fake_azure_modules(TruncatedClient())):
            result = collect(["sub-1"])
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "partial")
        self.assertIn("truncado sem skip_token", result["discovery"]["collection_log"][0]["note"])
        self.assertEqual(len(result["discovery"]["rbac"]), 1)

if __name__ == "__main__":
    unittest.main()
