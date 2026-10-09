import io
import json
import sys
import types
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.error import HTTPError
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_analytics import (
    aggregate_status,
    collect,
    collect_analytics_resources,
    collect_powerbi_workspaces,
)
import collect_analytics as analytics_collector


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


class AnalyticsPaginationTests(unittest.TestCase):
    def test_collect_records_per_source_status_without_tenant_access(self):
        class Client:
            def resources(self, request):
                return Response([{"id": "resource-1", "name": "Synthetic Purview", "type": "Microsoft.Purview/accounts"}])

        class Credential:
            def get_token(self, scope):
                return types.SimpleNamespace(token="synthetic-token")

        azure = types.ModuleType("azure")
        azure.__path__ = []
        identity = types.ModuleType("azure.identity")
        identity.DefaultAzureCredential = lambda **kwargs: Credential()
        mgmt = types.ModuleType("azure.mgmt")
        mgmt.__path__ = []
        resourcegraph = types.ModuleType("azure.mgmt.resourcegraph")
        resourcegraph.__path__ = []
        resourcegraph.ResourceGraphClient = lambda credential: Client()
        models = types.ModuleType("azure.mgmt.resourcegraph.models")
        models.QueryRequest = QueryRequest
        models.QueryRequestOptions = QueryRequestOptions
        modules = {
            "azure": azure,
            "azure.identity": identity,
            "azure.mgmt": mgmt,
            "azure.mgmt.resourcegraph": resourcegraph,
            "azure.mgmt.resourcegraph.models": models,
        }
        with patch.dict(sys.modules, modules), patch.object(
            analytics_collector,
            "collect_powerbi_workspaces",
            return_value=([], "not_available", "Synthetic Power BI unavailable", 0),
        ):
            result = analytics_collector.collect(["sub-1"])

        self.assertEqual(result["metadata"]["modules"]["analytics"], "partial")
        logs = {item["module"]: item for item in result["discovery"]["collection_log"]}
        self.assertEqual(logs["Purview"]["status"], "success")
        self.assertEqual(logs["Purview"]["records"], 1)
        self.assertEqual(logs["Power BI / Fabric workspaces"]["status"], "not_available")

    def test_arg_inventory_uses_1000_row_pages_and_stable_unique_order(self):
        class Client:
            def __init__(self):
                self.requests = []

            def resources(self, request):
                self.requests.append(request)
                if request.options.skip_token is None:
                    return Response([{"id": "a", "type": "Microsoft.Purview/accounts"}], "page-2")
                return Response([{"id": "b", "type": "Microsoft.Synapse/workspaces"}])

        client = Client()
        rows, status, note = collect_analytics_resources(client, ["sub-1"], QueryRequest, QueryRequestOptions)
        self.assertEqual([row["name"] for row in rows], ["—", "—"])
        self.assertEqual(status, "success")
        self.assertIn("conteúdo e dados de negócio não coletados", note)
        self.assertEqual([request.options.top for request in client.requests], [1000, 1000])
        self.assertEqual([request.options.skip_token for request in client.requests], [None, "page-2"])
        self.assertIn("order by id asc", client.requests[0].query.lower())

    def test_later_arg_page_failure_preserves_rows_as_partial(self):
        class Client:
            def __init__(self):
                self.calls = 0

            def resources(self, request):
                self.calls += 1
                if self.calls == 1:
                    return Response([{"id": "first", "type": "Microsoft.Purview/accounts"}], "page-2")
                raise RuntimeError("synthetic later-page failure")

        rows, status, note = collect_analytics_resources(Client(), ["sub-1"], QueryRequest, QueryRequestOptions)
        self.assertEqual(len(rows), 1)
        self.assertEqual(status, "partial")
        self.assertIn("synthetic later-page failure", note)

    def test_powerbi_uses_skip_paging_and_stops_on_short_page(self):
        requested = []

        def opener(request, timeout):
            parsed = urlparse(request.full_url)
            params = parse_qs(parsed.query)
            requested.append((int(params["$top"][0]), int(params["$skip"][0]), timeout))
            skip = int(params["$skip"][0])
            values = [{"name": f"Workspace {index}", "capacityId": "capacity-1"} for index in range(5000)] if skip == 0 else [{"name": "Workspace 5000"}]
            return io.BytesIO(json.dumps({"value": values}).encode("utf-8"))

        sleeps = []
        rows, status, note, pages = collect_powerbi_workspaces("synthetic-token", opener=opener, sleep=sleeps.append)
        self.assertEqual(status, "success")
        self.assertEqual(len(rows), 5001)
        self.assertEqual(pages, 2)
        self.assertEqual(requested, [(5000, 0, 30), (5000, 5000, 30)])
        self.assertEqual(sleeps, [4])
        self.assertIn("2 página(s)", note)

    def test_powerbi_page_budget_marks_full_final_page_partial(self):
        def opener(request, timeout):
            return io.BytesIO(json.dumps({"value": [{"name": str(index)} for index in range(5000)]}).encode("utf-8"))

        with patch.dict("os.environ", {"ASSESSMENT_POWERBI_MAX_PAGES": "1"}):
            rows, status, note, pages = collect_powerbi_workspaces("synthetic-token", opener=opener, sleep=lambda _: None)
        self.assertEqual(len(rows), 5000)
        self.assertEqual(status, "partial")
        self.assertEqual(pages, 1)
        self.assertIn("Limite de 1 páginas", note)

    def test_powerbi_later_http_failure_preserves_first_page(self):
        calls = 0

        def opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise HTTPError(request.full_url, 403, "Forbidden", {}, None)
            return io.BytesIO(json.dumps({"value": [{"name": str(index)} for index in range(5000)]}).encode("utf-8"))

        rows, status, note, pages = collect_powerbi_workspaces("synthetic-token", opener=opener, sleep=lambda _: None)
        self.assertEqual(len(rows), 5000)
        self.assertEqual(status, "partial")
        self.assertEqual(pages, 1)
        self.assertIn("HTTP 403", note)

    def test_powerbi_retries_throttling_after_retry_after(self):
        calls = 0
        delays = []

        def opener(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise HTTPError(request.full_url, 429, "Too Many Requests", {"Retry-After": "7"}, None)
            return io.BytesIO(json.dumps({"value": []}).encode("utf-8"))

        rows, status, _, pages = collect_powerbi_workspaces("synthetic-token", opener=opener, sleep=delays.append)
        self.assertEqual(rows, [])
        self.assertEqual(status, "success")
        self.assertEqual(pages, 1)
        self.assertEqual(calls, 2)
        self.assertEqual(delays, [7])

    def test_analytics_aggregate_status_does_not_hide_optional_source_gaps(self):
        self.assertEqual(aggregate_status(["success", "success"]), "success")
        self.assertEqual(aggregate_status(["success", "not_available"]), "partial")
        self.assertEqual(aggregate_status(["not_available", "not_available"]), "not_available")


if __name__ == "__main__":
    unittest.main()
