import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import collect_arg as arg_collector
from collect_arg import arg_result_status, query_arg_all_pages


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


class ArgPaginationTests(unittest.TestCase):
    def test_fetches_all_pages_including_skip_token_continuation(self):
        class Client:
            def __init__(self):
                self.requests = []
            def resources(self, request):
                self.requests.append(request)
                if request.options.skip_token is None:
                    return Response([{"id": "a"}], "page-2")
                return Response([{"id": "b"}])

        client = Client()
        rows = query_arg_all_pages(client, ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual([row["id"] for row in rows], ["a", "b"])
        self.assertEqual([request.options.skip_token for request in client.requests], [None, "page-2"])
        self.assertTrue(all(request.options.top == 1000 for request in client.requests))

    def test_repeated_skip_token_preserves_rows_as_partial(self):
        class Client:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                return Response([{"id": str(self.calls)}], "same-token")

        client = Client()
        result = query_arg_all_pages(client, ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual(len(result), 2)
        self.assertFalse(result.complete)
        self.assertEqual(arg_result_status(result), "partial")
        self.assertIn("repetiu o skip_token", result.error)
        self.assertEqual(client.calls, 2)

    def test_later_page_failure_preserves_first_page_and_marks_partial(self):
        class Client:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                if self.calls == 1:
                    return Response([{"id": "partial"}], "page-2")
                raise RuntimeError("service unavailable")

        result = query_arg_all_pages(Client(), ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual([row["id"] for row in result], ["partial"])
        self.assertFalse(result.complete)
        self.assertEqual(arg_result_status(result), "partial")
        self.assertIn("service unavailable", result.error)

    def test_first_page_failure_has_no_partial_rows(self):
        class Client:
            def resources(self, request):
                raise RuntimeError("service unavailable")

        result = query_arg_all_pages(Client(), ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual(result, [])
        self.assertFalse(result.complete)
        self.assertEqual(arg_result_status(result), "not_available")



    def test_truncated_response_without_skip_token_is_partial(self):
        class Client:
            def resources(self, request):
                response = Response([{"id": "first-page"}])
                response.result_truncated = True
                return response

        result = query_arg_all_pages(Client(), ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual([row["id"] for row in result], ["first-page"])
        self.assertFalse(result.complete)
        self.assertEqual(arg_result_status(result), "partial")
        self.assertIn("truncado sem skip_token", result.error)


    def test_paginated_queries_use_a_unique_ordering_key(self):
        query_names = (
            "QUERY", "POLICY_QUERY", "POLICY_ASSIGNMENTS_QUERY",
            "POLICY_DEFINITIONS_QUERY", "ORPHAN_QUERY", "RESOURCE_GROUP_QUERY",
            "NETWORK_HEALTH_QUERY", "DEFENDER_SCORE_QUERY",
            "DEFENDER_CONTROLS_QUERY", "RETIREMENT_QUERY", "ADVISOR_QUERY",
            "CONTAINERS_QUERY", "POWER_PLATFORM_QUERY", "BENEFITS_QUERY",
        )
        for name in query_names:
            query = getattr(arg_collector, name)
            self.assertRegex(
                query.lower(),
                r"\|\s*order by\s+(?:id|resourceid)\s+asc",
                msg=f"{name} must sort pages by a stable unique ID",
            )

if __name__ == "__main__":
    unittest.main()
