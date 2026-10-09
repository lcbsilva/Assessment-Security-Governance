import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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


if __name__ == "__main__":
    unittest.main()
