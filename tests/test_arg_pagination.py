import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_arg import query_arg_all_pages


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

    def test_repeated_skip_token_fails_closed_instead_of_reporting_complete(self):
        class Client:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                return Response([{"id": str(self.calls)}], "same-token")

        client = Client()
        with self.assertRaisesRegex(RuntimeError, "repetiu o skip_token"):
            query_arg_all_pages(client, ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)
        self.assertEqual(client.calls, 2)

    def test_later_page_failure_does_not_return_first_page_as_complete(self):
        class Client:
            def __init__(self):
                self.calls = 0
            def resources(self, request):
                self.calls += 1
                if self.calls == 1:
                    return Response([{"id": "partial"}], "page-2")
                raise RuntimeError("service unavailable")

        with self.assertRaisesRegex(RuntimeError, "service unavailable"):
            query_arg_all_pages(Client(), ["sub-1"], "Resources", QueryRequest, QueryRequestOptions)


if __name__ == "__main__":
    unittest.main()
