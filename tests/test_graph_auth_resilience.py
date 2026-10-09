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
