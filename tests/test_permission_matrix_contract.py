import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PermissionMatrixContractTests(unittest.TestCase):
    def test_graph_permissions_used_by_collector_are_documented(self):
        source = (ROOT / "src" / "collect_graph.py").read_text(encoding="utf-8")
        matrix = (ROOT / "docs" / "PERMISSIONS-MATRIX.md").read_text(encoding="utf-8")
        hints = re.findall(
            r"get_all\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]+['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            source,
            re.DOTALL,
        )
        self.assertTrue(hints, "Graph collector permission hints must remain discoverable")
        used_scopes = {
            scope.strip()
            for hint in hints
            for scope in hint.split("+")
            if scope.strip()
        }
        undocumented = sorted(scope for scope in used_scopes if scope not in matrix)
        self.assertEqual(undocumented, [], f"Document collector permissions: {undocumented}")

    def test_matrix_does_not_request_per_user_mfa_permission_for_bulk_report(self):
        matrix = (ROOT / "docs" / "PERMISSIONS-MATRIX.md").read_text(encoding="utf-8")
        collector = (ROOT / "src" / "collect_graph.py").read_text(encoding="utf-8")
        self.assertIn("Reports.Read.All", collector)
        self.assertNotIn("UserAuthenticationMethod.Read.All", collector)
        self.assertNotIn("UserAuthenticationMethod.Read.All", matrix)


if __name__ == "__main__":
    unittest.main()
