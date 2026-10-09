"""Regression checks for evidence-safe executive and Policy indicators."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from generate_report import render_executive_security_kpis, render_inventory_overview


class ReportEvidenceRegressionTests(unittest.TestCase):
    def test_graph_failure_does_not_look_like_zero_mfa_risk(self):
        data = {
            "discovery": {
                "users": [],
                "collection_log": [
                    {"module": "graph", "status": "error", "note": "authentication unavailable"}
                ],
            }
        }
        html = render_executive_security_kpis(data)
        self.assertIn("Sem evidência", html)
        self.assertIn("Sem MFA", html)

    def test_successful_users_without_mfa_endpoint_remain_unknown(self):
        data = {
            "discovery": {
                "users": [{"mfa_status": "Unknown"}],
                "collection_log": [{"module": "Identity basic", "status": "success"}],
            }
        }
        html = render_executive_security_kpis(data)
        self.assertIn("Sem evidência", html)

    def test_policy_exempt_and_unknown_not_counted_as_noncompliant(self):
        data = {
            "discovery": {
                "policy_compliance": [
                    {"compliance_state": "Compliant", "classification": "compliant", "non_compliant": 0},
                    {"compliance_state": "Exempt", "classification": "exempt", "non_compliant": 0},
                    {"compliance_state": "Unknown", "classification": "unknown", "non_compliant": 0},
                    {"compliance_state": "NonCompliant", "classification": "non_compliant", "non_compliant": 1},
                ]
            }
        }
        html = render_inventory_overview(data)
        self.assertIn("Não conformidades Policy</span><b>1</b>", html)


if __name__ == "__main__":
    unittest.main()
