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

    def test_unavailable_sources_do_not_render_executive_kpis_as_zero(self):
        data = {"discovery": {
            "users": [], "resources": [], "rbac": [], "policy_compliance": [],
            "device_summary": {"non_compliant": 0, "unmanaged": 0},
            "collection_log": [
                {"module": "Identity", "status": "error"},
                {"module": "MFA", "status": "not_available"},
                {"module": "RBAC", "status": "partial"},
                {"module": "Azure inventory", "status": "not_available"},
                {"module": "Azure Policy", "status": "error"},
                {"module": "Entra devices", "status": "success"},
                {"module": "Intune managed devices", "status": "not_available"},
            ],
        }}
        html = render_executive_security_kpis(data)
        for label in ("Sem MFA", "Privilegiados sem MFA", "Convidados externos",
                      "RBAC alto risco", "Recursos públicos",
                      "Policy: soma de não conformidades", "Endpoints em atenção"):
            self.assertIn(f"<span>{label}</span><b>Sem evidência</b>", html)

    def test_partial_aggregate_identity_hides_counts_after_role_member_failure(self):
        data = {
            "metadata": {"modules": {"identity": "partial"}},
            "discovery": {
                "users": [{"privileged": False, "mfa_status": "Not registered"}],
                "user_summary": {"Usuários sem MFA": 1, "Privilegiados sem MFA": 0},
                "collection_log": [
                    {"module": "Identity", "status": "success"},
                    {"module": "MFA", "status": "success"},
                    {"module": "Role members: Global Administrator", "status": "not_available"},
                ],
            },
        }
        html = render_executive_security_kpis(data)
        self.assertIn("<span>Sem MFA</span><b>Sem evidência</b>", html)
        self.assertIn("<span>Privilegiados sem MFA</span><b>Sem evidência</b>", html)
        self.assertNotIn("<span>Privilegiados sem MFA</span><b>0</b>", html)

    def test_successful_empty_sources_may_render_verified_zeroes(self):
        data = {"discovery": {
            "users": [], "resources": [], "rbac": [], "policy_compliance": [],
            "device_summary": {"non_compliant": 0, "unmanaged": 0},
            "collection_log": [
                {"module": "Identity basic", "status": "success"},
                {"module": "MFA", "status": "success"},
                {"module": "Directory roles", "status": "success"},
                {"module": "RBAC", "status": "success"},
                {"module": "Azure inventory", "status": "success"},
                {"module": "Azure Policy", "status": "success"},
                {"module": "Entra devices", "status": "success"},
                {"module": "Intune managed devices", "status": "success"},
            ],
        }}
        html = render_executive_security_kpis(data)
        for label in ("Sem MFA", "Privilegiados sem MFA", "Convidados externos",
                      "RBAC alto risco", "Recursos públicos",
                      "Policy: soma de não conformidades", "Endpoints em atenção"):
            self.assertIn(f"<span>{label}</span><b>0</b>", html)


    def test_missing_directory_roles_source_does_not_claim_zero_privileged_accounts(self):
        data = {"discovery": {
            "users": [], "user_summary": {"Privilegiados sem MFA": 0},
            "collection_log": [
                {"module": "Identity", "status": "success"},
                {"module": "MFA", "status": "success"},
            ],
        }}
        html = render_executive_security_kpis(data)
        self.assertIn("<span>Privilegiados sem MFA</span><b>Sem evidência</b>", html)

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
