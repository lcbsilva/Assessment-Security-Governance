import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from insight_engine import gate_insights


class CrossDomainEvidenceGateTests(unittest.TestCase):
    def test_partial_role_member_collection_keeps_identity_insight_conditional(self):
        insights = [{"id": "I-001", "title": "Privileged guest", "risk": 96, "priority": "P1"}]
        logs = [
            {"module": "Identity", "status": "success"},
            {"module": "Directory roles", "status": "success"},
            {"module": "Role members: Global Administrator", "status": "not_available"},
        ]
        result = gate_insights(insights, logs)[0]
        self.assertEqual(result["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["priority_eligibility"], "conditional_review")
        self.assertEqual(result["priority"], "P2")
        self.assertEqual(result["source_status"], "not_available")
        self.assertIn("incompleta", result["coverage_guardrail"])

    def test_complete_required_sources_keep_supported_priority(self):
        insights = [{"id": "I-004", "title": "Broad RBAC", "risk": 94, "priority": "P1"}]
        result = gate_insights(insights, [{"module": "RBAC", "status": "success"}])[0]
        self.assertEqual(result["evidence_state"], "SUPPORTED")
        self.assertEqual(result["priority_eligibility"], "eligible")
        self.assertEqual(result["priority"], "P1")
        self.assertEqual(result["source_status"], "success")

    def test_missing_inventory_source_does_not_confirm_exposure_correlation(self):
        insights = [{"id": "X-002", "title": "Public resource without owner", "risk": 88, "priority": "P2"}]
        result = gate_insights(insights, [])[0]
        self.assertEqual(result["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["source_status"], "not_available")
        self.assertEqual(result["priority_eligibility"], "conditional_review")

    def test_unmapped_insight_is_not_promoted_to_supported(self):
        result = gate_insights([{"id": "CI-999", "title": "Other correlation"}], [])[0]
        self.assertEqual(result["source_status"], "not_declared")
        self.assertEqual(result["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["priority_eligibility"], "conditional_review")

    def test_finops_orphan_correlation_requires_both_sources(self):
        insight = {"id": "XDI-002", "title": "Orphans and rightsizing", "priority": "P1"}
        result = gate_insights([insight], [
            {"module": "Orphan resources", "status": "success"},
            {"module": "Azure Advisor", "status": "partial"},
        ])[0]
        self.assertEqual(result["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["priority_eligibility"], "conditional_review")
        self.assertEqual(result["priority"], "P2")

    def test_cost_anomaly_correlation_requires_cost_and_advisor_sources(self):
        insight = {"id": "XDI-003", "title": "Cost anomaly and recommendations", "priority": "P2"}
        result = gate_insights([insight], [
            {"module": "Cost Management", "status": "success"},
            {"module": "Azure Advisor", "status": "success"},
        ])[0]
        self.assertEqual(result["evidence_state"], "SUPPORTED")
        self.assertEqual(result["priority_eligibility"], "eligible")


if __name__ == "__main__":
    unittest.main()
