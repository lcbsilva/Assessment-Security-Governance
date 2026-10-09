import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from preflight import module_readiness


class ProfileReadinessTests(unittest.TestCase):
    EXPECTED = {
        "security": {"Azure inventory", "Azure Policy / hierarchy", "Entra PIM", "Identity / users", "MFA / registration", "Conditional Access", "Sign-ins / legacy auth", "Secure Score", "Defender", "Intune", "Power Platform", "Directory audit", "M365 domain posture"},
        "governance": {"Azure inventory", "Azure Policy / hierarchy", "Azure RBAC assignments", "Entra PIM", "Power Platform"},
        "full": {"Azure inventory", "Azure Policy / hierarchy", "Azure RBAC assignments", "Entra PIM", "Identity / users", "MFA / registration", "Conditional Access", "Sign-ins / legacy auth", "Secure Score", "Defender", "Intune", "Cost Management", "Power Platform", "Azure DevOps", "Purview / Synapse / Databricks", "Directory audit", "Power BI / Fabric", "M365 domain posture"},
    }

    def test_manifest_matches_collectors_for_each_profile(self):
        for profile, expected in self.EXPECTED.items():
            with self.subTest(profile=profile):
                manifest = module_readiness(profile)
                in_scope = {item["module"] for item in manifest if item["status"] == "not_checked"}
                self.assertEqual(in_scope, expected)
                dlp = next(item for item in manifest if item["module"] == "Purview DLP / retention")
                self.assertEqual(dlp["status"], "not_run")
                self.assertTrue(all(item["detail"] for item in manifest))


if __name__ == "__main__":
    unittest.main()
