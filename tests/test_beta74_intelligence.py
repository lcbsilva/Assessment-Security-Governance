import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_arg import (
    advisor_row,
    defender_summary,
    enrich_policy_assignments,
    hygiene_summary,
    policy_assignment_row,
    resource_map,
    resource_row,
)
from generate_report import render_azure_intelligence


class AzureIntelligenceBeta74Tests(unittest.TestCase):
    def test_resource_map_builds_explicit_dependency_edges(self):
        plan_id = "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Web/serverfarms/plan1"
        app_id = "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.Web/sites/app1"
        plan = resource_row({
            "id": plan_id, "name": "plan1", "type": "Microsoft.Web/serverfarms",
            "subscriptionId": "sub1", "resourceGroup": "rg", "location": "brazilsouth",
            "properties": {}, "tags": {"owner": "cloud", "env": "lab"},
        })
        app = resource_row({
            "id": app_id, "name": "app1", "type": "Microsoft.Web/sites",
            "subscriptionId": "sub1", "resourceGroup": "rg", "location": "brazilsouth",
            "properties": {"serverFarmId": plan_id}, "tags": {"owner": "cloud", "env": "lab"},
        })
        graph = resource_map([plan, app])
        self.assertEqual(graph["node_count"], 2)
        self.assertEqual(graph["edge_count"], 1)
        self.assertEqual(graph["edges"][0]["kind"], "Resource dependency")

    def test_policy_assignment_resolves_default_assigned_and_effective_values(self):
        assignment = policy_assignment_row({
            "id": "/subscriptions/sub1/providers/Microsoft.Authorization/policyAssignments/a1",
            "name": "a1", "displayName": "Baseline", "subscriptionId": "sub1",
            "scope": "/subscriptions/sub1", "definitionId": "/providers/Microsoft.Authorization/policyDefinitions/p1",
            "parameters": {"allowedLocations": {"value": ["brazilsouth"]}},
        })
        definitions = [{
            "id": "/providers/Microsoft.Authorization/policyDefinitions/p1",
            "name": "p1", "type": "Microsoft.Authorization/policyDefinitions", "displayName": "Allowed locations",
            "parameters": {
                "allowedLocations": {"defaultValue": ["eastus"]},
                "effect": {"defaultValue": "Audit"},
            },
        }]
        result = enrich_policy_assignments([assignment], definitions)[0]
        params = {item["name"]: item for item in result["parameters"]}
        self.assertEqual(params["allowedLocations"]["assigned_value"], ["brazilsouth"])
        self.assertEqual(params["allowedLocations"]["effective_value"], ["brazilsouth"])
        self.assertEqual(params["allowedLocations"]["value_source"], "Assigned")
        self.assertEqual(params["effect"]["default_value"], "Audit")
        self.assertEqual(params["effect"]["effective_value"], "Audit")
        self.assertEqual(params["effect"]["value_source"], "Default")

    def test_hygiene_summary_finds_empty_resource_groups_and_network_attention(self):
        resources = [{"subscription": "sub1", "resource_group": "rg-used"}]
        groups = [
            {"subscriptionId": "sub1", "name": "rg-used", "location": "eastus"},
            {"subscriptionId": "sub1", "name": "rg-empty", "location": "eastus"},
        ]
        orphans = [{"reason": "Unused public IP"}, {"reason": "Unused public IP"}, {"reason": "Unattached disk"}]
        network = [{
            "name": "vpn1", "type": "Microsoft.Network/connections", "resourceGroup": "rg-used",
            "properties": {"connectionStatus": "Disconnected"},
        }]
        result = hygiene_summary(resources, orphans, groups, network)
        self.assertEqual(result["empty_resource_group_count"], 1)
        self.assertEqual(result["orphan_count"], 3)
        self.assertEqual(result["unused_by_reason"]["Unused public IP"], 2)
        self.assertEqual(result["network_attention_count"], 1)

    def test_defender_summary_prioritizes_potential_score_gain(self):
        result = defender_summary(
            [{"subscriptionId": "sub1", "current": 4.4, "max": 13, "percentage": 34}],
            [
                {"subscriptionId": "sub1", "displayName": "Control A", "current": 0, "max": 4, "unhealthy": "8"},
                {"subscriptionId": "sub1", "displayName": "Control B", "current": 2, "max": 3, "unhealthy": "1"},
            ],
        )
        self.assertEqual(result["top_improvements"][0]["control"], "Control A")
        self.assertEqual(result["top_improvements"][0]["potential_score_increase"], 4.0)

    def test_advisor_row_exposes_monthly_savings_without_claiming_guarantee(self):
        row = advisor_row({
            "category": "Cost", "impact": "High", "annualSavings": 1200,
            "savingsCurrency": "USD", "subscriptionId": "sub1",
        })
        self.assertEqual(row["monthly_savings"], 100.0)
        self.assertEqual(row["currency"], "USD")

    def test_html_contains_azure_intelligence_sections(self):
        html = render_azure_intelligence({"discovery": {
            "resource_map": {"nodes": [{"id": "r1", "name": "vnet1", "type": "Microsoft.Network/virtualNetworks", "resource_group": "rg1", "region": "brazilsouth"}], "edges": [], "node_count": 1, "edge_count": 0},
            "resource_hygiene": {"empty_resource_group_count": 0, "orphan_count": 0, "network_attention_count": 0, "empty_resource_groups": [], "unused_by_reason": {}, "network_attention": []},
            "policy_assignments": [],
            "policy_compliance": [],
            "defender_secure_score": {"scores": [], "top_improvements": []},
        }})
        self.assertIn("Resource Map interativo", html)
        self.assertIn("Resource Hygiene", html)
        self.assertIn("parâmetros efetivos", html)
        self.assertIn("Defender Secure Score", html)


if __name__ == "__main__":
    unittest.main()
