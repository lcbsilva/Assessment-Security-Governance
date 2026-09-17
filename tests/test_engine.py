import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from contract import validate_payload
from score_normalized import derive
from readonly_guard import assert_read_only, execution_metadata
from compare_runs import compare
from history import snapshot
from collect_arg import resource_row, exposure_details, power_platform_row, summarize_power_platform
from collect_arg import summarize_policy_compliance
from collect_arg import retryable_arg_error
from collect_graph import sign_in_path, permission_grant_row, build_identity_summary, enrich_pim_rows, conditional_access_row, credential_posture, user_posture, retryable_graph_status, secure_score_summary
from collect_rbac import access_risk
from collect_azure_devops import collect as collect_devops, repository_row, summarize as summarize_devops
from evidence_quality import classify, summarize
from insight_engine import risk_intersections, control_evidence, enrich_rbac_identity, cross_domain_insights
from run_assessment import skipped_module


class EngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = yaml.safe_load((ROOT / "catalog/controls.yaml").read_text(encoding="utf-8"))
        cls.mock = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))

    def test_mock_contract_is_valid(self):
        self.assertEqual(validate_payload(self.mock, self.catalog), [])

    def test_scoring_preserves_catalog_coverage(self):
        payload = derive({"metadata": {}, "discovery": {"users": [{"mfa_status": "Registered"}, {"mfa_status": "Not registered"}]}}, self.catalog)
        self.assertEqual(len(payload["controls"]), len(self.catalog["controls"]))
        self.assertTrue(any(item["control_id"] == "ID-001" for item in payload["findings"]))

    def test_evidence_drives_governance_and_cost_controls(self):
        payload = derive({"metadata": {}, "discovery": {
            "resources": [{"exposure": "Public"}, {"exposure": "Private"}],
            "policy_compliance": [{"compliance_state": "Compliant"}, {"compliance_state": "NonCompliant"}],
            "lifecycle": {"orphan_resources": [{"name": "orphan"}], "service_retirements": []},
        }}, self.catalog)
        controls = {item["id"]: item for item in payload["controls"]}
        self.assertEqual(controls["COST-001"]["score"], 45)
        finding_controls = {item["control_id"] for item in payload["findings"]}
        self.assertTrue({"GOV-004", "GOV-006", "COST-001"}.issubset(finding_controls))

    def test_invalid_finding_is_reported(self):
        errors = validate_payload({"metadata": {}, "controls": [], "findings": [{"id": "F-1"}], "discovery": {}}, self.catalog)
        self.assertTrue(any("findings[0].title" in error for error in errors))

    def test_privileged_mfa_is_scored_when_role_evidence_exists(self):
        payload = {"metadata": {}, "discovery": {"users": [
            {"privileged": True, "mfa_status": "Not registered"},
            {"privileged": True, "mfa_status": "Registered"},
        ]}}
        result = derive(payload, self.catalog)
        admin = next(item for item in result["controls"] if item["id"] == "ID-002")
        self.assertEqual(admin["status"], "fail")
        self.assertTrue(any(item["control_id"] == "ID-002" for item in result["findings"]))

    def test_legacy_auth_is_scored_from_aggregated_signin_evidence(self):
        payload = {"metadata": {}, "discovery": {"legacy_auth_summary": {
            "lookback_days": 30, "signins_reviewed": 100, "legacy_signins": 4, "affected_users": 2
        }}}
        result = derive(payload, self.catalog)
        control = next(item for item in result["controls"] if item["id"] == "ID-005")
        self.assertEqual(control["status"], "fail")
        self.assertTrue(any(item["control_id"] == "ID-005" for item in result["findings"]))

    def test_secure_score_is_scored_from_graph_evidence(self):
        payload = {"metadata": {}, "discovery": {"secure_score": [{"currentScore": 40, "maxScore": 100}], "secure_score_controls": [{"id": "S-1"}]}}
        result = derive(payload, self.catalog)
        control = next(item for item in result["controls"] if item["id"] == "SEC-001")
        self.assertEqual(control["score"], 40)
        self.assertTrue(any(item["control_id"] == "SEC-001" for item in result["findings"]))

    def test_endpoint_posture_is_scored_from_device_evidence(self):
        payload = {"metadata": {}, "discovery": {"devices": [
            {"compliant": True, "managed": True},
            {"compliant": False, "managed": True},
            {"compliant": "Unknown", "managed": False},
        ]}}
        result = derive(payload, self.catalog)
        control = next(item for item in result["controls"] if item["id"] == "SEC-002")
        self.assertEqual(control["score"], 33)
        self.assertTrue(any(item["control_id"] == "SEC-002" for item in result["findings"]))

    def test_pim_apps_and_defender_are_scored_from_aggregates(self):
        payload = {"metadata": {}, "discovery": {
            "pim_summary": {"active": 2, "eligible": 1, "permanent_or_active": 2},
            "enterprise_applications": [{"name": "app"}],
            "app_registrations": [{"credentials": 1}],
            "defender_summary": {"alerts": 3, "high": 1, "active": 2},
        }}
        result = derive(payload, self.catalog)
        controls = {item["id"]: item for item in result["controls"]}
        self.assertEqual(controls["ID-009"]["status"], "fail")
        self.assertTrue(any(item["control_id"] == "SEC-003" for item in result["findings"]))
        self.assertTrue(any(item["control_id"] == "SEC-005" for item in result["findings"]))

    def test_unknown_last_sign_in_is_not_counted_as_inactive(self):
        result = derive({"metadata": {}, "discovery": {"users": [{"last_sign_in": "Unknown", "account_enabled": "Unknown"}]}}, self.catalog)
        self.assertFalse(any(item["control_id"] == "ID-008" for item in result["findings"]))

    def test_hierarchy_evidence_improves_governance_control(self):
        payload = {"metadata": {}, "discovery": {"resources": [{"tags": "owner, env"}], "containers": [{"type": "microsoft.management/managementgroups"}]}}
        result = derive(payload, self.catalog)
        control = next(item for item in result["controls"] if item["id"] == "GOV-001")
        self.assertEqual(control["score"], 85)

    def test_preflight_contract_has_safe_status_and_no_write_actions(self):
        preflight = (ROOT / "src" / "preflight.py").read_text(encoding="utf-8")
        self.assertIn("preflight.json", preflight)
        self.assertIn("não altera o tenant", preflight)

    def test_read_only_guard_blocks_write_configuration(self):
        assert_read_only({"guardrails": {"allow_write": False, "allow_delete": False}})
        with self.assertRaises(RuntimeError):
            assert_read_only({"guardrails": {"allow_write": True, "allow_delete": False}})
        self.assertFalse(execution_metadata()["tenant_mutation"])

    def test_pilot_validation_requires_clean_contract_and_ai_payload(self):
        from validate_pilot import validate as validate_pilot
        data = {"metadata": {"contract_status": "valid", "execution": {"mode": "read-only", "tenant_mutation": False}}, "controls": [], "findings": [], "discovery": {"collection_log": []}}
        self.assertEqual(validate_pilot(data, self.catalog)["status"], "ready_for_pilot_review")
        data["metadata"]["execution"]["tenant_mutation"] = True
        self.assertEqual(validate_pilot(data, self.catalog)["status"], "blocked")

    def test_run_comparison_reports_control_delta_and_findings(self):
        previous = {"metadata": {"run_id": "old", "scope": {"users_assessed": 10}}, "controls": [{"id": "ID-001", "score": 60, "status": "partial"}], "findings": [{"control_id": "ID-001"}, {"control_id": "GOV-003"}]}
        current = {"metadata": {"run_id": "new", "scope": {"users_assessed": 12}}, "controls": [{"id": "ID-001", "score": 80, "status": "pass"}], "findings": [{"control_id": "GOV-003"}]}
        result = compare(previous, current)
        self.assertEqual(result["controls"][0]["delta"], 20)
        self.assertEqual(result["findings_resolved"], ["ID-001"])
        self.assertEqual(result["scope_delta"]["users_assessed"], 2)

    def test_arg_resource_row_does_not_depend_on_global_rows(self):
        row = resource_row({"id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", "name": "vm", "type": "Microsoft.Compute/virtualMachines", "subscriptionId": "sub", "resourceGroup": "rg", "location": "brazilsouth", "tags": {"owner": "platform"}, "properties": {}})
        self.assertEqual(row["name"], "vm")
        self.assertIn("age_days", row)
        self.assertIn("governance_signal", row)

    def test_public_resource_gets_security_signal(self):
        from collect_arg import resource_row
        row = resource_row({"id": "x", "name": "pip", "type": "Microsoft.Network/publicIPAddresses", "tags": {}, "properties": {}})
        self.assertEqual(row["security_signal"], "Atenção")

    def test_graph_sign_in_filter_is_url_encoded(self):
        self.assertNotIn(" ", sign_in_path("2026-09-17T00:00:00Z"))
        self.assertIn("%20", sign_in_path("2026-09-17T00:00:00Z"))

    def test_permission_grant_never_collects_secret_values(self):
        row = permission_grant_row({"clientId": "c1", "resourceId": "r1", "scope": "User.Read Files.ReadWrite.All", "consentType": "AllPrincipals"}, {"c1": "App"}, {"r1": "Graph"})
        self.assertEqual(row["client"], "App")
        self.assertIn("Files.ReadWrite.All", row["high_impact_scopes"])
        self.assertNotIn("secret", str(row).lower())

    def test_history_snapshot_excludes_sensitive_finding_text(self):
        result = snapshot({"metadata": {"run_id": "r1", "scope": {"users_assessed": 2}}, "controls": [], "findings": [{"id": "F1", "control_id": "ID-001", "severity": "high", "risk_score": 70, "summary": "sensitive@example.com"}]})
        self.assertNotIn("sensitive@example.com", str(result))
        self.assertEqual(result["scope"]["users_assessed"], 2)

    def test_evidence_quality_does_not_treat_unavailable_as_success(self):
        logs = [{"status": "success"}, {"status": "not_available", "note": "HTTP 403; consentimento"}, {"status": "error", "note": "HTTP 429"}]
        result = summarize(logs)
        self.assertEqual(result["score"], 33)
        self.assertEqual(classify("not_available", "HTTP 403; consentimento"), "permission")
        self.assertEqual(classify("error", "HTTP 429"), "throttling")

    def test_finding_contains_decision_lineage_and_dependencies(self):
        result = derive({"metadata": {}, "discovery": {"users": [{"mfa_status": "Not registered"}]}}, self.catalog)
        finding = next(item for item in result["findings"] if item["control_id"] == "ID-001")
        self.assertIn("evidence_lineage", finding)
        self.assertTrue(finding["remediation_dependencies"])
        self.assertTrue(finding["validation_questions"])

    def test_ai_payload_declares_security_governance_focus(self):
        from ai_payload import build
        payload = build({"metadata": {}, "findings": [], "discovery": {}})
        self.assertEqual(payload["focus"]["primary_domains"], ["security", "governance"])

    def test_risk_intersection_connects_security_and_governance(self):
        result = risk_intersections({"users": [{"privileged": True, "mfa_status": "Not registered"}], "resources": [{"exposure": "Public", "owner": "A definir", "tags": "Nenhuma"}]})
        self.assertEqual({item["id"] for item in result}, {"X-001", "X-002", "X-003"})

    def test_rbac_identity_correlation_detects_high_risk_access_without_mfa(self):
        discovery = {"users": [{"id": "u1", "display_name": "Admin", "account_type": "Member", "mfa_status": "Not registered", "privileged": True}], "rbac": [{"principal": "u1", "access_risk": "Crítico"}]}
        enrich_rbac_identity(discovery)
        self.assertEqual(discovery["rbac"][0]["principal_name"], "Admin")
        result = risk_intersections(discovery)
        self.assertIn("X-004", {item["id"] for item in result})

    def test_cross_domain_insights_prioritize_external_privileged_identity(self):
        result = cross_domain_insights({
            "users": [{"privileged": True, "account_type": "Guest", "last_sign_in": "Never"}],
            "rbac": [{"access_risk": "Crítico", "scope_kind": "Subscription"}],
            "conditional_access": [{"state": "enabled", "grant_controls": "—"}],
            "app_registrations": [{"expired_credentials": 1}],
            "resources": [],
        })
        ids = {item["id"] for item in result}
        self.assertTrue({"I-001", "I-002", "I-003", "I-004", "I-005"}.issubset(ids))
        self.assertEqual(result[0]["severity"], "critical")

    def test_control_evidence_returns_every_catalog_control(self):
        result = control_evidence({"discovery": {"collection_log": [{"module": "Identity", "status": "success", "records": 10}]}}, self.catalog)
        self.assertEqual(len(result), len(self.catalog["controls"]))

    def test_profile_skip_is_explicit_and_read_only(self):
        result = skipped_module("cost", "Azure Cost Management API")
        self.assertEqual(result["metadata"]["modules"]["cost"], "not_run")
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "not_available")

    def test_identity_summary_is_aggregated_and_actionable(self):
        summary = build_identity_summary([
            {"account_type": "Guest", "account_enabled": True, "last_sign_in": "Never", "privileged": True, "mfa_status": "Not registered", "risk": "high"},
            {"account_type": "Member", "account_enabled": False, "last_sign_in": "2026-09-01", "privileged": False, "mfa_status": "Registered", "risk": "None"},
        ], [{"high_impact_scopes": "Application.ReadWrite.All"}])
        self.assertEqual(summary["Convidados externos"], 1)
        self.assertEqual(summary["Privilegiados sem MFA"], 1)
        self.assertEqual(summary["Consentimentos de alto impacto"], 1)

    def test_pim_rows_resolve_principal_and_scope_level(self):
        rows = enrich_pim_rows([{"principal_id": "u1", "scope": "/"}, {"principal_id": "u2", "scope": "/administrativeUnits/au1"}], [{"id": "u1", "display_name": "Admin"}])
        self.assertEqual(rows[0]["principal_name"], "Admin")
        self.assertEqual(rows[0]["scope_kind"], "Tenant")
        self.assertEqual(rows[1]["scope_kind"], "Administrative unit")
        self.assertEqual(rows[1]["principal_name"], "Principal não resolvido")

    def test_rbac_risk_is_conservative_and_scope_aware(self):
        self.assertEqual(access_risk("Owner", "Management Group")[0], "Crítico")
        self.assertEqual(access_risk("Owner", "Resource")[0], "Alto")
        self.assertEqual(access_risk("Reader", "Subscription")[0], "Moderado")

    def test_conditional_access_exposes_coverage_and_exclusions(self):
        row = conditional_access_row({"displayName": "Require MFA", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"], "excludeGroups": ["breakglass"]}}, "grantControls": {"builtInControls": ["mfa"]}})
        self.assertEqual(row["users_scope"], "Todos os usuários")
        self.assertEqual(row["excluded"], 1)
        self.assertIn("exclusões", row["risk_signal"])
        disabled = conditional_access_row({"displayName": "Draft", "state": "disabled", "conditions": {}, "grantControls": {}})
        self.assertIn("Não aplicada", disabled["risk_signal"])

    def test_credential_posture_detects_expired_and_expiring_secrets(self):
        from datetime import datetime, timezone
        now = datetime(2026, 9, 17, tzinfo=timezone.utc)
        result = credential_posture([{"endDateTime": "2026-09-16T00:00:00Z"}, {"endDateTime": "2026-10-01T00:00:00Z"}, {"endDateTime": "2027-01-01T00:00:00Z"}], now)
        self.assertEqual(result, {"expired": 1, "expiring_30d": 1})

    def test_user_posture_explains_individual_security_signals(self):
        level, signal = user_posture({"privileged": True, "mfa_status": "Not registered", "account_type": "Member", "account_enabled": True, "last_sign_in": "2026-09-01", "risk": "None"})
        self.assertEqual(level, "Crítico")
        self.assertIn("Privilegiado sem MFA", signal)
        level, signal = user_posture({"privileged": False, "mfa_status": "Registered", "account_type": "Guest", "account_enabled": True, "last_sign_in": "Never", "risk": "None"})
        self.assertEqual(level, "Atenção")
        self.assertIn("Convidado externo", signal)

    def test_graph_retry_policy_handles_throttling_and_transient_errors(self):
        self.assertTrue(retryable_graph_status(429))
        self.assertTrue(retryable_graph_status(503))
        self.assertFalse(retryable_graph_status(403))
        self.assertFalse(retryable_graph_status(404))

    def test_arg_retry_policy_only_accepts_transient_statuses(self):
        class Error:
            def __init__(self, status_code):
                self.status_code = status_code
        self.assertTrue(retryable_arg_error(Error(429)))
        self.assertTrue(retryable_arg_error(Error(503)))
        self.assertFalse(retryable_arg_error(Error(403)))

    def test_secure_score_summary_calculates_posture_and_recommendations(self):
        result = secure_score_summary([{"currentScore": 42, "maxScore": 100}], [{"implementationCost": "Low", "maxScore": 5}, {"implementationCost": "High", "maxScore": 10}])
        self.assertEqual(result["percentage"], 42.0)
        self.assertEqual(result["recommendations"], 2)
        self.assertEqual(result["high_impact_recommendations"], 1)

    def test_beta_gate_is_read_only_and_has_all_checks(self):
        from beta_gate import run_gate
        result = run_gate(ROOT / "mock" / "assessment.json", include_tests=False)
        self.assertEqual(result["status"], "beta_ready")
        self.assertTrue(result["read_only"])
        self.assertGreaterEqual(result["passed"], 7)

    def test_beta_deployment_wrappers_exist(self):
        self.assertTrue((ROOT / "scripts" / "run-beta-gate.ps1").exists())
        self.assertTrue((ROOT / "scripts" / "run-beta-gate.sh").exists())

    def test_azure_exposure_detection_covers_network_properties(self):
        self.assertEqual(exposure_details("Microsoft.Storage/storageAccounts", {"publicNetworkAccess": "Disabled"})[0], "Private")
        self.assertEqual(exposure_details("Microsoft.Storage/storageAccounts", {"allowBlobPublicAccess": True})[0], "Public access / Review")
        self.assertEqual(exposure_details("Microsoft.KeyVault/vaults", {})[0], "Review")
        row = resource_row({"id": "x", "type": "Microsoft.Web/sites", "properties": {"publicNetworkAccess": "Enabled"}, "tags": {}})
        self.assertEqual(row["exposure_reason"], "publicNetworkAccess=Enabled")

    def test_policy_summary_groups_evidence_and_assigns_risk(self):
        result = summarize_policy_compliance([
            {"policy": "Require TLS", "assignment": "baseline", "subscription": "sub1", "non_compliant": 1},
            {"policy": "Require TLS", "assignment": "baseline", "subscription": "sub1", "non_compliant": 0},
        ])
        self.assertEqual(result[0]["evaluated"], 2)
        self.assertEqual(result[0]["non_compliant"], 1)
        self.assertEqual(result[0]["compliance_rate"], 50.0)
        self.assertEqual(result[0]["risk_signal"], "Atenção")

    def test_engine_version_is_loaded_from_single_source(self):
        from version import engine_version
        self.assertEqual(engine_version(), (ROOT / "VERSION").read_text(encoding="utf-8").strip())

    def test_power_platform_inventory_is_normalized_without_content(self):
        row = power_platform_row({
            "id": "/providers/Microsoft.PowerPlatform/apps/app1",
            "name": "Sales App",
            "type": "Microsoft.PowerPlatform/apps",
            "subscriptionId": "sub1",
            "properties": {
                "environmentName": "Default-Env",
                "owner": "owner@example.com",
                "powerPlatformConnectors": [{"id": "shared-office365", "tier": "Premium"}],
                "formula": "must never be collected",
            },
        })
        self.assertEqual(row["kind"], "apps")
        self.assertEqual(row["premium_connectors"], 1)
        self.assertNotIn("formula", str(row))
        self.assertIn("Conector premium", row["posture_signals"])

    def test_power_platform_summary_is_aggregated(self):
        result = summarize_power_platform([
            {"kind": "apps", "environment": "E1", "owner": "A definir", "premium_connectors": 1},
            {"kind": "flow", "environment": "E1", "owner": "team", "premium_connectors": 0},
        ])
        self.assertEqual(result["resources"], 2)
        self.assertEqual(result["without_owner"], 1)
        self.assertEqual(result["premium_connectors"], 1)
        self.assertEqual(result["environments"], 1)

    def test_collectors_use_only_read_http_methods(self):
        import re
        for path in (ROOT / "src").glob("collect_*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"method\s*=\s*[\"'](?:PUT|PATCH|DELETE)[\"']")
        cost_text = (ROOT / "src" / "collect_cost.py").read_text(encoding="utf-8")
        self.assertIn('method="POST"', cost_text)
        self.assertIn("CostManagement/query", cost_text)

    def test_devops_without_credentials_is_explicitly_unavailable(self):
        result = collect_devops(org_url="", pat="")
        self.assertEqual(result["metadata"]["modules"]["azure_devops"], "not_available")
        self.assertEqual(result["discovery"]["azure_devops_summary"]["repositories"], 0)

    def test_devops_repository_public_visibility_is_a_governance_signal(self):
        row = repository_row({"id": "r1", "name": "infra", "project": {"visibility": "public"}}, "Platform")
        self.assertEqual(row["governance_signal"], "Crítico")
        self.assertIn("público", row["posture_signals"])
        self.assertEqual(summarize_devops({"projects": [], "repositories": [row], "pipelines": [], "branch_policies": []})["public_repositories"], 1)

    def test_devops_collector_contract_does_not_include_pat(self):
        from urllib.error import HTTPError
        def denied(*args, **kwargs):
            raise HTTPError("https://dev.azure.com/example", 403, "denied", {}, None)
        result = collect_devops(org_url="https://dev.azure.com/example", pat="super-secret", opener=denied)
        self.assertNotIn("super-secret", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
