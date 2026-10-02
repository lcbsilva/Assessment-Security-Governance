import json
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from contract import validate_payload
from score_normalized import derive, evidence_state, license_gate_status
from readonly_guard import assert_read_only, execution_metadata
from compare_runs import compare
from history import snapshot
from collect_arg import resource_row, exposure_details, resource_security_posture, power_platform_row, summarize_power_platform, retirement_row
from collect_arg import policy_row, summarize_policy_compliance, summarize_security_posture, summarize_governance_posture
from collect_arg import retryable_arg_error
from collect_graph import sign_in_path, permission_grant_row, build_identity_summary, enrich_pim_rows, conditional_access_row, credential_posture, user_posture, retryable_graph_status, secure_score_summary, license_posture, directory_audit_summary
from collect_rbac import access_risk, summarize_rbac_posture
from collect_azure_devops import collect as collect_devops, repository_row, summarize as summarize_devops
from evidence_quality import classify, summarize
from insight_engine import risk_intersections, control_evidence, enrich_rbac_identity, cross_domain_insights, prioritize_findings
from run_assessment import skipped_module, safe_collect
from run_assessment import load_engagement
from preflight import estimate, check, module_readiness, permission_check
from execution_health import summarize as summarize_execution, coverage_map, build_execution_manifest
from collect_analytics import category, resource_row as analytics_resource_row, powerbi_row
from collect_cost import anomaly_summary, is_readonly_cost_query_url, query_cost
from simulate_tenant import simulate
from beta_gate import run_gate
from release_gate import read_only_source_scan, release_checks
from checkpoint import load as load_checkpoint, scope_key, write as write_checkpoint
from schema_contract import load_schema, validate_schema
from history_dashboard import load_history, render as render_history_dashboard
from collect_m365_posture import analyze_domain, collect as collect_m365, capability_manifest
from quality_audit import audit
from review_checklist import build as build_review_checklist
from artifact_manifest import build as build_artifact_manifest
from validate_manifest import validate as validate_manifest
from pseudonymize import pseudonymize
from summarize_lab_validation import summarize as summarize_lab_validation
from module_diagnostics import diagnose as diagnose_module
from build_demo_package import build_demo
from doctor import diagnose
from pilot_evidence import build as build_pilot_evidence
from generate_pilot_pack import build as build_pilot_pack


class EngineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = yaml.safe_load((ROOT / "catalog/controls.yaml").read_text(encoding="utf-8"))
        cls.mock = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))

    def test_mock_contract_is_valid(self):
        self.assertEqual(validate_payload(self.mock, self.catalog), [])

    def test_pilot_evidence_gate_requires_confirmed_scope_and_consent(self):
        preflight = {"status": "ready", "profile": "full", "subscriptions_requested": ["sub-1"], "summary": {"warning": 0}}
        assessment = {"metadata": {"execution": {"mode": "read-only", "tenant_mutation": False}}}
        pilot = {"status": "ready_for_pilot_review"}
        approval = {"consent_status": "confirmed", "approved_profile": "full", "approved_subscriptions": ["sub-1"], "approved_read_scopes": ["Reader"]}
        result = build_pilot_evidence(preflight, assessment, pilot, approval)
        self.assertEqual(result["status"], "ready_for_controlled_pilot")
        approval["consent_status"] = "not_confirmed"
        self.assertEqual(build_pilot_evidence(preflight, assessment, pilot, approval)["status"], "blocked")

    def test_pilot_evidence_gate_rejects_scope_expansion_and_secrets(self):
        preflight = {"status": "ready", "profile": "security", "subscriptions_requested": ["sub-2"], "summary": {"warning": 0}}
        assessment = {"metadata": {"execution": {"mode": "read-only", "tenant_mutation": False}}}
        pilot = {"status": "ready_for_pilot_review"}
        approval = {"consent_status": "confirmed", "approved_profile": "security", "approved_subscriptions": ["sub-1"], "approved_read_scopes": ["Contributor"], "client_secret": "do-not-include"}
        result = build_pilot_evidence(preflight, assessment, pilot, approval)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any("campo sensível" in error for error in result["errors"]))

    def test_release_source_scan_enforces_read_only_path(self):
        result = read_only_source_scan()
        self.assertEqual(result["status"], "pass")

    def test_demo_package_generates_complete_offline_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = build_demo(Path(temporary) / "demo", "full")
            self.assertEqual(summary["status"], "ready_for_internal_demo")
            self.assertTrue(summary["read_only"])
            self.assertTrue(summary["synthetic"])
            self.assertIn("assessment.html", summary["outputs"])
            self.assertIn("assessment-one-page-brief.pdf", summary["outputs"])
            self.assertTrue((Path(temporary) / "demo" / "dist" / "team-review-guide.md").exists())
            self.assertTrue((Path(temporary) / "demo" / "dist" / "team-feedback-template.md").exists())
            self.assertIn("assessment-action-plan.xlsx", summary["outputs"])
            self.assertEqual(summary["artifact_integrity"], "valid")

    def test_doctor_contract_is_read_only_and_reports_output_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = diagnose([], "full", Path(temporary) / "runtime" / "doctor.json")
        self.assertTrue(result["read_only"])
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(item["name"] == "output_path" for item in result["checks"]))

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

    def test_controls_have_formal_evidence_states(self):
        result = derive({"metadata": {}, "discovery": {"users": [{"mfa_status": "Registered"}]}}, self.catalog)
        self.assertTrue(all(item["evidence_state"] in {"CONFORMANT", "NON_CONFORMANT", "INSUFFICIENT_EVIDENCE"} for item in result["controls"]))
        self.assertEqual(evidence_state("not_available"), ("INSUFFICIENT_EVIDENCE", "missing_permission_license_or_data"))
        self.assertEqual(evidence_state("fail"), ("NON_CONFORMANT", "score_below_threshold"))
        self.assertEqual(license_gate_status("SEC-001", {}), "not_satisfied_or_not_available")
        self.assertEqual(license_gate_status("SEC-005", {"defender_summary": {"alerts": 0}}), "satisfied")

    def test_contract_rejects_contradictory_evidence_state(self):
        payload = {"metadata": {"schema_version": "1.0", "engine_version": "test", "run_id": "r1", "execution": {"mode": "read-only", "tenant_mutation": False}}, "controls": [{"id": "ID-001", "status": "pass", "score": 90, "confidence": "high", "evidence_state": "INSUFFICIENT_EVIDENCE"}], "findings": [], "discovery": {}}
        errors = validate_payload(payload, self.catalog)
        self.assertTrue(any("INSUFFICIENT_EVIDENCE exige" in item for item in errors))

    def test_quality_audit_detects_high_risk_quality_gaps(self):
        data = {"metadata": {}, "controls": [{"id": "ID-001", "status": "pass", "score": 90, "confidence": "high", "evidence_state": "CONFORMANT"}], "findings": [{"control_id": "ID-001", "risk_score": 90, "title": "Risco", "limitations": []}], "discovery": {"collection_log": [{"status": "not_available"}]}}
        result = audit(data, self.catalog)
        codes = {item["code"] for item in result["errors"]}
        self.assertIn("FINDING_WITHOUT_EVIDENCE", codes)
        self.assertIn("HIGH_RISK_WITHOUT_LIMITATION", codes)
        self.assertEqual(result["status"], "blocked")

    def test_score_calculation_exposes_domain_coverage(self):
        from generate_report import calculate
        domains, overall, coverage = calculate(self.catalog, {"controls": [{"id": item["id"], "status": "not_available", "score": 0, "confidence": "low"} for item in self.catalog["controls"]]})
        self.assertIsNone(overall)
        self.assertEqual(coverage, 0)
        self.assertTrue(all(item["coverage"] == 0 for item in domains.values()))
        self.assertEqual(domains["compliance"]["coverage_status"], "insufficient")
        self.assertTrue(all(item["coverage_status"] in {"insufficient", "not_configured"} for item in domains.values()))

    def test_executive_report_shows_na_when_no_controls_have_evidence(self):
        from generate_report import render
        data = json.loads(json.dumps(self.mock))
        data["controls"] = [{**item, "status": "not_available", "score": 0, "evidence_state": "INSUFFICIENT_EVIDENCE"} for item in data["controls"]]
        data["findings"] = []
        catalog = yaml.safe_load((ROOT / "catalog/controls.yaml").read_text(encoding="utf-8"))
        runbooks = yaml.safe_load((ROOT / "catalog/runbooks.yaml").read_text(encoding="utf-8"))
        report = render(catalog, data, runbooks)
        self.assertIn("Evidência insuficiente", report)
        self.assertIn("N/D", report)
        self.assertIn("sem score", report)

    def test_score_coverage_excludes_insufficient_evidence_even_when_status_is_fail(self):
        from generate_report import calculate
        controls = [{"id": item["id"], "status": "fail", "score": 0, "confidence": "low", "evidence_state": "INSUFFICIENT_EVIDENCE"} for item in self.catalog["controls"]]
        domains, overall, coverage = calculate(self.catalog, {"controls": controls})
        self.assertIsNone(overall)
        self.assertEqual(coverage, 0)
        self.assertTrue(all(item["evaluated"] == 0 for item in domains.values()))

    def test_checkpoint_resume_is_scoped_and_does_not_cross_tenants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = scope_key(["sub-a"], "full")
            write_checkpoint(root, "graph", key, {"metadata": {"modules": {"identity": "success"}}})
            self.assertIsNotNone(load_checkpoint(root, "graph", key))
            self.assertIsNone(load_checkpoint(root, "graph", scope_key(["sub-b"], "full")))

    def test_checkpoint_does_not_reuse_failed_or_unavailable_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = scope_key(["sub-a"], "full")
            failed = {"metadata": {"modules": {"graph": "error"}}, "discovery": {"collection_log": [{"status": "error"}]}}
            unavailable = {"metadata": {"modules": {"graph": "not_available"}}, "discovery": {"collection_log": [{"status": "not_available"}]}}
            write_checkpoint(root, "graph", key, failed)
            self.assertIsNone(load_checkpoint(root, "graph", key))
            write_checkpoint(root, "graph", key, unavailable)
            self.assertIsNone(load_checkpoint(root, "graph", key))
            partial = {"metadata": {"modules": {"graph": "partial"}}, "discovery": {"collection_log": [{"status": "partial"}]}}
            write_checkpoint(root, "graph", key, partial)
            self.assertIsNone(load_checkpoint(root, "graph", key))

    def test_checkpoint_expiration_prevents_reuse_of_stale_tenant_data(self):
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = scope_key(["sub-a"], "full")
            write_checkpoint(root, "graph", key, {"metadata": {"modules": {"identity": "success"}}})
            path = root / "graph.json"
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["written_at"] = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
            path.write_text(json.dumps(envelope), encoding="utf-8")
            self.assertIsNone(load_checkpoint(root, "graph", key))

    def test_module_diagnostic_categorizes_without_claiming_root_cause(self):
        permission = diagnose_module("Defender", "not_available", "HTTP 403; insufficient privileges")
        timeout = diagnose_module("Sign-ins", "partial", "TimeoutError: read timed out")
        configured = diagnose_module("Azure DevOps", "not_available", "Configure AZDO_ORG_URL")
        self.assertEqual(permission["limitation_category"], "permission_or_role")
        self.assertIn("pode", permission["likely_cause"])
        self.assertEqual(timeout["limitation_category"], "timeout")
        self.assertEqual(configured["limitation_category"], "configuration")

    def test_safe_collect_records_duration_and_attempt(self):
        name, result = safe_collect("graph", lambda: {"metadata": {"modules": {"graph": "success"}}, "discovery": {"collection_log": [{"status": "success"}]}}, {})
        self.assertEqual(name, "graph")
        self.assertTrue(result["metadata"]["execution"]["attempted"])
        self.assertGreaterEqual(result["metadata"]["execution"]["duration_seconds"], 0)
        self.assertIn("started_at", result["discovery"]["collection_log"][0])
        self.assertIn("finished_at", result["discovery"]["collection_log"][0])
        self.assertEqual(result["discovery"]["collection_log"][0]["attempt"], 1)

    def test_versioned_schema_is_present_and_rejects_missing_execution_metadata(self):
        schema = load_schema()
        self.assertEqual(schema["$id"], "https://softwareone.example/schemas/assessment-1.0.json")
        errors = validate_schema({"metadata": {"schema_version": "1.0"}, "controls": [], "findings": [], "discovery": {}})
        self.assertTrue(any("metadata.execution" in item for item in errors))

    def test_priority_sort_has_stable_tiebreakers(self):
        rows = prioritize_findings([{"control_id": "GOV-002", "title": "B", "risk_score": 50, "effort": 3}, {"control_id": "GOV-001", "title": "A", "risk_score": 50, "effort": 3}], {"score": 80})
        self.assertEqual([item["control_id"] for item in rows], ["GOV-001", "GOV-002"])

    def test_m365_domain_posture_is_metadata_only_and_detects_dns_signals(self):
        records = {"example.com": ["v=spf1 include:spf.example -all"], "_dmarc.example.com": ["v=DMARC1; p=quarantine"], "selector1._domainkey.example.com": ["v=DKIM1; k=rsa; p=public"], "selector2._domainkey.example.com": []}
        row = analyze_domain("example.com", lambda name: records.get(name, []))
        self.assertEqual(row["spf"], "present")
        self.assertEqual(row["dmarc"], "present")
        self.assertEqual(row["dkim_selector1"], "present")
        self.assertEqual(row["dkim_selector2"], "not_present")
        self.assertNotIn("public", str(row))

    def test_m365_posture_fails_gracefully_without_configured_domains(self):
        result = collect_m365(domains=[])
        self.assertEqual(result["metadata"]["modules"]["m365"], "not_available")
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "not_available")
        self.assertEqual(len(capability_manifest()), 5)
        self.assertTrue(all(item["status"] == "not_configured" for item in capability_manifest()))

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
        self.assertIn('"[0].name"', preflight)
        self.assertNotIn('"--top", "1"', preflight)

    def test_preflight_permission_probe_timeout_is_warning(self):
        with patch("preflight.subprocess.run", side_effect=subprocess.TimeoutExpired(["az"], 30)):
            result = permission_check(["sub-1"])
        self.assertEqual(result["status"], "warning")
        self.assertFalse(result["blocking"])
        self.assertIn("inconclusiva por tempo", result["detail"])
        decision = "blocked" if result.get("blocking") and result["status"] == "blocked" else "run_full_with_limitations"
        self.assertNotEqual(decision, "blocked")

    def test_preflight_permission_probe_real_failure_is_blocked(self):
        failed = subprocess.CompletedProcess(["az"], 1, "", "Forbidden")
        with patch("preflight.subprocess.run", return_value=failed):
            result = permission_check(["sub-1"])
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["blocking"])

    def test_readiness_gate_distinguishes_blocking_and_optional_warning(self):
        essential = check("reader", "Leitura", "azure", "blocked", "403", "sem evidência", "conceder Reader", True)
        optional = check("defender", "Defender", "coverage", "warning", "licença", "módulo parcial", "validar licença")
        self.assertTrue(essential["blocking"])
        self.assertFalse(optional["blocking"])
        self.assertEqual(estimate(2, "full")["low_minutes"], 36)
        self.assertGreater(estimate(2, "full", "large")["low_minutes"], estimate(2, "full")["low_minutes"])

    def test_readiness_manifest_does_not_claim_unverified_consent(self):
        manifest = module_readiness("full")
        self.assertGreaterEqual(len(manifest), 10)
        self.assertIn("será confirmado", " ".join(item["detail"] for item in manifest))
        self.assertTrue(any(item["module"] == "RBAC / PIM" and "RoleManagement" in item["expected_read_scope"] for item in manifest))

    def test_execution_health_does_not_turn_unavailable_into_zero_risk(self):
        result = summarize_execution([
            {"module": "Identity", "status": "success", "records": 10},
            {"module": "Defender", "status": "not_available", "records": 0, "limitation_category": "permission"},
            {"module": "Cost", "status": "partial", "records": 2, "limitation_category": "throttling"},
        ])
        self.assertEqual(result["completed_modules"], 2)
        self.assertEqual(result["coverage_percent"], 66.7)
        self.assertEqual(result["health"], "degraded")
        self.assertEqual(result["limitations"][0]["module"], "Defender")
        self.assertEqual(result["confidence_band"], "média")
        self.assertEqual(result["confidence_score"], 50.0)

    def test_pilot_validation_blocks_invalid_contract_status(self):
        from validate_pilot import validate as validate_pilot
        data = {"metadata": {"contract_status": "invalid", "execution": {"mode": "read-only", "tenant_mutation": False}}, "controls": [], "findings": [], "discovery": {"collection_log": []}}
        result = validate_pilot(data, self.catalog)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any("contract_status" in error for error in result["errors"]))

    def test_pilot_pack_is_local_read_only_and_actionable(self):
        pack = build_pilot_pack({"profile": "security", "status": "ready", "subscriptions_requested": ["sub-1"], "required_read_scopes": ["Reader"], "optional_read_scopes": ["Reports.Read.All"], "module_readiness": [{"module": "Identity / users", "domain": "Identidade", "expected_read_scope": "User.Read.All", "status": "not_checked"}], "limitations": ["Permissões opcionais serão confirmadas pelos coletores."]})
        self.assertIn("read-only", pack)
        self.assertIn("User.Read.All", pack)
        self.assertIn("não cria, altera, exclui", pack)

    def test_coverage_map_explains_unavailable_modules_without_claiming_success(self):
        result = coverage_map(
            [{"module": "Defender", "status": "not_available", "records": 0, "note": "HTTP 403; verifique licença"}],
            [{"module": "Defender", "domain": "Segurança", "expected_read_scope": "SecurityIncident.Read.All", "status": "not_checked"}],
        )
        self.assertEqual(result[0]["status"], "not_available")
        self.assertEqual(result[0]["evidence_confidence"], "baixa")
        self.assertIn("HTTP 403", result[0]["limitation"])

    def test_collector_failure_isolated_without_write_fallback(self):
        name, result = safe_collect("security", lambda: (_ for _ in ()).throw(RuntimeError("temporary")), {})
        self.assertEqual(name, "security")
        self.assertEqual(result["metadata"]["modules"]["security"], "error")
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "error")

    def test_analytics_inventory_is_metadata_only(self):
        self.assertEqual(category("Microsoft.Synapse/workspaces"), "Synapse")
        row = analytics_resource_row({"name": "data", "type": "Microsoft.Databricks/workspaces", "properties": {}, "sku": {}})
        self.assertEqual(row["category"], "Databricks")
        self.assertNotIn("properties", row)
        self.assertFalse(powerbi_row({"name": "workspace"})["is_on_dedicated_capacity"])

    def test_finops_ai_payload_aggregates_names_away(self):
        from ai_payload import build
        result = build({"metadata": {}, "findings": [], "discovery": {"finops_summary": {"cost_total_period": 100, "resource_groups": 2, "cost_by_resource_group": [{"resource_group": "secret-rg", "cost": 100}], "anomalies": {"anomaly_days": [{"date": "2026-01-01"}]}}}})
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("secret-rg", serialized)
        self.assertEqual(result["financial_aggregates"]["finops_summary"]["anomaly_days_count"], 1)

    def test_finops_anomaly_is_conservative_and_aggregated(self):
        result = anomaly_summary([
            {"UsageDate": "2026-01-01", "PreTaxCost": 10},
            {"UsageDate": "2026-01-02", "PreTaxCost": 10},
            {"UsageDate": "2026-01-03", "PreTaxCost": 40},
        ])
        self.assertEqual(result["days_observed"], 3)
        self.assertEqual(result["anomaly_days"][0]["date"], "2026-01-03")

    def test_directory_audit_is_aggregated_without_pii(self):
        events = [
            {"category": "RoleManagement", "activityDisplayName": "Add eligible role", "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}}},
            {"loggedByService": "Microsoft Entra ID", "activityDisplayName": "Update application policy", "targetResources": [{"id": "secret-id"}]},
        ]
        result = directory_audit_summary(events)
        self.assertEqual(result["events"], 2)
        self.assertEqual(result["high_risk_operation_signals"], 2)
        self.assertTrue(result["pii_excluded"])
        self.assertNotIn("admin@example.com", json.dumps(result))
        self.assertNotIn("secret-id", json.dumps(result))

    def test_directory_audit_ai_payload_excludes_categories_and_identifiers(self):
        from ai_payload import build
        summary = directory_audit_summary([{"category": "Microsoft Entra ID", "activityDisplayName": "Update policy"}])
        payload = build({"metadata": {}, "findings": [], "discovery": {"directory_audit_summary": summary}})
        serialized = json.dumps(payload, ensure_ascii=False)
        self.assertIn('"events": 1', serialized)
        self.assertNotIn("Microsoft Entra ID", serialized)
        self.assertNotIn("categories", payload["ecosystem_aggregates"]["directory_audit"])

    def test_priority_is_deterministic_and_financial_signal_is_conservative(self):
        findings = [{"control_id": "GOV-004", "risk_score": 82, "effort": 3, "severity": "high"}, {"control_id": "COST-001", "risk_score": 62, "effort": 2, "severity": "medium"}]
        without_cost = prioritize_findings(findings, {"score": 90}, "Não quantificado")
        with_cost = prioritize_findings(findings, {"score": 90}, "R$ 500/mês potencial")
        self.assertEqual(without_cost[0]["control_id"], "GOV-004")
        self.assertEqual(without_cost[0]["evidence_confidence"], "alta")
        self.assertEqual(without_cost[1]["financial_signal"], "unquantified")
        self.assertEqual(with_cost[1]["financial_signal"], "quantified")
        self.assertGreater(with_cost[1]["priority_score"], without_cost[1]["priority_score"])

    def test_priority_fields_are_part_of_the_action_contract(self):
        row = prioritize_findings([{"control_id": "SEC-001", "risk_score": 80, "effort": 2}], {"score": 70})[0]
        self.assertEqual(set(("priority", "priority_score", "evidence_confidence", "financial_signal")) & set(row), {"priority", "priority_score", "evidence_confidence", "financial_signal"})

    def test_simulation_scenarios_are_marked_and_never_touch_input(self):
        original = json.loads(json.dumps(self.mock))
        result = simulate(self.mock, "limited")
        self.assertEqual(self.mock, original)
        self.assertTrue(result["metadata"]["simulation"]["is_simulation"])
        self.assertEqual(result["metadata"]["simulation"]["evidence_status"], "synthetic_not_customer_evidence")
        defender = next(item for item in result["discovery"]["collection_log"] if item["module"] == "Defender")
        self.assertEqual(defender["status"], "not_available")
        self.assertNotIn("defender_summary", result["discovery"])
        self.assertEqual(result["metadata"]["contract_status"], "valid")

    def test_small_simulation_reduces_scope_without_claiming_real_tenant(self):
        result = simulate(self.mock, "small")
        self.assertEqual(result["metadata"]["scope"]["subscriptions"], 1)
        self.assertLessEqual(len(result["discovery"]["users"]), 2)
        self.assertEqual(result["metadata"]["simulation"]["scenario"], "small")
        self.assertEqual(result["metadata"]["scope"]["users_assessed"], len(result["discovery"]["users"]))

    def test_demo_scenarios_recalculate_posture_and_coverage(self):
        summaries = [simulate(self.mock, scenario, 10 if scenario == "large" else 1) for scenario in ("small", "medium", "limited", "full", "large")]
        scores = {item["metadata"]["overall_score"] for item in summaries}
        coverages = {item["metadata"]["coverage"] for item in summaries}
        self.assertGreaterEqual(len(scores), 3)
        self.assertGreaterEqual(len(coverages), 2)
        self.assertTrue(all(item["metadata"]["contract_status"] == "valid" for item in summaries))

    def test_medium_simulation_has_intermediate_scope_and_explicit_limitations(self):
        result = simulate(self.mock, "medium")
        scope = result["metadata"]["scope"]
        self.assertEqual(scope["users_assessed"], 200)
        self.assertEqual(scope["resources_assessed"], 250)
        self.assertEqual(result["metadata"]["simulation"]["scenario"], "medium")
        statuses = {item["status"] for item in result["discovery"]["collection_log"]}
        self.assertIn("partial", statuses)
        self.assertIn("not_available", statuses)

    def test_readonly_cost_query_allows_only_azure_cost_query_endpoint(self):
        allowed = "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789abc/providers/Microsoft.CostManagement/query?api-version=2023-03-01"
        denied = "https://management.azure.com/subscriptions/12345678-1234-1234-1234-123456789abc/providers/Microsoft.Storage/storageAccounts/listKeys/action?api-version=2023-01-01"
        self.assertTrue(is_readonly_cost_query_url(allowed))
        self.assertFalse(is_readonly_cost_query_url(denied))
        rows, error = query_cost(denied, "unused", {})
        self.assertEqual(rows, [])
        self.assertIn("Refused", error)

    def test_ai_privacy_guard_rejects_camelcase_identifiers_and_resource_paths(self):
        from ai_payload import privacy_violations
        payload = {"resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/private-rg", "summary": "Owner admin@example.com"}
        violations = privacy_violations(payload)
        self.assertTrue(any("resourceId" in item for item in violations))
        self.assertTrue(any("padrão identificável" in item for item in violations))

    def test_large_simulation_is_deterministic_and_contains_failure_modes(self):
        first = simulate(self.mock, "large", scale=1)
        second = simulate(self.mock, "large", scale=1)
        self.assertEqual(len(first["discovery"]["users"]), 2000)
        self.assertEqual(len(first["discovery"]["resources"]), 2500)
        self.assertEqual(first["discovery"]["users"], second["discovery"]["users"])
        statuses = {item["status"] for item in first["discovery"]["collection_log"]}
        self.assertTrue({"success", "partial", "not_available"}.issubset(statuses))
        self.assertTrue(first["metadata"]["simulation"]["is_simulation"])
        self.assertGreater(first["discovery"]["security_posture_summary"]["resources_with_explicit_signals"], 0)
        self.assertGreater(first["discovery"]["rbac_summary"]["critical_assignments"], 0)
        self.assertGreater(first["discovery"]["governance_summary"]["policy_evaluated"], 0)
        self.assertEqual(first["discovery"]["governance_summary"], second["discovery"]["governance_summary"])

    def test_beta_gate_runs_all_synthetic_scenarios(self):
        result = run_gate(ROOT / "mock" / "assessment.json", include_tests=False)
        self.assertEqual(result["status"], "beta_ready")
        self.assertTrue(all(item["status"] == "pass" for item in result["checks"] if item["name"].startswith("scenario_")))
        self.assertTrue(any(item["name"] == "scenario_large_scale5" for item in result["checks"]))
        self.assertTrue(any(item["name"] == "scenario_large_determinism" for item in result["checks"]))

    def test_pilot_validation_exposes_warnings_without_hiding_read_only_status(self):
        from validate_pilot import validate as validate_pilot
        data = {"metadata": {"contract_status": "valid", "simulation": {"is_simulation": True}, "execution": {"mode": "read-only", "tenant_mutation": False}}, "controls": [], "findings": [], "discovery": {"collection_log": []}}
        result = validate_pilot(data, self.catalog)
        self.assertEqual(result["status"], "ready_for_pilot_review")
        self.assertTrue(result["warnings"])
        self.assertTrue(result["acceptance"]["read_only"])

    def test_release_gate_checks_read_only_and_beta_documents(self):
        checks = {item["name"]: item for item in release_checks()}
        self.assertEqual(checks["readonly_config"]["status"], "pass")
        self.assertEqual(checks["doc_BETA-RELEASE-CHECKLIST"]["status"], "pass")
        self.assertEqual(checks["doc_BETA-SCOPE-REVIEW"]["status"], "pass")

    def test_compliance_manifest_does_not_claim_dlp_or_retention_collection(self):
        manifest = module_readiness("full")
        dlp = next(item for item in manifest if item["module"] == "Purview DLP / retention")
        self.assertEqual(dlp["status"], "not_run")
        self.assertIn("Integração Purview específica", dlp["expected_read_scope"])

    def test_benefit_inventory_is_aggregated_for_ai(self):
        from ai_payload import build
        result = build({"metadata": {}, "findings": [], "discovery": {"benefits_summary": {"reservations": 2, "savings_plans": 1}}})
        aggregate = result["financial_aggregates"]["finops_summary"]
        self.assertEqual(aggregate["reservation_inventory_count"], 2)
        self.assertEqual(aggregate["savings_plan_inventory_count"], 1)

    def test_license_posture_detects_product_families_without_assignments(self):
        result = license_posture([
            {"skuPartNumber": "M365_COPILOT", "consumedUnits": 2, "prepaidUnits": {"enabled": 5, "suspended": 0}},
            {"skuPartNumber": "TEAMS_PREMIUM", "consumedUnits": 1, "prepaidUnits": {"enabled": 1, "suspended": 0}},
        ])
        self.assertEqual(result["product_families"]["Copilot"], 1)
        self.assertEqual(result["product_families"]["Teams Premium"], 1)
        self.assertEqual(result["skus"][0]["unused_enabled"], 3)
        self.assertNotIn("user", json.dumps(result).lower())

    def test_power_platform_classifies_agents_and_keeps_ai_aggregate_safe(self):
        rows = [power_platform_row({"name": "agent", "type": "Microsoft.PowerPlatform/bots", "properties": {"kind": "bot", "environmentName": "Sensitive Environment"}}), power_platform_row({"name": "flow", "type": "Microsoft.PowerPlatform/flows", "properties": {"kind": "flow"}})]
        summary = summarize_power_platform(rows)
        self.assertEqual(summary["copilot_studio_agents"], 1)
        self.assertEqual(summary["power_automate"], 1)
        from ai_payload import build
        serialized = json.dumps(build({"metadata": {}, "findings": [], "discovery": {"power_platform_summary": summary}}), ensure_ascii=False)
        self.assertNotIn("Sensitive Environment", serialized)

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
        previous = {"metadata": {"run_id": "old", "scope": {"users_assessed": 10}, "coverage": 50}, "controls": [{"id": "ID-001", "score": 60, "status": "partial"}], "findings": [{"control_id": "ID-001"}, {"control_id": "GOV-003"}]}
        current = {"metadata": {"run_id": "new", "scope": {"users_assessed": 12}, "coverage": 75}, "controls": [{"id": "ID-001", "score": 80, "status": "pass"}], "findings": [{"control_id": "GOV-003"}]}
        result = compare(previous, current)
        self.assertEqual(result["controls"][0]["delta"], 20)
        self.assertEqual(result["findings_resolved"], ["ID-001"])
        self.assertEqual(result["scope_delta"]["users_assessed"], 2)
        self.assertEqual(result["comparability"]["comparable_controls"], 1)
        self.assertEqual(result["comparability"]["average_delta_on_overlap"], 20)
        self.assertTrue(result["comparability"]["coverage_changed"])

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

    def test_evidence_quality_excludes_out_of_profile_modules(self):
        result = summarize([
            {"status": "success"},
            {"status": "not_available", "note": "HTTP 403; consentimento"},
            {"status": "not_run", "note": "Fora do perfil"},
        ])
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["evaluated_modules"], 2)
        self.assertEqual(result["not_run"], 1)

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
        self.assertEqual(result["discovery"]["collection_log"][0]["status"], "not_run")
        self.assertIn("fora do perfil", result["discovery"]["collection_log"][0]["note"])

    def test_optional_collectors_are_not_called_in_focused_profiles(self):
        from run_assessment import skipped_module
        self.assertEqual(skipped_module("analytics", "Purview / Fabric") ["metadata"]["modules"]["analytics"], "not_run")
        self.assertEqual(skipped_module("azure_devops", "Azure DevOps")["metadata"]["modules"]["azure_devops"], "not_run")

    def test_execution_health_distinguishes_out_of_profile_from_unavailable(self):
        result = summarize_execution([{"status": "success"}, {"status": "not_run"}, {"status": "not_available"}])
        self.assertEqual(result["status_counts"]["not_run"], 1)
        self.assertEqual(result["out_of_profile_modules"], 1)
        self.assertEqual(result["coverage_percent"], 33.3)

    def test_execution_manifest_separates_executed_unavailable_and_out_of_profile(self):
        result = build_execution_manifest([
            {"module": "Identity", "status": "success", "records": 10},
            {"module": "Defender", "status": "not_available", "records": 0, "note": "Licença"},
            {"module": "Cost", "status": "not_run", "records": 0},
        ], "security")
        self.assertEqual(result["totals"], {"all": 3, "executed": 1, "unavailable_or_error": 1, "out_of_profile": 1})
        self.assertTrue(result["read_only"])

    def test_report_priority_domain_is_data_driven(self):
        from generate_report import render
        data = json.loads(json.dumps(self.mock))
        data["metadata"]["customer_name"] = "Tenant de teste"
        data["controls"] = [
            {"id": item["id"], "status": "not_available", "score": 0, "confidence": "low", "evidence_state": "INSUFFICIENT_EVIDENCE"}
            for item in self.catalog["controls"]
        ]
        data["controls"][0]["status"] = "fail"
        data["controls"][0]["score"] = 10
        data["controls"][0]["evidence_state"] = "NON_COMPLIANT"
        html = render(self.catalog, data, {"runbooks": []})
        self.assertIn("maior necessidade de atenção em", html)
        self.assertNotIn("maior necessidade de atenção em <b>Governança Azure</b>", html)

    def test_report_uses_detected_tenant_label_when_customer_is_not_configured(self):
        from generate_report import render
        data = json.loads(json.dumps(self.mock))
        data["metadata"].pop("customer_name", None)
        data["metadata"]["tenant_label"] = "lab-subscription"
        html = render(self.catalog, data, {"runbooks": []})
        self.assertIn("lab-subscription", html)
        self.assertNotIn("Tenant não identificado", html.split("<h1>", 1)[0])

    def test_report_falls_back_to_tenant_id_when_label_is_missing(self):
        from generate_report import render
        data = json.loads(json.dumps(self.mock))
        data["metadata"].pop("customer_name", None)
        data["metadata"].pop("tenant_label", None)
        data["metadata"]["tenant_id"] = "5006cec6-aa6d-4eab-bc19-c6d69046bddd"
        html = render(self.catalog, data, {"runbooks": []})
        self.assertIn("Tenant identificado", html)

    def test_report_labels_insufficient_evidence_without_claiming_nonconformity(self):
        from generate_report import render
        data = json.loads(json.dumps(self.mock))
        data["controls"] = [{**item, "status": "fail", "evidence_state": "INSUFFICIENT_EVIDENCE"} for item in data["controls"]]
        html = render(self.catalog, data, {"runbooks": []})
        self.assertIn("Evidência insuficiente", html)

    def test_report_navigation_is_compact_and_has_return_to_top(self):
        from generate_report import render
        html = render(self.catalog, json.loads(json.dumps(self.mock)), {"runbooks": []})
        self.assertIn('aria-label="Navegação do relatório"', html)
        self.assertIn('class="to-top"', html)
        self.assertIn(".nav-row{display:contents}", html)

    def test_report_findings_have_local_decision_actions(self):
        from generate_report import render
        html = render(self.catalog, json.loads(json.dumps(self.mock)), {"runbooks": []})
        self.assertIn("data-review-status=\"in_review\"", html)
        self.assertIn("data-copy-finding", html)
        self.assertIn("Marcar resolvido", html)

    def test_resource_exposure_distinguishes_confirmed_and_heuristic(self):
        confirmed = resource_row({"id": "/subscriptions/x", "type": "Microsoft.Network/publicIPAddresses", "properties": {}, "tags": {}})
        heuristic = resource_row({"id": "/subscriptions/x", "type": "Microsoft.Web/sites", "properties": {}, "tags": {}})
        self.assertEqual(confirmed["exposure_class"], "confirmed")
        self.assertEqual(heuristic["exposure_class"], "heuristic")

    def test_unresolved_pim_principal_is_insufficient_evidence(self):
        rows = enrich_pim_rows([{"principal_id": "missing", "scope": "/"}], [])
        self.assertEqual(rows[0]["principal_resolution"], "insufficient_evidence")

    def test_retirement_row_normalizes_iso_date(self):
        row = retirement_row({"properties": {"ImpactStartTime": "2026-11-10T00:00:00Z"}})
        self.assertEqual(row["retirement_date"], "2026-11-10T00:00:00Z")
        self.assertIsInstance(row["days_remaining"], int)

    def test_license_gate_blocks_compliance_without_entitlement_evidence(self):
        payload = derive({"metadata": {}, "discovery": {"secure_score": [{"currentScore": 80, "maxScore": 100}]}}, self.catalog)
        controls = {item["id"]: item for item in payload["controls"]}
        self.assertEqual(controls["SEC-001"]["status"], "pass")
        self.assertEqual(controls["SEC-005"]["status"], "not_available")
        self.assertEqual(controls["SEC-005"]["evidence_reason"], "license_or_entitlement_not_verified")
        self.assertEqual(controls["SEC-005"]["evidence_state"], "INSUFFICIENT_EVIDENCE")

    def test_insufficient_evidence_cannot_become_p1(self):
        from insight_engine import prioritize_findings, executive_actions
        finding = {"control_id": "SEC-005", "title": "Sinal condicional", "risk_score": 99, "effort": 1, "evidence_state": "INSUFFICIENT_EVIDENCE", "owner": "Security"}
        result = prioritize_findings([finding], {"score": 100})[0]
        self.assertNotEqual(result["priority"], "P1")
        self.assertEqual(result["priority_eligibility"], "conditional_review")
        self.assertTrue(executive_actions([result])[0]["priority"] != "P1")

    def test_review_checklist_blocks_non_read_only_and_warns_on_limitations(self):
        data = {"metadata": {"contract_status": "valid", "coverage": 40, "execution": {"tenant_mutation": False}, "execution_health": {"status_counts": {"not_available": 1}}}, "controls": [], "findings": [], "discovery": {"collection_log": [{"module": "Defender", "status": "not_available"}]}}
        result = build_review_checklist(data)
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["blocking"], 0)
        self.assertTrue(any(item["name"] == "coverage" and item["status"] == "warning" for item in result["checks"]))
        data["metadata"]["execution"]["tenant_mutation"] = True
        self.assertEqual(build_review_checklist(data)["status"], "blocked")

    def test_artifact_manifest_is_read_only_and_hashes_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "dist"
            output_dir.mkdir()
            (output_dir / "assessment.html").write_text("offline", encoding="utf-8")
            result = build_artifact_manifest(output_dir, {"metadata": {"engine_version": "test", "schema_version": "1.0", "profile": "security", "run_id": "r1", "execution": {"tenant_mutation": False}}})
            self.assertTrue(result["read_only"])
            self.assertEqual(result["files"][0]["name"], "assessment.html")
            self.assertEqual(len(result["files"][0]["sha256"]), 64)

    def test_artifact_manifest_hashes_normalized_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_dir = root / "dist"
            output_dir.mkdir()
            assessment = root / "assessment.json"
            ai_payload = root / "ai-payload.json"
            assessment.write_text("{}", encoding="utf-8")
            ai_payload.write_text('{"aggregated":true}', encoding="utf-8")
            result = build_artifact_manifest(output_dir, {"metadata": {"execution": {"tenant_mutation": False}}}, [assessment, ai_payload])
        self.assertEqual(result["manifest_version"], "1.1")
        self.assertEqual([item["name"] for item in result["inputs"]], ["assessment.json", "ai-payload.json"])
        self.assertTrue(all(len(item["sha256"]) == 64 for item in result["inputs"]))

    def test_manifest_validation_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_dir = root / "dist"
            output_dir.mkdir()
            artifact = output_dir / "assessment.html"
            artifact.write_text("original", encoding="utf-8")
            manifest = build_artifact_manifest(output_dir, {"metadata": {"execution": {"tenant_mutation": False}}})
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            artifact.write_text("tampered", encoding="utf-8")
            result = validate_manifest(manifest_path, output_dir, root)
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(any("hash divergente" in error for error in result["errors"]))

    def test_review_checklist_exposes_artifact_integrity(self):
        data = {"metadata": {"execution": {"tenant_mutation": False}, "contract_status": "valid", "coverage": 100}, "discovery": {"collection_log": []}, "findings": []}
        result = build_review_checklist(data, quality={"score": 100}, manifest_validation={"status": "valid", "read_only": True})
        check = next(item for item in result["checks"] if item["name"] == "artifact_integrity")
        self.assertEqual(check["status"], "pass")

    def test_pseudonymization_does_not_mutate_input_or_leak_email(self):
        source = {"metadata": {"customer_name": "Cliente Real"}, "discovery": {"users": [{"display_name": "Ana Souza", "mail": "ana@example.com", "mfa_status": "Registered"}]}}
        result = pseudonymize(source, "test-salt")
        self.assertEqual(source["metadata"]["customer_name"], "Cliente Real")
        self.assertNotIn("ana@example.com", json.dumps(result))
        self.assertNotIn("Ana Souza", json.dumps(result))
        self.assertEqual(result["metadata"]["privacy_mode"], "pseudonymized")

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

    def test_rbac_summary_exposes_blast_radius_without_claiming_inheritance(self):
        result = summarize_rbac_posture([
            {"role": "Owner", "scope_kind": "Subscription", "access_risk": "Crítico", "assignment_type": "Permanent/unknown"},
            {"role": "Reader", "scope_kind": "Resource Group", "access_risk": "Moderado", "assignment_type": "Permanent/unknown"},
        ])
        self.assertEqual(result["assignments"], 2)
        self.assertEqual(result["critical_assignments"], 1)
        self.assertEqual({item["scope_kind"] for item in result["by_scope"]}, {"Subscription", "Resource Group"})
        self.assertIn("não é presumida", result["inheritance_note"])

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
        self.assertTrue((ROOT / "scripts" / "run-focused-pilot.sh").exists())
        self.assertTrue((ROOT / "scripts" / "run-focused-pilot.ps1").exists())
        self.assertTrue((ROOT / "scripts" / "run-lab-validation.sh").exists())
        self.assertTrue((ROOT / "scripts" / "run-lab-validation.ps1").exists())
        self.assertTrue((ROOT / "scripts" / "generate-pilot-pack.sh").exists())
        self.assertTrue((ROOT / "scripts" / "generate-pilot-pack.ps1").exists())

    def test_windows_runner_supports_python_launcher_and_lists_outputs(self):
        runner = (ROOT / "scripts" / "run-assessment.ps1").read_text(encoding="utf-8")
        self.assertIn('Get-Command py', runner)
        self.assertIn('Get-ChildItem (Join-Path $root "dist")', runner)
        self.assertIn('Start-Process -FilePath $html', runner)

    def test_azure_exposure_detection_covers_network_properties(self):
        self.assertEqual(exposure_details("Microsoft.Storage/storageAccounts", {"publicNetworkAccess": "Disabled"})[0], "Private")
        self.assertEqual(exposure_details("Microsoft.Storage/storageAccounts", {"allowBlobPublicAccess": True})[0], "Public access / Review")
        self.assertEqual(exposure_details("Microsoft.KeyVault/vaults", {})[0], "Review")
        row = resource_row({"id": "x", "type": "Microsoft.Web/sites", "properties": {"publicNetworkAccess": "Enabled"}, "tags": {}})
        self.assertEqual(row["exposure_reason"], "publicNetworkAccess=Enabled")

    def test_resource_security_posture_detects_explicit_service_gaps(self):
        storage = resource_security_posture("Microsoft.Storage/storageAccounts", {"allowBlobPublicAccess": True, "supportsHttpsTrafficOnly": False, "minimumTlsVersion": "TLS1_0"})
        self.assertIn("Storage: blob público habilitado", storage)
        self.assertIn("Storage: HTTPS-only desabilitado", storage)
        keyvault = resource_security_posture("Microsoft.KeyVault/vaults", {"enablePurgeProtection": False, "networkAcls": {"defaultAction": "Allow"}})
        self.assertIn("Key Vault: purge protection desabilitado", keyvault)
        nsg = resource_security_posture("Microsoft.Network/networkSecurityGroups", {"securityRules": [{"access": "Allow", "direction": "Inbound", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "3389"}]})
        self.assertIn("NSG: entrada pública permitida na porta 3389", nsg)
        app_service = resource_security_posture("Microsoft.Web/sites", {"httpsOnly": False, "siteConfig": {"minTlsVersion": "1.0"}})
        self.assertIn("App Service: HTTPS-only desabilitado", app_service)
        self.assertIn("App Service: TLS mínimo legado", app_service)
        sql_firewall = resource_security_posture("Microsoft.Sql/servers/firewallRules", {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"})
        self.assertIn("SQL Firewall: acesso público de qualquer origem", sql_firewall)
        sql_server = resource_security_posture("Microsoft.Sql/servers", {"publicNetworkAccess": True})
        self.assertIn("Azure SQL: acesso público habilitado", sql_server)
        cosmos = resource_security_posture("Microsoft.DocumentDB/databaseAccounts", {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": False})
        self.assertIn("Serviço de dados: acesso público habilitado", cosmos)
        self.assertIn("Cosmos DB: filtro de rede virtual desabilitado", cosmos)
        redis = resource_security_posture("Microsoft.Cache/Redis", {"publicNetworkAccess": True})
        self.assertIn("Serviço de dados: acesso público habilitado", redis)
        acr = resource_security_posture("Microsoft.ContainerRegistry/registries", {"adminUserEnabled": True})
        self.assertIn("Container Registry: usuário administrador habilitado", acr)
        gateway = resource_security_posture("Microsoft.Network/applicationGateways", {"webApplicationFirewallConfiguration": {"enabled": False}})
        self.assertIn("Application Gateway: WAF desabilitado", gateway)

    def test_security_posture_summary_is_explicit_and_aggregated(self):
        result = summarize_security_posture([
            {"type": "Microsoft.Storage/storageAccounts", "security_posture": "Storage: blob público habilitado; HTTPS-only desabilitado"},
            {"type": "Microsoft.Web/sites", "security_posture": "Nenhum sinal explícito retornado"},
        ])
        self.assertEqual(result["resources"], 2)
        self.assertEqual(result["resources_with_explicit_signals"], 1)
        self.assertEqual(result["signals_total"], 2)
        self.assertEqual(result["by_signal"][0]["resources"], 1)
        self.assertIn("ausência não é conformidade", result["coverage_note"])

    def test_governance_summary_aggregates_tags_owner_and_policy(self):
        result = summarize_governance_posture(
            [{"owner": "A definir", "tags": "env"}, {"owner": "Platform", "tags": "Nenhuma"}],
            [{"non_compliant": 1}, {"non_compliant": 0}],
        )
        self.assertEqual(result["resources_assessed"], 2)
        self.assertEqual(result["without_owner"], 1)
        self.assertEqual(result["without_environment_tag"], 1)
        self.assertEqual(result["policy_non_compliant"], 1)
        self.assertEqual(result["policy_compliance_rate"], 50.0)
        self.assertIn("não prova risco", result["interpretation"])

    def test_cross_domain_insights_include_explicit_azure_posture_signals(self):
        result = cross_domain_insights({
            "security_posture_summary": {
                "resources_with_explicit_signals": 2,
                "by_signal": [{"signal": "Storage: blob público habilitado", "resources": 2}],
            }
        })
        posture = next(item for item in result if item["id"] == "I-008")
        self.assertEqual(posture["affected"], 2)
        self.assertEqual(posture["severity"], "high")
        self.assertIn("explicitamente", posture["evidence"])

    def test_cross_domain_insights_include_governance_gaps_without_overclaiming(self):
        result = cross_domain_insights({
            "governance_summary": {
                "resources_assessed": 10,
                "without_owner": 6,
                "policy_evaluated": 10,
                "policy_non_compliant": 6,
            }
        })
        owner = next(item for item in result if item["id"] == "I-009")
        policy = next(item for item in result if item["id"] == "I-010")
        self.assertEqual(owner["severity"], "high")
        self.assertEqual(policy["affected"], 6)
        self.assertIn("Validar", policy["action"])
        self.assertEqual(owner["priority"], "P2")
        self.assertEqual(policy["suggested_owner"], "Cloud Governance")
        self.assertIn(policy["effort_band"], {"Baixo", "Médio", "Alto"})

    def test_policy_summary_groups_evidence_and_assigns_risk(self):
        result = summarize_policy_compliance([
            {"policy": "Require TLS", "assignment": "baseline", "subscription": "sub1", "non_compliant": 1},
            {"policy": "Require TLS", "assignment": "baseline", "subscription": "sub1", "non_compliant": 0},
        ])
        self.assertEqual(result[0]["evaluated"], 2)
        self.assertEqual(result[0]["non_compliant"], 1)
        self.assertEqual(result[0]["compliance_rate"], 50.0)
        self.assertEqual(result[0]["risk_signal"], "Atenção")

    def test_policy_unknown_state_is_evidence_gap_not_non_compliance(self):
        unknown = policy_row({"policyDefinitionName": "Require TLS", "policyAssignmentName": "baseline", "complianceState": "Unknown", "subscriptionId": "sub1"})
        compliant = policy_row({"policyDefinitionName": "Require TLS", "policyAssignmentName": "baseline", "complianceState": "Compliant", "subscriptionId": "sub1"})
        result = summarize_policy_compliance([unknown, compliant])
        self.assertEqual(unknown["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(unknown["non_compliant"], 0)
        self.assertEqual(result[0]["observations"], 2)
        self.assertEqual(result[0]["evaluated"], 1)
        self.assertEqual(result[0]["insufficient_evidence"], 1)
        self.assertEqual(result[0]["compliance_rate"], 100.0)
        self.assertEqual(result[0]["evidence_coverage"], 50.0)

    def test_service_health_row_handles_raw_properties(self):
        row = retirement_row({"name": "event-1", "properties": {"Title": "Retirement advisory", "EventType": "HealthAdvisory", "Status": "Active", "TrackingId": "t1"}})
        self.assertEqual(row["service"], "Retirement advisory")
        self.assertEqual(row["status"], "Active")
        self.assertEqual(row["tracking_id"], "t1")

    def test_engine_version_is_loaded_from_single_source(self):
        from version import engine_version
        self.assertEqual(engine_version(), (ROOT / "VERSION").read_text(encoding="utf-8").strip())

    def test_engagement_config_is_local_metadata_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "engagement.yaml"
            path.write_text("customer_name: Cliente Demo\nconsultant_name: Lucas\nsubscriptions: all\n", encoding="utf-8")
            result = load_engagement(path)
        self.assertEqual(result["customer_name"], "Cliente Demo")
        self.assertEqual(result["consultant_name"], "Lucas")
        self.assertNotIn("subscriptions", result)

    def test_lab_validation_summary_is_cross_platform_and_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for profile in ("security", "governance", "full"):
                folder = root / profile
                folder.mkdir()
                (folder / "pilot-validation.json").write_text(json.dumps({"status": "ready_for_pilot_review", "quality_audit": {"metrics": {"coverage": 80, "overall_score": 34.5}}, "modules_unavailable_or_error": 1, "warnings": ["limited"]}), encoding="utf-8")
                (folder / "manifest-validation.json").write_text(json.dumps({"status": "valid"}), encoding="utf-8")
                (folder / "assessment.json").write_text(json.dumps({"discovery": {"collection_log": [{"module": "Módulo teste", "status": "not_available", "records": 0, "note": "user@example.com"}]}}), encoding="utf-8")
            result = summarize_lab_validation(root)
            self.assertTrue(result["read_only"])
            self.assertEqual(set(result["profiles"]), {"security", "governance", "full"})
            self.assertEqual(result["overall_status"], "warning")
            self.assertEqual(result["profiles"]["governance"]["readiness"], "warning")
            self.assertEqual(result["profiles"]["full"]["artifact_integrity"], "valid")
            self.assertEqual(result["profiles"]["full"]["control_coverage_percent"], 80)
            self.assertTrue(result["profiles"]["full"]["score_is_provisional"])
            self.assertEqual(result["profiles"]["full"]["collection_issues"], [{"module": "Módulo teste", "status": "not_available", "records": 0}])
            self.assertNotIn("user@example.com", json.dumps(result))

    def test_lab_validation_summary_blocks_on_invalid_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / "full"
            folder.mkdir()
            (folder / "pilot-validation.json").write_text(json.dumps({"status": "ready_for_pilot_review", "quality_audit": {"metrics": {"coverage": 100, "overall_score": 80}}, "warnings": [], "errors": []}), encoding="utf-8")
            (folder / "manifest-validation.json").write_text(json.dumps({"status": "invalid"}), encoding="utf-8")
            result = summarize_lab_validation(root)
        self.assertEqual(result["overall_status"], "blocked")
        self.assertEqual(result["profiles"]["full"]["readiness"], "blocked")

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

    def test_history_dashboard_is_aggregate_only_and_handles_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            history = Path(temporary)
            (history / "run-1.json").write_text(json.dumps({
                "run_id": "run-1",
                "collected_at": "2026-09-28T12:00:00Z",
                "engine_version": "0.2.0-beta.72",
                "overall_score": 61.2,
                "coverage": 80.0,
                "scope": {"users": 10, "secret_scope": "ignored"},
                "modules": {"identity": {"status": "ok"}, "defender": {"status": "not_available"}},
                "controls": [{"id": "c1", "score": 1, "status": "pass", "confidence": "high"}],
                "findings": [{"id": "f1", "control_id": "c1", "severity": "high", "risk_score": 8, "title": "private"}],
            }), encoding="utf-8")
            rows = load_history(history)
            output = render_history_dashboard(history)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scope"], {"users": 10})
        self.assertIn("61.2", output)
        self.assertIn("not_available: 1", output)
        self.assertNotIn("private", output)
        self.assertNotIn("secret_scope", output)
        self.assertIn("nenhum tenant foi acessado", output.lower())


if __name__ == "__main__":
    unittest.main()
