"""
Unit & Integration Tests for Compliance Remediation Engine.
"""
import unittest
from src.compliance_engine.models import (
    ComplianceFinding,
    ResourceDetails,
    Severity,
    EnvironmentTier,
    FindingCategory,
    RiskLevel,
    ActionDecision,
    PlanStatus,
)
from src.compliance_engine.governance.risk_engine import RiskEngine
from src.compliance_engine.governance.policy_engine import PolicyEngine
from src.compliance_engine.governance.approval_engine import ApprovalEngine
from src.compliance_engine.planner.remediation_planner import RemediationPlanner
from src.compliance_engine.tools.gcs_tools import GCSPublicAccessRemediationTool
from src.compliance_engine.tools.firewall_tools import FirewallRestrictSSHRemediationTool
from src.compliance_engine.validation.validator import ComplianceValidator
from src.compliance_engine.orchestrator import ComplianceOrchestrator


class TestComplianceEngine(unittest.TestCase):

    def setUp(self):
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.approval_engine = ApprovalEngine()
        self.planner = RemediationPlanner(self.risk_engine)
        self.validator = ComplianceValidator()
        self.orchestrator = ComplianceOrchestrator()

        self.dev_finding = ComplianceFinding(
            finding_id="TEST-DEV-001",
            source="SCC",
            category=FindingCategory.STORAGE_PUBLIC_ACCESS,
            severity=Severity.HIGH,
            compliance_standard="CIS GCP 5.1",
            description="Public bucket test",
            resource=ResourceDetails(
                resource_id="projects/dev-p/buckets/test-bucket-dev",
                resource_name="test-bucket-dev",
                resource_type="storage.googleapis.com/Bucket",
                project_id="dev-p",
                environment=EnvironmentTier.DEVELOPMENT,
                current_state={
                    "iam_bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
                    "public_access_prevention": "unspecified",
                },
            ),
        )

        self.prod_finding = ComplianceFinding(
            finding_id="TEST-PROD-001",
            source="SCC",
            category=FindingCategory.FIREWALL_OPEN_INGRESS,
            severity=Severity.CRITICAL,
            compliance_standard="CIS GCP 3.6",
            description="Open SSH test",
            resource=ResourceDetails(
                resource_id="projects/prod-p/global/firewalls/allow-ssh",
                resource_name="allow-ssh",
                resource_type="compute.googleapis.com/Firewall",
                project_id="prod-p",
                environment=EnvironmentTier.PRODUCTION,
                current_state={"source_ranges": ["0.0.0.0/0"]},
            ),
        )

    def test_risk_assessment_environment_scaling(self):
        risk_dev = self.risk_engine.assess_risk(self.dev_finding, "Remove allUsers")
        risk_prod = self.risk_engine.assess_risk(self.prod_finding, "Restrict to IAP")

        self.assertLess(risk_dev.score, risk_prod.score)
        self.assertIn(risk_dev.risk_level, [RiskLevel.LOW, RiskLevel.MEDIUM])
        self.assertIn(risk_prod.risk_level, [RiskLevel.HIGH, RiskLevel.CRITICAL])

    def test_policy_governance_gates(self):
        risk_dev = self.risk_engine.assess_risk(self.dev_finding, "action")
        policy_dev = self.policy_engine.evaluate(self.dev_finding, risk_dev)
        self.assertEqual(policy_dev.decision, ActionDecision.AUTO_EXECUTE)

        risk_prod = self.risk_engine.assess_risk(self.prod_finding, "action")
        policy_prod = self.policy_engine.evaluate(self.prod_finding, risk_prod)
        self.assertEqual(policy_prod.decision, ActionDecision.REQUIRE_HUMAN_APPROVAL)

    def test_gcs_remediation_tool(self):
        tool = GCSPublicAccessRemediationTool()
        params = {
            "bucket_name": "test-bucket-dev",
            "current_iam_bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers", "user:admin@example.com"]}
            ],
        }
        success, msg, metadata = tool.execute(params, simulate=True)
        self.assertTrue(success)
        self.assertEqual(metadata["public_access_prevention"], "enforced")
        self.assertIn("allUsers (roles/storage.objectViewer)", metadata["removed_members"])

    def test_firewall_remediation_tool(self):
        tool = FirewallRestrictSSHRemediationTool()
        params = {
            "firewall_name": "allow-ssh",
            "new_source_ranges": ["35.235.240.0/20"],
        }
        success, msg, metadata = tool.execute(params, simulate=True)
        self.assertTrue(success)
        self.assertEqual(metadata["updated_source_ranges"], ["35.235.240.0/20"])

    def test_orchestrator_auto_heal_dev(self):
        result = self.orchestrator.process_finding(self.dev_finding, simulate=True)
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "RESOLVED")
        self.assertEqual(result["plan"].status, PlanStatus.COMPLETED)
        self.assertEqual(result["audit"].approval_status, "AUTO_APPROVED")

    def test_orchestrator_hitl_approval_prod(self):
        # Case 1: Human approves
        result_approved = self.orchestrator.process_finding(
            self.prod_finding,
            approval_callback=lambda plan, ticket: True,
            simulate=True,
        )
        self.assertTrue(result_approved["success"])
        self.assertEqual(result_approved["audit"].approval_status, "MANUALLY_APPROVED")

        # Case 2: Human rejects
        prod_finding_2 = ComplianceFinding(
            finding_id="TEST-PROD-002",
            source="SCC",
            category=FindingCategory.FIREWALL_OPEN_INGRESS,
            severity=Severity.CRITICAL,
            compliance_standard="CIS GCP 3.6",
            description="Open SSH test 2",
            resource=ResourceDetails(
                resource_id="projects/prod-p/global/firewalls/allow-ssh-2",
                resource_name="allow-ssh-2",
                resource_type="compute.googleapis.com/Firewall",
                project_id="prod-p",
                environment=EnvironmentTier.PRODUCTION,
                current_state={"source_ranges": ["0.0.0.0/0"]},
            ),
        )
        result_rejected = self.orchestrator.process_finding(
            prod_finding_2,
            approval_callback=lambda plan, ticket: False,
            simulate=True,
        )
        self.assertFalse(result_rejected["success"])
        self.assertEqual(result_rejected["status"], "REJECTED")
        self.assertEqual(result_rejected["audit"].approval_status, "REJECTED")

    def test_enterprise_data_loaders(self):
        from data.loader import (
            load_resources,
            load_policies,
            load_raw_findings,
            get_ranked_findings,
            get_compliance_stats,
            get_finding_by_key,
        )
        from src.compliance_engine.comprehensive_orchestrator import ComprehensiveComplianceOrchestrator

        resources = load_resources()
        self.assertGreaterEqual(len(resources), 20)

        policies = load_policies()
        self.assertGreaterEqual(len(policies), 15)

        findings = load_raw_findings()
        self.assertGreaterEqual(len(findings), 20)

        # Verify findings are sorted by risk score descending
        ranked = get_ranked_findings()
        scores = [f.get("risk_assessment", {}).get("score", 0) for f in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))

        # Check stats
        stats = get_compliance_stats()
        self.assertIn("compliance_score_percent", stats)
        self.assertIn("severity_distribution", stats)
        self.assertEqual(stats["severity_distribution"]["CRITICAL"], 5)

        # Test comprehensive planner on every finding
        orchestrator = ComprehensiveComplianceOrchestrator()
        for f_dict in findings:
            scenario_key = f_dict.get("scenario_key")
            finding_obj = get_finding_by_key(scenario_key)
            self.assertIsNotNone(finding_obj)
            plan = orchestrator.planner.plan_remediation(finding_obj)
            self.assertIsNotNone(plan.plan_id)
            self.assertIsNotNone(plan.action_title)


class TestComplianceAgent(unittest.TestCase):

    def setUp(self):
        from src.compliance_engine.agent.compliance_agent import ComplianceAgent
        self.agent = ComplianceAgent()

    def test_autoheal_violations_query(self):
        query = "how many auto-heal violations are present?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "AUTOHEAL_VIOLATIONS")
        self.assertEqual(res["count"], 16)
        self.assertEqual(res["sidebar_filter"], "autoheal")
        self.assertTrue(res["issues_first"])
        self.assertIn("AUTO-HEAL ELIGIBLE VIOLATIONS REPORT", res["answer_markdown"])
        self.assertIn("16 ACTIVE VIOLATIONS", res["answer_markdown"])
        self.assertIn("Fleet Batch Dev Buckets", res["answer_markdown"])
        self.assertIn("retail-app-invoices-dev", res["answer_markdown"])

    def test_prod_violations_query(self):
        query = "how many prod violations are present?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "PROD_VIOLATIONS")
        self.assertEqual(res["count"], 16)
        self.assertEqual(res["sidebar_filter"], "hitl")
        self.assertTrue(res["issues_first"])
        self.assertIn("16 Production Violations", res["answer_markdown"])
        self.assertIn("payments-gke-prod", res["answer_markdown"])
        self.assertIn("allow-ssh-ingress", res["answer_markdown"])

    def test_zero_violation_resource_query(self):
        query = "in which resource violations are not present?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "ZERO_VIOLATION_RESOURCE")
        self.assertEqual(res["resource_name"], "secure-backup-vault-prod")
        self.assertEqual(res["sidebar_filter"], "clean")
        self.assertIn("secure-backup-vault-prod", res["answer_markdown"])
        self.assertIn("ZERO-VIOLATION", res["answer_markdown"])
        self.assertIn("no any issues are violating", res["answer_markdown"])

    def test_are_there_any_resource_in_which_issues_are_not_violating(self):
        query = "are there any resource in which issues are not violating"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "ZERO_VIOLATION_RESOURCE")
        self.assertEqual(res["resource_name"], "secure-backup-vault-prod")
        self.assertEqual(res["sidebar_filter"], "clean")
        self.assertIn("secure-backup-vault-prod", res["answer_markdown"])
        self.assertIn("no any issues are violating", res["answer_markdown"])

    def test_non_violating_controls_query(self):
        query = "which issues are not violating?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "NON_VIOLATING_CONTROLS")
        self.assertEqual(res["resource_name"], "analytics-warehouse-export-prod")
        self.assertEqual(res["sidebar_filter"], "partial")
        self.assertTrue(res["issues_first"])
        self.assertIn("Public Access Prevention (PAP)", res["answer_markdown"])
        self.assertIn("Object Lifecycle Management", res["answer_markdown"])
        self.assertIn("Uniform Bucket-Level Access (UBLA)", res["answer_markdown"])
        self.assertIn("analytics-warehouse-export-prod", res["answer_markdown"])

    def test_risk_ranking_query(self):
        query = "rank resources according to risk"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "RANKED_RISK")
        self.assertIn("TOP RANKED VIOLATIONS BY COMPOSITE RISK SCORE", res["answer_markdown"])
        self.assertIn("allow-ssh-ingress", res["answer_markdown"])

    def test_scoped_autoheal_gke_query(self):
        query = "in GKE resource how many auto-heal issues are violating?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "SCOPED_AUTOHEAL_VIOLATIONS")
        self.assertEqual(res["scope"], "gke")
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["sidebar_filter"], "gke-autoheal")
        self.assertTrue(res["issues_first"])
        self.assertIn("order-processing-cluster", res["answer_markdown"])
        self.assertIn("1 AUTO-HEAL VIOLATION IN GKE", res["answer_markdown"])

    def test_scoped_autoheal_gke_or_other_resource_query(self):
        query = "in GKE resource or any other resource how many auto-heal issues are violating?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "SCOPED_AUTOHEAL_VIOLATIONS")
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["sidebar_filter"], "gke-autoheal")
        self.assertIn("order-processing-cluster", res["answer_markdown"])
        self.assertIn("Auto-Heal Violations Across All Other GCP Resources", res["answer_markdown"])
        self.assertIn("Cloud Storage", res["answer_markdown"])

    def test_scoped_autoheal_sql_query(self):
        query = "in SQL resource how many auto-heal issues are violating?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "SCOPED_AUTOHEAL_VIOLATIONS")
        self.assertEqual(res["scope"], "sql")
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["sidebar_filter"], "sql-autoheal")
        self.assertIn("analytics-mysql-dev", res["answer_markdown"])

    def test_scoped_autoheal_storage_query(self):
        query = "in storage resource how many auto-heal issues are violating?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "SCOPED_AUTOHEAL_VIOLATIONS")
        self.assertEqual(res["scope"], "gcs")
        self.assertEqual(res["count"], 12)
        self.assertEqual(res["sidebar_filter"], "gcs-autoheal")
        self.assertIn("retail-app-invoices-dev", res["answer_markdown"])

    def test_scoped_prod_gke_query(self):
        query = "in GKE resource how many prod violations are present?"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "SCOPED_PROD_VIOLATIONS")
        self.assertEqual(res["scope"], "gke")
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["sidebar_filter"], "gke-prod")
        self.assertIn("payments-gke-prod", res["answer_markdown"])

    def test_bucket_public_and_object_authenticated_urls_query(self):
        query = "any specific bucket is giving more publicly accessible but any object is having exposing authenticated URL's"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "BUCKET_OBJECT_EXPOSURE_AUDIT")
        self.assertEqual(res["sidebar_filter"], "gcs")
        self.assertEqual(res["resource_name"], "retail-app-invoices-dev")
        self.assertTrue(res["action_available"])
        self.assertEqual(res["scenario_key"], "gcs-multi-issue")
        self.assertIn("retail-app-invoices-dev", res["answer_markdown"])
        self.assertIn("Uniform Bucket-Level Access (UBLA)", res["answer_markdown"])
        self.assertIn("Public Access Prevention (PAP)", res["answer_markdown"])
        self.assertIn("allAuthenticatedUsers", res["answer_markdown"])
        self.assertIn("Act On This: Auto-Heal Bucket", res["answer_markdown"])

    def test_action_prompt_execution(self):
        query = "act on it"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "EXECUTE_REMEDIATION")
        self.assertTrue(res["action_executable"])
        self.assertEqual(res["scenario_key"], "gcs-multi-issue")
        self.assertIn("retail-app-invoices-dev", res["answer_markdown"])

    def test_configuration_search_firewall(self):
        query = "what is the configuration of port 22 open ingress on firewall"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "RESOURCE_DETAIL")
        self.assertEqual(res["resource_name"], "allow-ssh-ingress")
        self.assertIn("allow-ssh-ingress", res["answer_markdown"])

    def test_agent_executable_query(self):
        query = "what is agent executable"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "AGENT_EXECUTABLE_OVERVIEW")
        self.assertTrue(res["action_available"])
        self.assertIn("WHAT IS AGENT EXECUTABLE", res["answer_markdown"])
        self.assertIn("Deterministic Idempotency", res["answer_markdown"])

    def test_multi_agent_query(self):
        query = "what are the multiple agents"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "MULTIPLE_AGENTS_OVERVIEW")
        self.assertEqual(res["agents_count"], 5)
        self.assertIn("Remediation Dispatcher Agent", res["answer_markdown"])
        self.assertIn("Security & Compliance Auditor Agent", res["answer_markdown"])

    def test_skills_query(self):
        query = "what multiple skills are defined"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "MULTIPLE_SKILLS_OVERVIEW")
        self.assertEqual(res["skills_count"], 7)
        self.assertIn("gcs-storage-hardening", res["answer_markdown"])
        self.assertIn("gke-cluster-defense", res["answer_markdown"])

    def test_tools_query(self):
        query = "what all tools defined for this"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "DEFINED_TOOLS_OVERVIEW")
        self.assertEqual(res["tools_count"], 7)
        self.assertIn("gcp_asset_inventory_tool", res["answer_markdown"])
        self.assertIn("rego_policy_evaluator", res["answer_markdown"])


    def test_fleet_incidents_query(self):
        query = "show all 36 violated resources and repeating issues at 1000 scale"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "FLEET_INCIDENTS_OVERVIEW")
        self.assertEqual(res["violated_resources"], 36)
        self.assertIn("Repeating Issue Signatures", res["answer_markdown"])

    def test_gcp_connector_query(self):
        query = "how does this connect to gcp and cloud asset inventory"
        res = self.agent.process_query(query)
        self.assertEqual(res["intent"], "GCP_CONNECTOR_OVERVIEW")
        self.assertEqual(res["connection_status"], "READY")
        self.assertIn("Cloud Asset Inventory API", res["answer_markdown"])

    def test_split_sql_findings_and_loader(self):
        from data.loader import get_all_findings, get_resource_by_id, load_policies, load_remediations
        findings = get_all_findings()
        self.assertEqual(len(findings), 20)

        # Check split findings
        backup_f = next((f for f in findings if f.finding_id == "SCC-SQL-MULTI-4401"), None)
        ssl_f = next((f for f in findings if f.finding_id == "SCC-SQL-MULTI-4401-SSL"), None)
        self.assertIsNotNone(backup_f)
        self.assertIsNotNone(ssl_f)
        self.assertEqual(backup_f.category, FindingCategory.DATABASE_BACKUP_DISABLED)
        self.assertEqual(ssl_f.category, FindingCategory.DATABASE_SSL_ENFORCEMENT)

        # Check resource reconciliation
        res = get_resource_by_id("analytics-warehouse-export-prod")
        self.assertIsNotNone(res)
        self.assertEqual(res["compliance_posture"]["status"], "UNKNOWN_REQUIRES_RESCAN")
        self.assertEqual(res["compliance_posture"]["passing_controls_count"], 3)
        self.assertEqual(res["compliance_posture"]["active_violations_count"], 0)

        # Check policy and remediation coverage
        policies = load_policies()
        remediations = load_remediations()
        self.assertEqual(len(policies), 18)
        self.assertEqual(len(remediations), 18)

    def test_comprehensive_planner_new_categories(self):
        from src.compliance_engine.planner.comprehensive_planner import ComprehensiveRemediationPlanner
        from src.compliance_engine.governance.risk_engine import RiskEngine
        from data.loader import get_finding_by_key
        planner = ComprehensiveRemediationPlanner(RiskEngine())

        # Test SSL finding
        ssl_finding = get_finding_by_key("sql-ssl-enforcement")
        self.assertIsNotNone(ssl_finding)
        ssl_plan = planner.plan_remediation(ssl_finding)
        self.assertEqual(ssl_plan.tool_name, "gcp_sql_enforce_ssl_only")
        self.assertEqual(ssl_plan.rollback_procedure.strategy_type, "SAFE_STOP_AND_RESTORE_COMPLIANT_SNAPSHOT")

        # Test Cloud Function finding
        func_finding = get_finding_by_key("func-runtime-dev")
        self.assertIsNotNone(func_finding)
        func_plan = planner.plan_remediation(func_finding)
        self.assertEqual(func_plan.tool_name, "gcp_cloudfunction_harden")
        self.assertEqual(func_plan.rollback_procedure.strategy_type, "SAFE_STOP_AND_RESTORE_COMPLIANT_SNAPSHOT")


if __name__ == "__main__":
    unittest.main()


