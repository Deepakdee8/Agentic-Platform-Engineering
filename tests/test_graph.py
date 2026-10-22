"""
Unit Tests for LangGraph Multi-Agent Automated Compliance Remediation Pipeline.
"""
import unittest
from src.compliance_engine.graph import (
    ComplianceWorkflowRunner,
    TriageAgent,
    RiskAssessmentAgent,
    RemediationPlannerAgent,
    VerificationAuditAgent,
)
from data.loader import load_raw_findings


class TestLangGraphCompliancePipeline(unittest.TestCase):

    def setUp(self):
        self.runner = ComplianceWorkflowRunner()
        self.raw_findings = load_raw_findings()

    def test_production_finding_requires_hitl(self):
        """Production finding (e.g. fw-open-ssh) must hold at WAITING_APPROVAL."""
        finding = next((f for f in self.raw_findings if f.get("scenario_key") == "fw-open-ssh"), None)
        self.assertIsNotNone(finding)

        state = self.runner.start_remediation(finding, thread_id="test-thread-prod")
        self.assertEqual(state.get("status"), "WAITING_APPROVAL")
        self.assertTrue(state.get("policy", {}).get("requires_hitl"))
        self.assertIsNotNone(state.get("approval_ticket_id"))
        self.assertIn("diff", state.get("plan", {}))

    def test_production_approval_resumption(self):
        """Approving a production finding executes mutations and records SHA-256 audit."""
        finding = next((f for f in self.raw_findings if f.get("scenario_key") == "fw-open-ssh"), None)
        thread_id = "test-thread-approval"
        self.runner.start_remediation(finding, thread_id=thread_id)

        resumed = self.runner.resume_with_decision(thread_id, decision="APPROVE", approver="Platform-Lead")
        self.assertEqual(resumed.get("status"), "RESOLVED")
        self.assertTrue(resumed.get("execution", {}).get("success"))
        self.assertTrue(resumed.get("verification", {}).get("verified"))
        self.assertIsNotNone(resumed.get("audit", {}).get("checksum_sha256"))
        self.assertEqual(len(resumed.get("audit", {}).get("checksum_sha256")), 64)

    def test_production_rejection_resumption(self):
        """Rejecting an approval aborts the change and escalates to SOC."""
        finding = next((f for f in self.raw_findings if f.get("scenario_key") == "fw-open-ssh"), None)
        thread_id = "test-thread-rejection"
        self.runner.start_remediation(finding, thread_id=thread_id)

        resumed = self.runner.resume_with_decision(thread_id, decision="REJECT", reason="Change window closed")
        self.assertEqual(resumed.get("status"), "ABORTED")
        self.assertFalse(resumed.get("execution", {}).get("success"))
        self.assertIn("aborted", resumed.get("execution", {}).get("message").lower())

    def test_development_finding_auto_heals(self):
        """Development findings (e.g. gcs-multi-issue) must auto-heal under POL-AUTO-001."""
        finding = next((f for f in self.raw_findings if f.get("environment") == "development"), None)
        self.assertIsNotNone(finding)

        state = self.runner.start_remediation(finding, thread_id="test-thread-dev")
        self.assertEqual(state.get("status"), "RESOLVED")
        self.assertFalse(state.get("policy", {}).get("requires_hitl"))
        self.assertEqual(state.get("policy", {}).get("decision"), "AUTO_APPROVED")
        self.assertIsNotNone(state.get("audit", {}).get("audit_id"))


if __name__ == "__main__":
    unittest.main()
