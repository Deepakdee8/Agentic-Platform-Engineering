"""
Master Compliance Remediation Orchestrator.
Coordinates the entire lifecycle: Detect -> Ingest -> Plan -> Govern -> HITL -> Execute -> Validate -> Audit.
"""
from typing import Dict, Any, Optional, Callable
from src.compliance_engine.models import (
    ComplianceFinding,
    RemediationPlan,
    PolicyEvaluation,
    ActionDecision,
    PlanStatus,
    AuditRecord,
)
from src.compliance_engine.governance.risk_engine import RiskEngine
from src.compliance_engine.governance.policy_engine import PolicyEngine
from src.compliance_engine.governance.approval_engine import ApprovalEngine, ApprovalTicket
from src.compliance_engine.planner.remediation_planner import RemediationPlanner
from src.compliance_engine.tools.gcs_tools import GCSPublicAccessRemediationTool
from src.compliance_engine.tools.firewall_tools import FirewallRestrictSSHRemediationTool
from src.compliance_engine.validation.validator import ComplianceValidator
from src.compliance_engine.audit.audit_logger import AuditVault


class ComplianceOrchestrator:
    """
    Control Plane Orchestrator for Capability 2:
    Automated Environment Compliance Remediation.
    """

    def __init__(self):
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.approval_engine = ApprovalEngine()
        self.planner = RemediationPlanner(self.risk_engine)
        self.validator = ComplianceValidator()
        self.audit_vault = AuditVault()

        # Tool registry
        self.tool_registry = {
            "gcp_storage_remove_public_access": GCSPublicAccessRemediationTool(),
            "gcp_firewall_restrict_ssh_ingress": FirewallRestrictSSHRemediationTool(),
        }

    def process_finding(
        self,
        finding: ComplianceFinding,
        approval_callback: Optional[Callable[[RemediationPlan, ApprovalTicket], bool]] = None,
        simulate: bool = True,
    ) -> Dict[str, Any]:
        """
        Processes a compliance finding through the governed autonomous lifecycle.
        """
        # 1. AI Planning
        plan = self.planner.plan_remediation(finding)

        # 2. Policy Evaluation
        policy = self.policy_engine.evaluate(finding, plan.risk_assessment)

        approval_status = "NOT_REQUIRED"
        approved_by = None
        ticket = None

        # 3. Governance Gate
        if policy.decision == ActionDecision.BLOCKED_BY_POLICY:
            finding.status = "MUTED_POLICY_BLOCKED"
            audit = self.audit_vault.log_remediation_event(
                finding=finding,
                plan=plan,
                policy=policy,
                approval_status="BLOCKED",
                approved_by=None,
                execution_status="NOT_RUN",
                validation_status="SKIPPED",
                proof_evidence={"reason": policy.rationale},
            )
            return {
                "success": False,
                "plan": plan,
                "policy": policy,
                "status": "BLOCKED",
                "message": policy.rationale,
                "audit": audit,
            }

        elif policy.decision == ActionDecision.REQUIRE_HUMAN_APPROVAL:
            ticket = self.approval_engine.create_request(plan)
            # If a callback is provided (e.g. interactive CLI prompt), invoke it
            user_decision = False
            if approval_callback:
                user_decision = approval_callback(plan, ticket)

            if user_decision:
                self.approval_engine.approve(ticket.ticket_id, approver="Platform-Engineer@corp.internal")
                approval_status = "MANUALLY_APPROVED"
                approved_by = ticket.approver
                plan.status = PlanStatus.APPROVED
            else:
                self.approval_engine.reject(ticket.ticket_id, approver="Platform-Engineer@corp.internal", reason="Rejected by human reviewer")
                approval_status = "REJECTED"
                plan.status = PlanStatus.REJECTED
                finding.status = "ACTIVE_APPROVAL_REJECTED"
                audit = self.audit_vault.log_remediation_event(
                    finding=finding,
                    plan=plan,
                    policy=policy,
                    approval_status=approval_status,
                    approved_by=ticket.approver,
                    execution_status="CANCELLED",
                    validation_status="SKIPPED",
                    proof_evidence={"rejection_reason": ticket.comments},
                )
                return {
                    "success": False,
                    "plan": plan,
                    "policy": policy,
                    "ticket": ticket,
                    "status": "REJECTED",
                    "message": "Human reviewer rejected the remediation plan.",
                    "audit": audit,
                }

        else:
            # Auto-execute
            approval_status = "AUTO_APPROVED"
            approved_by = "System-Autonomous-Policy-Engine"
            plan.status = PlanStatus.APPROVED

        # 4. Deterministic Tool Execution
        tool = self.tool_registry.get(plan.tool_name)
        if not tool:
            raise RuntimeError(f"Tool {plan.tool_name} not found in Tool Registry.")

        plan.status = PlanStatus.EXECUTING
        exec_success, exec_msg, exec_metadata = tool.execute(plan.tool_parameters, simulate=simulate)

        if not exec_success:
            plan.status = PlanStatus.FAILED
            finding.status = "REMEDIATION_FAILED"
            # Trigger rollback
            tool.rollback(plan.rollback_procedure.snapshot_state, simulate=simulate)
            plan.status = PlanStatus.ROLLED_BACK
            audit = self.audit_vault.log_remediation_event(
                finding=finding,
                plan=plan,
                policy=policy,
                approval_status=approval_status,
                approved_by=approved_by,
                execution_status="ROLLED_BACK",
                validation_status="FAILED",
                proof_evidence={"execution_error": exec_msg},
            )
            return {
                "success": False,
                "plan": plan,
                "policy": policy,
                "status": "FAILED_ROLLED_BACK",
                "message": exec_msg,
                "audit": audit,
            }

        # 5. Closed-Loop Validation
        val_success, val_msg, val_evidence = self.validator.verify_remediation(finding, exec_metadata)

        if val_success:
            plan.status = PlanStatus.COMPLETED
            finding.status = "RESOLVED"
            validation_status = "PASSED"
        else:
            plan.status = PlanStatus.FAILED
            finding.status = "VALIDATION_FAILED"
            validation_status = "FAILED"

        # 6. Audit Logging
        audit = self.audit_vault.log_remediation_event(
            finding=finding,
            plan=plan,
            policy=policy,
            approval_status=approval_status,
            approved_by=approved_by,
            execution_status="SUCCESS",
            validation_status=validation_status,
            proof_evidence=val_evidence,
        )

        return {
            "success": val_success,
            "plan": plan,
            "policy": policy,
            "ticket": ticket,
            "execution_metadata": exec_metadata,
            "validation_message": val_msg,
            "status": "RESOLVED" if val_success else "VALIDATION_FAILED",
            "audit": audit,
        }
