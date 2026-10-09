"""
AI-assisted Remediation Planner.
Formulates structured Remediation Plans, technical diffs, and rollback procedures.
"""
import uuid
from typing import Dict, Any, List
from src.compliance_engine.models import (
    ComplianceFinding,
    FindingCategory,
    RemediationPlan,
    TechnicalDiff,
    RollbackProcedure,
    PlanStatus,
)
from src.compliance_engine.governance.risk_engine import RiskEngine


class RemediationPlanner:
    """
    Formulates safe, deterministic remediation plans based on CIS GCP benchmarks.
    """

    def __init__(self, risk_engine: RiskEngine):
        self.risk_engine = risk_engine

    def plan_remediation(self, finding: ComplianceFinding) -> RemediationPlan:
        plan_id = f"PLAN-{uuid.uuid4().hex[:8].upper()}"

        if finding.category == FindingCategory.STORAGE_PUBLIC_ACCESS:
            action_title = "Enforce Public Access Prevention and Strip Public IAM Bindings"
            rationale = (
                f"CIS GCP Benchmark 5.1 requires storage buckets to prohibit allUsers and "
                f"allAuthenticatedUsers. Public Access Prevention prevents accidental public disclosure."
            )
            diffs = [
                TechnicalDiff(
                    parameter="iam_bindings",
                    current_value=[{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
                    proposed_value=[],
                    description="Remove 'allUsers' from objectViewer role.",
                ),
                TechnicalDiff(
                    parameter="public_access_prevention",
                    current_value="unspecified",
                    proposed_value="enforced",
                    description="Enforce organization-wide public access prevention on bucket.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={
                    "bucket_name": finding.resource.resource_name,
                    "iam_bindings": finding.resource.current_state.get("iam_bindings", []),
                    "public_access_prevention": "unspecified",
                },
                steps=[
                    "Restore original IAM policy bindings from encrypted snapshot.",
                    "Set public_access_prevention to 'inherited'.",
                ],
                estimated_recovery_time_seconds=15,
            )
            tool_name = "gcp_storage_remove_public_access"
            tool_params = {
                "bucket_name": finding.resource.resource_name,
                "current_iam_bindings": finding.resource.current_state.get("iam_bindings", []),
            }

        elif finding.category == FindingCategory.FIREWALL_OPEN_INGRESS:
            action_title = "Restrict Inbound SSH Port 22 to Google Cloud IAP CIDR"
            rationale = (
                f"CIS GCP Benchmark 3.6 mandates that SSH port 22 must never be open to 0.0.0.0/0. "
                f"Restricting to Identity-Aware Proxy (35.235.240.0/20) allows secure admin tunneling without public exposure."
            )
            diffs = [
                TechnicalDiff(
                    parameter="source_ranges",
                    current_value=["0.0.0.0/0"],
                    proposed_value=["35.235.240.0/20"],
                    description="Replace global internet CIDR with GCP IAP tunnel range.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={
                    "firewall_name": finding.resource.resource_name,
                    "source_ranges": ["0.0.0.0/0"],
                },
                steps=[
                    "Re-apply original source_ranges ['0.0.0.0/0'] to firewall rule.",
                ],
                estimated_recovery_time_seconds=20,
            )
            tool_name = "gcp_firewall_restrict_ssh_ingress"
            tool_params = {
                "firewall_name": finding.resource.resource_name,
                "new_source_ranges": ["35.235.240.0/20"],
            }

        else:
            action_title = f"Generic Remediation for {finding.category.value}"
            rationale = "Remediate according to baseline security controls."
            diffs = []
            rollback = RollbackProcedure(
                strategy_type="MANUAL_RUNBOOK",
                snapshot_state={},
                steps=["Review cloud logs."],
            )
            tool_name = "generic_tool"
            tool_params = {}

        # Assess risk
        risk = self.risk_engine.assess_risk(finding, action_title)

        return RemediationPlan(
            plan_id=plan_id,
            finding_id=finding.finding_id,
            target_resource_id=finding.resource.resource_id,
            action_title=action_title,
            rationale=rationale,
            governing_standard=finding.compliance_standard,
            diffs=diffs,
            risk_assessment=risk,
            rollback_procedure=rollback,
            tool_name=tool_name,
            tool_parameters=tool_params,
            status=PlanStatus.DRAFTED,
        )
