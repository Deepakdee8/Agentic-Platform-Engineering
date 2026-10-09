"""
Immutable Audit Logging Engine.
Records cryptographic audit records for every compliance remediation event.
"""
from datetime import datetime
import json
import uuid
from typing import Dict, Any, Optional, List
from src.compliance_engine.models import (
    AuditRecord,
    ComplianceFinding,
    RemediationPlan,
    PolicyEvaluation,
)


class AuditVault:
    """
    Simulates append-only, tamper-evident audit store (BigQuery Vault)
    described in Section 33 & 54 of the PRD.
    """

    def __init__(self):
        self._records: List[AuditRecord] = []

    def log_remediation_event(
        self,
        finding: ComplianceFinding,
        plan: RemediationPlan,
        policy: PolicyEvaluation,
        approval_status: str,
        approved_by: Optional[str],
        execution_status: str,
        validation_status: str,
        proof_evidence: Dict[str, Any],
    ) -> AuditRecord:
        audit_id = f"AUDIT-{uuid.uuid4().hex[:8].upper()}"
        record = AuditRecord(
            audit_id=audit_id,
            finding_id=finding.finding_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            environment=finding.resource.environment.value,
            resource_id=finding.resource.resource_id,
            agent_id="gcp-compliance-remediation-agent-v1",
            risk_level=plan.risk_assessment.risk_level.value,
            policy_decision=policy.decision.value,
            approval_status=approval_status,
            approved_by=approved_by,
            tool_executed=plan.tool_name,
            execution_status=execution_status,
            validation_status=validation_status,
            proof_evidence=proof_evidence,
        )
        record.checksum_sha256 = record.calculate_checksum()
        self._records.append(record)
        return record

    def get_records(self) -> List[AuditRecord]:
        return list(self._records)
