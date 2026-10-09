"""
Domain models for Immutable Compliance Audit Records.
"""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
from typing import Dict, Any, Optional


@dataclass
class AuditRecord:
    audit_id: str
    finding_id: str
    timestamp: str
    environment: str
    resource_id: str
    agent_id: str
    risk_level: str
    policy_decision: str
    approval_status: str  # "AUTO_APPROVED", "MANUALLY_APPROVED", "REJECTED"
    approved_by: Optional[str]
    tool_executed: str
    execution_status: str  # "SUCCESS", "FAILED", "ROLLED_BACK"
    validation_status: str  # "PASSED", "FAILED"
    proof_evidence: Dict[str, Any]
    checksum_sha256: str = ""

    def calculate_checksum(self) -> str:
        payload = {
            "audit_id": self.audit_id,
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "environment": self.environment,
            "resource_id": self.resource_id,
            "tool_executed": self.tool_executed,
            "execution_status": self.execution_status,
            "validation_status": self.validation_status,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
