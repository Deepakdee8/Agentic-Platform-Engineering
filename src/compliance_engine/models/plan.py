"""
Domain models for Remediation Plans and Execution Diffs.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
from src.compliance_engine.models.risk import RiskAssessment


class PlanStatus(str, Enum):
    DRAFTED = "DRAFTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


@dataclass
class TechnicalDiff:
    parameter: str
    current_value: Any
    proposed_value: Any
    description: str


@dataclass
class RollbackProcedure:
    strategy_type: str  # "AUTOMATIC_RESTORE", "COMPENSATION_SCRIPT", "MANUAL_RUNBOOK"
    snapshot_state: Dict[str, Any]
    steps: List[str]
    estimated_recovery_time_seconds: int = 30


@dataclass
class RemediationPlan:
    plan_id: str
    finding_id: str
    target_resource_id: str
    action_title: str
    rationale: str
    governing_standard: str
    diffs: List[TechnicalDiff]
    risk_assessment: RiskAssessment
    rollback_procedure: RollbackProcedure
    tool_name: str
    tool_parameters: Dict[str, Any]
    status: PlanStatus = PlanStatus.DRAFTED
    created_at: datetime = field(default_factory=datetime.utcnow)
