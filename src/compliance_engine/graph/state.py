"""
LangGraph Compliance State Definition for Capability 2:
Automated Environment Compliance Remediation.
"""
from typing import Dict, Any, List, Optional, TypedDict


class ComplianceGraphState(TypedDict, total=False):
    """
    Unified state flowing through the LangGraph Multi-Agent Remediation Pipeline.
    """
    # 1. Ingestion / Input
    thread_id: str
    scenario_key: str
    finding: Dict[str, Any]
    finding_id: str
    resource_id: str
    resource_name: str
    service: str
    environment: str

    # 2. Triage & Classification Agent Output
    triage: Dict[str, Any]
    # { "compliance_standard": str, "policy_id": str, "category": str, "description": str, "reasoning_steps": List[str] }

    # 3. Blast Radius & Risk Assessment Agent Output
    risk: Dict[str, Any]
    # { "score": int, "level": str, "affected_services": int, "data_loss_risk": bool, "downtime_minutes": int, "rationale": str }

    # 4. Remediation Planner Agent Output
    plan: Dict[str, Any]
    # { "plan_id": str, "action_title": str, "rationale": str, "tool_name": str, "tool_parameters": Dict[str, Any], "diff": Dict[str, str], "rollback": Dict[str, Any] }

    # 5. Policy & Governance Evaluation
    policy: Dict[str, Any]
    # { "governing_policy": str, "decision": str, "requires_hitl": bool, "rationale": str }

    # 6. Human-in-the-Loop (HITL) Gate State
    approval_ticket_id: Optional[str]
    approval_decision: Optional[str]   # "APPROVE" | "REJECT" | "PENDING"
    approved_by: Optional[str]
    approval_reason: Optional[str]

    # 7. Execution Engine State
    execution: Optional[Dict[str, Any]]
    # { "success": bool, "message": str, "metadata": Dict[str, Any] }

    # 8. Post-Remediation Verification & Audit Agent Output
    verification: Optional[Dict[str, Any]]
    # { "verified": bool, "message": str, "synthetic_probe": str }
    audit: Optional[Dict[str, Any]]
    # { "audit_id": str, "checksum_sha256": str, "timestamp": str }

    # Status & Telemetry
    current_step: str
    status: str  # "TRIAGED" | "PLANNED" | "WAITING_APPROVAL" | "APPROVED" | "REJECTED" | "EXECUTED" | "RESOLVED" | "FAILED"
    error: Optional[str]
    messages: List[Dict[str, str]]
