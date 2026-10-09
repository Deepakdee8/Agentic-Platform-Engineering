"""
Human-in-the-Loop (HITL) Approval Engine.
Manages approval requests, approver tokens, and sign-offs.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List
from src.compliance_engine.models import RemediationPlan


@dataclass
class ApprovalTicket:
    ticket_id: str
    plan_id: str
    status: str  # "PENDING", "APPROVED", "REJECTED"
    requested_at: datetime
    decided_at: Optional[datetime] = None
    approver: Optional[str] = None
    comments: Optional[str] = None


class ApprovalEngine:
    """
    Manages human approvals for high-risk or production operations.
    """

    def __init__(self):
        self._tickets: dict[str, ApprovalTicket] = {}

    def create_request(self, plan: RemediationPlan) -> ApprovalTicket:
        ticket_id = f"APPR-{plan.plan_id.split('-')[-1]}"
        ticket = ApprovalTicket(
            ticket_id=ticket_id,
            plan_id=plan.plan_id,
            status="PENDING",
            requested_at=datetime.utcnow(),
        )
        self._tickets[ticket_id] = ticket
        return ticket

    def approve(self, ticket_id: str, approver: str, comments: str = "Approved via Platform CLI") -> ApprovalTicket:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            raise ValueError(f"Approval ticket {ticket_id} not found.")
        ticket.status = "APPROVED"
        ticket.approver = approver
        ticket.comments = comments
        ticket.decided_at = datetime.utcnow()
        return ticket

    def reject(self, ticket_id: str, approver: str, reason: str = "Rejected by reviewer") -> ApprovalTicket:
        ticket = self._tickets.get(ticket_id)
        if not ticket:
            raise ValueError(f"Approval ticket {ticket_id} not found.")
        ticket.status = "REJECTED"
        ticket.approver = approver
        ticket.comments = reason
        ticket.decided_at = datetime.utcnow()
        return ticket
