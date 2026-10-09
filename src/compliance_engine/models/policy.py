"""
Domain models for Policy Evaluation and Governance Decisions.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ActionDecision(str, Enum):
    AUTO_EXECUTE = "AUTO_EXECUTE"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


@dataclass
class PolicyEvaluation:
    decision: ActionDecision
    governing_policy: str
    rationale: str
    approver_roles: List[str] = field(default_factory=list)
    requires_change_window: bool = False
    is_in_change_window: bool = True
    conditions_checked: List[str] = field(default_factory=list)
