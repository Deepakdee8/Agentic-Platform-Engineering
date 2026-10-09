"""
Domain models for Risk Assessment.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class BlastRadius:
    affected_services_count: int
    direct_dependencies: List[str]
    has_internet_facing_impact: bool
    potential_downtime_minutes: int
    data_loss_risk: bool = False


@dataclass
class RiskAssessment:
    score: int  # 0 to 100
    risk_level: RiskLevel
    blast_radius: BlastRadius
    reversibility: str  # "FULL", "PARTIAL", "IRREVERSIBLE"
    factors: List[str] = field(default_factory=list)
    rationale: str = ""
