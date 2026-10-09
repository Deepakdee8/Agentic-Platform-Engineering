"""
Policy Governance Engine.
Evaluates enterprise compliance policies and determines autonomous vs human-gated decisions.
"""
from typing import List
from src.compliance_engine.models import (
    ComplianceFinding,
    EnvironmentTier,
    RiskAssessment,
    RiskLevel,
    ActionDecision,
    PolicyEvaluation,
)


class PolicyEngine:
    """
    Evaluates enterprise governance rules following Section 12 of the PRD:
    'AI proposes, policy governs'.
    """

    POLICY_ID_NON_PROD_AUTO_HEAL = "POL-AUTO-001: Non-Prod Self-Healing"
    POLICY_ID_PROD_GATE = "POL-PROD-002: Production Mandatory Human Approval"
    POLICY_ID_HIGH_RISK_GATE = "POL-RISK-003: High/Critical Risk Sign-off Gate"
    POLICY_ID_DATA_LOSS_PROTECTION = "POL-SAFE-004: Anti-Data-Loss Invariant"

    def evaluate(self, finding: ComplianceFinding, risk: RiskAssessment) -> PolicyEvaluation:
        env = finding.resource.environment
        conditions: List[str] = []

        # 1. Anti-Data-Loss Invariant
        if risk.blast_radius.data_loss_risk:
            conditions.append("Data loss risk detected: Operation strictly blocked.")
            return PolicyEvaluation(
                decision=ActionDecision.BLOCKED_BY_POLICY,
                governing_policy=self.POLICY_ID_DATA_LOSS_PROTECTION,
                rationale="Enterprise policy strictly prohibits automated execution of actions with data loss risk.",
                conditions_checked=conditions,
            )

        # 2. Production Environment Invariant
        if env == EnvironmentTier.PRODUCTION:
            conditions.append("Environment is PRODUCTION: Zero autonomous mutations permitted.")
            return PolicyEvaluation(
                decision=ActionDecision.REQUIRE_HUMAN_APPROVAL,
                governing_policy=self.POLICY_ID_PROD_GATE,
                rationale="All production modifications require explicit human sign-off from a Platform Owner.",
                approver_roles=["Platform-Owner", "Cloud-Security-Lead", "SRE-Principal"],
                conditions_checked=conditions,
            )

        # 3. High or Critical Risk Invariant
        if risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            conditions.append(f"Risk tier is {risk.risk_level.value}: Exceeds autonomous execution threshold.")
            return PolicyEvaluation(
                decision=ActionDecision.REQUIRE_HUMAN_APPROVAL,
                governing_policy=self.POLICY_ID_HIGH_RISK_GATE,
                rationale=f"Risk level {risk.risk_level.value} requires secondary human validation.",
                approver_roles=["Platform-Engineer", "DevOps-Engineer"],
                conditions_checked=conditions,
            )

        # 4. Standard Non-Prod Autonomous Self-Healing
        conditions.append(f"Environment is {env.value.upper()} and Risk is {risk.risk_level.value}: Eligible for auto-remediation.")
        return PolicyEvaluation(
            decision=ActionDecision.AUTO_EXECUTE,
            governing_policy=self.POLICY_ID_NON_PROD_AUTO_HEAL,
            rationale="Non-production low/medium risk violations are pre-authorized for autonomous self-healing.",
            conditions_checked=conditions,
        )
