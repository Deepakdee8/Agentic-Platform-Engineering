"""
Risk Assessment Engine.
Calculates blast radius, environment weighting, and risk scores (0-100).
"""
from typing import Dict, Any, List
from src.compliance_engine.models import (
    ComplianceFinding,
    EnvironmentTier,
    FindingCategory,
    RiskLevel,
    BlastRadius,
    RiskAssessment,
)


class RiskEngine:
    """
    Deterministic Risk Engine implementing Section 13 of the PRD:
    Risk = Resource Criticality + Environment + Change Type + Blast Radius + Reversibility.
    """

    ENVIRONMENT_WEIGHTS = {
        EnvironmentTier.SANDBOX: 10,
        EnvironmentTier.DEVELOPMENT: 25,
        EnvironmentTier.STAGING: 50,
        EnvironmentTier.PRODUCTION: 85,
    }

    CATEGORY_WEIGHTS = {
        FindingCategory.STORAGE_PUBLIC_ACCESS: 35,
        FindingCategory.FIREWALL_OPEN_INGRESS: 75,
        FindingCategory.DATABASE_PUBLIC_IP: 65,
        FindingCategory.IAM_EXCESSIVE_PRIVILEGE: 80,
        FindingCategory.UNENCRYPTED_RESOURCE: 30,
    }

    def assess_risk(self, finding: ComplianceFinding, proposed_action: str) -> RiskAssessment:
        env = finding.resource.environment
        category = finding.category

        env_weight = self.ENVIRONMENT_WEIGHTS.get(env, 50)
        category_weight = self.CATEGORY_WEIGHTS.get(category, 40)

        cat_str = category.value if hasattr(category, "value") else str(category)
        factors: List[str] = []
        factors.append(f"Target Environment: {env.value.upper()} (weight: {env_weight})")
        factors.append(f"Violation Category: {cat_str} (criticality: {category_weight})")

        # Determine Blast Radius
        if category == FindingCategory.FIREWALL_OPEN_INGRESS:
            blast_radius = BlastRadius(
                affected_services_count=5 if env == EnvironmentTier.PRODUCTION else 1,
                direct_dependencies=["production-vpc", "kubernetes-node-pool", "bastion-host"],
                has_internet_facing_impact=True,
                potential_downtime_minutes=0,
                data_loss_risk=False,
            )
            factors.append("Network Firewall modification affects inbound VPC traffic routes.")
        elif category == FindingCategory.STORAGE_PUBLIC_ACCESS:
            blast_radius = BlastRadius(
                affected_services_count=1,
                direct_dependencies=["public-web-assets"],
                has_internet_facing_impact=True,
                potential_downtime_minutes=0,
                data_loss_risk=False,
            )
            factors.append("GCS Bucket IAM modification restricts public anonymous readers.")
        else:
            blast_radius = BlastRadius(
                affected_services_count=1,
                direct_dependencies=[],
                has_internet_facing_impact=False,
                potential_downtime_minutes=0,
                data_loss_risk=False,
            )

        # Composite score calculation: 40% Environment + 40% Category + 20% Blast radius
        blast_weight = 20 if blast_radius.affected_services_count > 1 else 10
        raw_score = int((env_weight * 0.45) + (category_weight * 0.40) + (blast_weight * 0.75))
        score = min(max(raw_score, 5), 98)

        if score < 30:
            level = RiskLevel.LOW
        elif score < 60:
            level = RiskLevel.MEDIUM
        elif score < 80:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        rationale = (
            f"Remediation in {env.value} for {cat_str} evaluated at {score}/100 ({level.value}). "
            f"Affects {blast_radius.affected_services_count} dependent service(s)."
        )

        return RiskAssessment(
            score=score,
            risk_level=level,
            blast_radius=blast_radius,
            reversibility="FULL",
            factors=factors,
            rationale=rationale,
        )
