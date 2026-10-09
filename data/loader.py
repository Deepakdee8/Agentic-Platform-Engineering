"""
Data loader and model converter for enterprise GCP compliance resources, policies, findings, and remediations.
"""
import json
import os
from typing import List, Dict, Any, Optional
from src.compliance_engine.models.finding import (
    ComplianceFinding,
    ResourceDetails,
    Severity,
    EnvironmentTier,
    FindingCategory,
)
import src.compliance_engine.models.extensions  # ensure category extensions loaded


DATA_DIR = os.path.dirname(__file__)
FINDINGS_FILE = os.path.join(DATA_DIR, "findings.json")
RESOURCES_FILE = os.path.join(DATA_DIR, "resources.json")
POLICIES_FILE = os.path.join(DATA_DIR, "policies.json")
REMEDIATIONS_FILE = os.path.join(DATA_DIR, "remediations.json")


def _read_json_file(file_path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


# --- Findings Loaders ---

def load_raw_findings() -> List[Dict[str, Any]]:
    """Loads all raw findings dictionaries from findings.json, ordered by rank/risk."""
    return _read_json_file(FINDINGS_FILE)


def get_finding_by_key(scenario_key: str) -> Optional[ComplianceFinding]:
    """Retrieves and parses a specific finding by scenario_key or finding_id."""
    raws = load_raw_findings()
    for item in raws:
        if item.get("scenario_key") == scenario_key or item.get("finding_id") == scenario_key:
            return _dict_to_finding(item)
    return None


def get_all_findings() -> List[ComplianceFinding]:
    """Returns all findings parsed as typed ComplianceFinding domain objects."""
    raws = load_raw_findings()
    return [_dict_to_finding(item) for item in raws]


def get_ranked_findings() -> List[Dict[str, Any]]:
    """Returns findings sorted in descending order of risk score (highest risk first)."""
    raws = load_raw_findings()
    return sorted(
        raws,
        key=lambda x: x.get("risk_assessment", {}).get("score", 0),
        reverse=True
    )


# --- Resources Loaders ---

def load_resources() -> List[Dict[str, Any]]:
    """Loads all existing GCP resources in the enterprise organization from resources.json."""
    return _read_json_file(RESOURCES_FILE)


def get_all_resources() -> List[Dict[str, Any]]:
    """Alias for load_resources."""
    return load_resources()


def get_resource_by_id(resource_id: str) -> Optional[Dict[str, Any]]:
    """Finds resource by resource_id or resource_name."""
    resources = load_resources()
    for res in resources:
        if res.get("resource_id") == resource_id or res.get("resource_name") == resource_id:
            return res
    return None


# --- Policies Loaders ---

def load_policies() -> List[Dict[str, Any]]:
    """Loads enterprise compliance policies from policies.json."""
    return _read_json_file(POLICIES_FILE)


def get_all_policies() -> List[Dict[str, Any]]:
    """Alias for load_policies."""
    return load_policies()


def get_policy_by_id(policy_id: str) -> Optional[Dict[str, Any]]:
    """Finds policy by policy_id."""
    policies = load_policies()
    for pol in policies:
        if pol.get("policy_id") == policy_id:
            return pol
    return None


# --- Remediations Loaders ---

def load_remediations() -> List[Dict[str, Any]]:
    """Loads remediation playbooks from remediations.json."""
    return _read_json_file(REMEDIATIONS_FILE)


def get_remediation_by_category(category: str) -> Optional[Dict[str, Any]]:
    """Finds remediation playbook by violation category."""
    remediations = load_remediations()
    for rem in remediations:
        if rem.get("category") == category:
            return rem
    return None


# --- Statistics and Posture Summary ---

def get_compliance_stats() -> Dict[str, Any]:
    """Calculates fleet-wide enterprise compliance statistics."""
    resources = load_resources()
    findings = load_raw_findings()
    policies = load_policies()

    total_resources = len(resources)
    compliant_resources = sum(1 for r in resources if r.get("compliance_posture", {}).get("status") == "COMPLIANT")
    violated_resources = total_resources - compliant_resources

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW" and f.get("scenario_key") != "gcs-zero-violation")

    auto_heal_eligible = sum(1 for f in findings if f.get("remediation", {}).get("governance_decision") == "AUTO_EXECUTE" and f.get("scenario_key") != "gcs-zero-violation")
    gated_production = sum(1 for f in findings if f.get("remediation", {}).get("governance_decision") == "REQUIRE_HUMAN_APPROVAL")

    return {
        "organization": "org-enterprise-cloud-7192",
        "total_monitored_resources": total_resources,
        "compliant_resources_count": compliant_resources,
        "violated_resources_count": violated_resources,
        "total_active_findings": len([f for f in findings if f.get("scenario_key") != "gcs-zero-violation"]),
        "total_governance_policies": len(policies),
        "severity_distribution": {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": medium_count,
            "LOW": low_count,
        },
        "governance_breakdown": {
            "auto_execute_eligible": auto_heal_eligible,
            "human_approval_required": gated_production,
        },
        "compliance_score_percent": round((compliant_resources / total_resources * 100), 1) if total_resources else 100.0,
    }


def _dict_to_finding(data: Dict[str, Any]) -> ComplianceFinding:
    env_str = str(data.get("environment", "development")).lower()
    if "prod" in env_str:
        env = EnvironmentTier.PRODUCTION
    elif "stag" in env_str:
        env = EnvironmentTier.STAGING
    else:
        env = EnvironmentTier.DEVELOPMENT

    sev_str = str(data.get("severity", "MEDIUM")).upper()
    try:
        severity = Severity[sev_str]
    except Exception:
        severity = Severity.HIGH

    cat_str = str(data.get("category", "STORAGE_PUBLIC_ACCESS"))
    try:
        category = FindingCategory[cat_str]
    except Exception:
        try:
            category = getattr(FindingCategory, cat_str)
        except Exception:
            category = FindingCategory.STORAGE_PUBLIC_ACCESS

    resource = ResourceDetails(
        resource_id=data.get("resource_id", ""),
        resource_name=data.get("resource_name", ""),
        resource_type=data.get("resource_type", ""),
        project_id=data.get("project_id", "default-proj"),
        environment=env,
        region=data.get("region", "us-central1"),
        current_state=data.get("current_state", {}),
    )

    finding = ComplianceFinding(
        finding_id=data.get("finding_id", "SCC-UNKNOWN"),
        source=data.get("source", "Security Command Center"),
        category=category,
        severity=severity,
        compliance_standard=data.get("compliance_standard", "CIS GCP Benchmark"),
        description=data.get("description", ""),
        resource=resource,
        metadata={
            "scenario_key": data.get("scenario_key"),
            "service": data.get("service"),
            "rank": data.get("rank"),
            "policy_id": data.get("policy_id"),
            "risk_assessment": data.get("risk_assessment"),
            "remediation": data.get("remediation"),
        },
    )
    return finding
