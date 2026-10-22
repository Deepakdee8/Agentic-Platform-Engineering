"""
Domain models for Compliance Findings.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EnvironmentTier(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    SANDBOX = "sandbox"


class FindingCategory(str, Enum):
    STORAGE_PUBLIC_ACCESS = "STORAGE_PUBLIC_ACCESS"
    STORAGE_MISSING_CMEK = "STORAGE_MISSING_CMEK"
    STORAGE_UBLA_DISABLED = "STORAGE_UBLA_DISABLED"
    FIREWALL_OPEN_INGRESS = "FIREWALL_OPEN_INGRESS"
    DATABASE_PUBLIC_IP = "DATABASE_PUBLIC_IP"
    DATABASE_BACKUP_DISABLED = "DATABASE_BACKUP_DISABLED"
    DATABASE_MISSING_SSL = "DATABASE_MISSING_SSL"
    DATABASE_SSL_ENFORCEMENT = "DATABASE_SSL_ENFORCEMENT"
    GKE_PUBLIC_ENDPOINT = "GKE_PUBLIC_ENDPOINT"
    GKE_WORKLOAD_IDENTITY_DISABLED = "GKE_WORKLOAD_IDENTITY_DISABLED"
    VM_EXTERNAL_IP = "VM_EXTERNAL_IP"
    IAM_EXCESSIVE_PRIVILEGE = "IAM_EXCESSIVE_PRIVILEGE"
    IAM_KEY_UNROTATED = "IAM_KEY_UNROTATED"
    BIGQUERY_DATASET_PUBLIC = "BIGQUERY_DATASET_PUBLIC"
    CLOUDRUN_UNAUTHENTICATED = "CLOUDRUN_UNAUTHENTICATED"
    KMS_KEY_ROTATION_DISABLED = "KMS_KEY_ROTATION_DISABLED"
    SECRET_UNENCRYPTED = "SECRET_UNENCRYPTED"
    PUBSUB_MISSING_CMEK = "PUBSUB_MISSING_CMEK"
    FUNCTION_PUBLIC_INGRESS = "FUNCTION_PUBLIC_INGRESS"
    STORAGE_OBJECT_ACL_EXPOSURE = "STORAGE_OBJECT_ACL_EXPOSURE"
    UNENCRYPTED_RESOURCE = "UNENCRYPTED_RESOURCE"
    CLEAN_COMPLIANT_RESOURCE = "CLEAN_COMPLIANT_RESOURCE"


@dataclass
class ResourceDetails:
    resource_id: str
    resource_name: str
    resource_type: str
    project_id: str
    environment: EnvironmentTier
    region: str = "us-central1"
    labels: Dict[str, str] = field(default_factory=dict)
    current_state: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceFinding:
    finding_id: str
    source: str  # e.g., "Security Command Center (SCC)", "Cloud Asset Inventory"
    category: FindingCategory
    severity: Severity
    compliance_standard: str  # e.g., "CIS GCP Benchmark v2.0 - 5.1"
    description: str
    resource: ResourceDetails
    created_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "ACTIVE"  # "ACTIVE", "IN_REMEDIATION", "RESOLVED", "MUTED"
    metadata: Dict[str, Any] = field(default_factory=dict)
