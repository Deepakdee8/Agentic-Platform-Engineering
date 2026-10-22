"""
Extended FindingCategory and Tool definitions for comprehensive GCP Resource coverage.
"""
from src.compliance_engine.models.finding import FindingCategory, ComplianceFinding, ResourceDetails, Severity, EnvironmentTier

# Extend FindingCategory with additional GCP domains dynamically if needed
new_categories = {
    "STORAGE_MISSING_CMEK": "STORAGE_MISSING_CMEK",
    "GKE_PUBLIC_ENDPOINT": "GKE_PUBLIC_ENDPOINT",
    "GKE_WORKLOAD_IDENTITY_DISABLED": "GKE_WORKLOAD_IDENTITY_DISABLED",
    "DATABASE_BACKUP_DISABLED": "DATABASE_BACKUP_DISABLED",
    "DATABASE_MISSING_SSL": "DATABASE_MISSING_SSL",
    "VM_EXTERNAL_IP": "VM_EXTERNAL_IP",
    "IAM_KEY_UNROTATED": "IAM_KEY_UNROTATED",
    "BIGQUERY_DATASET_PUBLIC": "BIGQUERY_DATASET_PUBLIC",
    "CLOUDRUN_UNAUTHENTICATED": "CLOUDRUN_UNAUTHENTICATED",
    "KMS_KEY_ROTATION_DISABLED": "KMS_KEY_ROTATION_DISABLED",
    "SECRET_UNENCRYPTED": "SECRET_UNENCRYPTED",
    "PUBSUB_MISSING_CMEK": "PUBSUB_MISSING_CMEK",
    "STORAGE_UBLA_DISABLED": "STORAGE_UBLA_DISABLED",
    "DATABASE_SSL_ENFORCEMENT": "DATABASE_SSL_ENFORCEMENT",
    "FUNCTION_PUBLIC_INGRESS": "FUNCTION_PUBLIC_INGRESS",
    "STORAGE_OBJECT_ACL_EXPOSURE": "STORAGE_OBJECT_ACL_EXPOSURE",
    "CLEAN_COMPLIANT_RESOURCE": "CLEAN_COMPLIANT_RESOURCE",
}
for k, v in new_categories.items():
    if not hasattr(FindingCategory, k):
        try:
            setattr(FindingCategory, k, v)
        except Exception:
            pass
