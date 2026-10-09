"""
Comprehensive Compliance Orchestrator supporting all GCP resources with full tool registry.
"""
from typing import Dict, Any, Optional, Callable
from src.compliance_engine.orchestrator import ComplianceOrchestrator
from src.compliance_engine.planner.comprehensive_planner import ComprehensiveRemediationPlanner
from src.compliance_engine.tools.extended_tools import (
    GKEPublicEndpointRemediationTool,
    GKEWorkloadIdentityTool,
    CloudSQLPrivateIPTool,
    CloudSQLBackupTool,
    GCEExternalIPTool,
    IAMLeastPrivilegeTool,
    IAMKeyRotationTool,
    BigQueryPublicDatasetTool,
    CloudRunAuthTool,
    GCSCMEKTool,
)
from src.compliance_engine.tools.gcs_tools import GCSPublicAccessRemediationTool
from src.compliance_engine.tools.firewall_tools import FirewallRestrictSSHRemediationTool


class ComprehensiveComplianceOrchestrator(ComplianceOrchestrator):
    """
    Extends ComplianceOrchestrator with full tool registry and planner
    covering Cloud Storage, GKE, Cloud SQL, Compute Engine, IAM, BigQuery, and Cloud Run.
    """

    def __init__(self):
        super().__init__()
        # Replace planner with comprehensive planner
        self.planner = ComprehensiveRemediationPlanner(self.risk_engine)

        # Register tools for all GCP resource types
        self.tool_registry.update({
            "gcp_storage_remove_public_access": GCSPublicAccessRemediationTool(),
            "gcp_firewall_restrict_ssh_ingress": FirewallRestrictSSHRemediationTool(),
            "gcp_gke_disable_public_endpoint": GKEPublicEndpointRemediationTool(),
            "gcp_gke_enable_workload_identity": GKEWorkloadIdentityTool(),
            "gcp_sql_enforce_private_ip": CloudSQLPrivateIPTool(),
            "gcp_sql_enable_automated_backups": CloudSQLBackupTool(),
            "gcp_gce_remove_external_ip": GCEExternalIPTool(),
            "gcp_iam_enforce_least_privilege": IAMLeastPrivilegeTool(),
            "gcp_iam_rotate_sa_key": IAMKeyRotationTool(),
            "gcp_bigquery_revoke_public_access": BigQueryPublicDatasetTool(),
            "gcp_cloudrun_enforce_authentication": CloudRunAuthTool(),
            "gcp_storage_enforce_cmek": GCSCMEKTool(),
        })
