"""
Multi-service Remediation Planner extending RemediationPlanner for all GCP resources:
GCS, GKE, Cloud SQL, Compute Engine, IAM, BigQuery, and Cloud Run.
"""
import uuid
from typing import Dict, Any, List
from src.compliance_engine.models import (
    ComplianceFinding,
    FindingCategory,
    RemediationPlan,
    TechnicalDiff,
    RollbackProcedure,
    PlanStatus,
)
from src.compliance_engine.governance.risk_engine import RiskEngine
from src.compliance_engine.planner.remediation_planner import RemediationPlanner


class ComprehensiveRemediationPlanner(RemediationPlanner):
    """
    Formulates safe, deterministic remediation plans across the full spectrum
    of GCP resource types (Storage, GKE, Cloud SQL, VPC, IAM, BigQuery, Cloud Run).
    """

    def plan_remediation(self, finding: ComplianceFinding) -> RemediationPlan:
        # Check standard categories first
        cat_val = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        plan_id = f"PLAN-{uuid.uuid4().hex[:8].upper()}"

        if cat_val == FindingCategory.STORAGE_PUBLIC_ACCESS.value:
            return super().plan_remediation(finding)
        elif cat_val == FindingCategory.FIREWALL_OPEN_INGRESS.value:
            return super().plan_remediation(finding)

        elif "GKE_PUBLIC" in cat_val or "gke" in finding.resource.resource_type.lower():
            action_title = "Restrict GKE Master Authorized Networks to Corporate Bastion"
            rationale = (
                f"CIS GCP Benchmark 4.1 requires GKE cluster master endpoints to prohibit public access. "
                f"Restricting authorized networks to corporate CIDR blocks blocks external exploitation."
            )
            diffs = [
                TechnicalDiff(
                    parameter="master_authorized_networks",
                    current_value=["0.0.0.0/0"],
                    proposed_value=["10.128.0.0/24"],
                    description="Restrict GKE control plane authorized networks.",
                ),
                TechnicalDiff(
                    parameter="private_endpoint_enforced",
                    current_value=False,
                    proposed_value=True,
                    description="Enforce private cluster endpoint.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"cluster_name": finding.resource.resource_name, "master_authorized_networks": ["0.0.0.0/0"]},
                steps=["Restore master authorized networks to initial snapshot."],
                estimated_recovery_time_seconds=30,
            )
            tool_name = "gcp_gke_disable_public_endpoint"
            tool_params = {"cluster_name": finding.resource.resource_name, "authorized_cidrs": ["10.128.0.0/24"]}

        elif "WORKLOAD_IDENTITY" in cat_val:
            action_title = "Enable GKE Workload Identity on Cluster"
            rationale = "CIS GCP Benchmark 4.2 recommends Workload Identity to replace long-lived static JSON service account keys."
            diffs = [
                TechnicalDiff(
                    parameter="workload_identity_config",
                    current_value=None,
                    proposed_value={"workload_pool": f"{finding.resource.project_id}.svc.id.goog"},
                    description="Attach Workload Identity pool to cluster.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"cluster_name": finding.resource.resource_name},
                steps=["Revert workload identity configuration."],
                estimated_recovery_time_seconds=45,
            )
            tool_name = "gcp_gke_enable_workload_identity"
            tool_params = {"cluster_name": finding.resource.resource_name, "workload_pool": f"{finding.resource.project_id}.svc.id.goog"}

        elif "DATABASE_PUBLIC_IP" in cat_val or ("sql" in finding.resource.resource_type.lower() and "ip" in cat_val.lower()):
            action_title = "Revoke Public IPv4 & Enforce Private Service Access on Cloud SQL"
            rationale = "CIS GCP Benchmark 6.2 mandates that Cloud SQL instances must not be configured with public IPs or 0.0.0.0/0 authorized networks."
            diffs = [
                TechnicalDiff(
                    parameter="authorized_networks",
                    current_value=[{"value": "0.0.0.0/0", "name": "all"}],
                    proposed_value=[],
                    description="Clear 0.0.0.0/0 public authorized network.",
                ),
                TechnicalDiff(
                    parameter="private_network",
                    current_value=None,
                    proposed_value=f"projects/{finding.resource.project_id}/global/networks/payments-vpc",
                    description="Attach Private Service Access (PSA) peering.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"instance_name": finding.resource.resource_name},
                steps=["Re-enable authorized network if failover occurs."],
                estimated_recovery_time_seconds=30,
            )
            tool_name = "gcp_sql_enforce_private_ip"
            tool_params = {"instance_name": finding.resource.resource_name, "vpc_network": "payments-vpc"}

        elif "DATABASE_BACKUP" in cat_val or "backup" in cat_val.lower():
            action_title = "Enable Automated Daily Backups and Point-In-Time Recovery"
            rationale = "CIS GCP Benchmark 6.7 mandates automated daily snapshots with binary logging for disaster recovery."
            diffs = [
                TechnicalDiff(
                    parameter="backup_configuration.enabled",
                    current_value=False,
                    proposed_value=True,
                    description="Enable automated backup schedule.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="SAFE_STOP_AND_RESTORE_COMPLIANT_SNAPSHOT",
                snapshot_state={"instance_name": finding.resource.resource_name},
                steps=["If health checks fail, safely stop and restore verified compliant snapshot."],
                estimated_recovery_time_seconds=10,
            )
            tool_name = "gcp_sql_enable_automated_backups"
            tool_params = {"instance_name": finding.resource.resource_name}

        elif "DATABASE_SSL_ENFORCEMENT" in cat_val or "missing_ssl" in cat_val.lower():
            action_title = "Require TLS for Cloud SQL Connections"
            rationale = "CIS GCP Benchmark 6.4 mandates SSL/TLS encryption for all database connections to prevent plaintext data in transit."
            diffs = [
                TechnicalDiff(
                    parameter="ssl_mode",
                    current_value="ALLOW_UNENCRYPTED_AND_ENCRYPTED",
                    proposed_value="ENCRYPTED_ONLY",
                    description="Require encrypted connections only after client validation.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="SAFE_STOP_AND_RESTORE_COMPLIANT_SNAPSHOT",
                snapshot_state={"instance_name": finding.resource.resource_name},
                steps=["If client compatibility checks fail, safely stop and restore verified compliant snapshot."],
                estimated_recovery_time_seconds=15,
            )
            tool_name = "gcp_sql_enforce_ssl_only"
            tool_params = {"instance_name": finding.resource.resource_name, "ssl_mode": "ENCRYPTED_ONLY"}

        elif "FUNCTION_PUBLIC_INGRESS" in cat_val or "function" in finding.resource.resource_type.lower():
            action_title = "Restrict Cloud Function Ingress and Upgrade Runtime"
            rationale = "Google Cloud Security Baseline mandates restricting Cloud Function ingress to internal traffic and deprecating outdated runtimes."
            diffs = [
                TechnicalDiff(
                    parameter="ingress_settings",
                    current_value="ALLOW_ALL",
                    proposed_value="ALLOW_INTERNAL_ONLY",
                    description="Restrict ingress traffic to internal resources only.",
                ),
                TechnicalDiff(
                    parameter="runtime",
                    current_value="python38",
                    proposed_value="python312",
                    description="Upgrade runtime from deprecated Python 3.8 to Python 3.12.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="SAFE_STOP_AND_RESTORE_COMPLIANT_SNAPSHOT",
                snapshot_state={"function_name": finding.resource.resource_name},
                steps=["If deployment validation fails, revert to previous internal snapshot."],
                estimated_recovery_time_seconds=20,
            )
            tool_name = "gcp_cloudfunction_harden"
            tool_params = {"function_name": finding.resource.resource_name, "ingress_settings": "ALLOW_INTERNAL_ONLY", "runtime": "python312"}

        elif "VM_EXTERNAL_IP" in cat_val or "gce" in finding.resource.resource_type.lower():
            action_title = "Delete External Public IP AccessConfig from Database VM"
            rationale = "CIS GCP Benchmark 3.8 states internal database and worker VMs must have only internal IP addresses and route through Cloud NAT."
            diffs = [
                TechnicalDiff(
                    parameter="access_configs",
                    current_value=[{"type": "ONE_TO_ONE_NAT", "nat_ip": "35.202.14.89"}],
                    proposed_value=[],
                    description="Remove external IP address from VM network interface.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"instance_name": finding.resource.resource_name},
                steps=["Re-attach external IP if needed."],
                estimated_recovery_time_seconds=15,
            )
            tool_name = "gcp_gce_remove_external_ip"
            tool_params = {"instance_name": finding.resource.resource_name}

        elif "IAM_EXCESSIVE_PRIVILEGE" in cat_val or "sa_owner" in cat_val.lower() or "owner" in cat_val.lower():
            action_title = "Downgrade Primitive roles/owner to Scoped Least-Privilege Roles"
            rationale = "CIS GCP Benchmark 1.4 dictates service accounts should not hold Owner or Editor roles. Scope to exact IAM roles used in last 90 days."
            diffs = [
                TechnicalDiff(
                    parameter="roles",
                    current_value=["roles/owner"],
                    proposed_value=["roles/bigquery.jobUser", "roles/storage.objectViewer"],
                    description="Replace broad primitive Owner with least-privilege roles.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"sa": finding.resource.resource_name, "roles": ["roles/owner"]},
                steps=["Re-grant previous IAM roles."],
                estimated_recovery_time_seconds=15,
            )
            tool_name = "gcp_iam_enforce_least_privilege"
            tool_params = {
                "service_account": finding.resource.resource_name,
                "removed_roles": ["roles/owner"],
                "added_roles": ["roles/bigquery.jobUser", "roles/storage.objectViewer"],
            }

        elif "IAM_KEY_UNROTATED" in cat_val or "key" in cat_val.lower():
            action_title = "Rotate Expired Service Account Key and Sync Secret Manager"
            rationale = "CIS GCP Benchmark 1.3 requires user-managed service account keys to be rotated every 90 days."
            diffs = [
                TechnicalDiff(
                    parameter="key_status",
                    current_value="EXPIRED (>90 days active)",
                    proposed_value="ROTATED_AND_ACTIVE",
                    description="Generate replacement key, upload to Secret Manager, disable old key.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"sa": finding.resource.resource_name},
                steps=["Re-enable previous key if client deployment fails."],
                estimated_recovery_time_seconds=10,
            )
            tool_name = "gcp_iam_rotate_sa_key"
            tool_params = {"service_account": finding.resource.resource_name, "old_key_id": "key-9281"}

        elif "BIGQUERY" in cat_val or "bigquery" in finding.resource.resource_type.lower():
            action_title = "Revoke allAuthenticatedUsers from BigQuery Dataset Access List"
            rationale = "CIS GCP Benchmark 7.1 prohibits granting dataset permissions to allAuthenticatedUsers or allUsers to avoid data leakage."
            diffs = [
                TechnicalDiff(
                    parameter="access",
                    current_value={"role": "READER", "specialGroup": "allAuthenticatedUsers"},
                    proposed_value={"role": "READER", "groupByEmail": "data-analysts@company.com"},
                    description="Revoke public group; scope to verified analyst group.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"dataset": finding.resource.resource_name},
                steps=["Restore previous access list."],
                estimated_recovery_time_seconds=10,
            )
            tool_name = "gcp_bigquery_revoke_public_access"
            tool_params = {"dataset_name": finding.resource.resource_name}

        elif "CLOUDRUN" in cat_val or "run" in finding.resource.resource_type.lower():
            action_title = "Revoke Unauthenticated Invocations on Cloud Run Service"
            rationale = "Enterprise Security Baseline mandates internal microservices require OIDC token verification via API Gateway."
            diffs = [
                TechnicalDiff(
                    parameter="invoker_binding",
                    current_value={"member": "allUsers", "role": "roles/run.invoker"},
                    proposed_value={"member": "serviceAccount:api-gateway@proj.iam", "role": "roles/run.invoker"},
                    description="Enforce authenticated invocations.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"service": finding.resource.resource_name},
                steps=["Restore allUsers invoker binding."],
                estimated_recovery_time_seconds=10,
            )
            tool_name = "gcp_cloudrun_enforce_authentication"
            tool_params = {"service_name": finding.resource.resource_name}

        elif "CMEK" in cat_val:
            action_title = "Enforce Customer-Managed Encryption Key (CMEK) via Cloud KMS"
            rationale = "CIS GCP Benchmark 5.3 requires financial audit buckets to utilize KMS CMEK encryption."
            diffs = [
                TechnicalDiff(
                    parameter="default_kms_key_name",
                    current_value=None,
                    proposed_value="projects/payments-prod/locations/us-central1/keyRings/kms-prod/cryptoKeys/audit-key",
                    description="Set default Cloud KMS encryption key.",
                ),
            ]
            rollback = RollbackProcedure(
                strategy_type="AUTOMATIC_RESTORE",
                snapshot_state={"bucket": finding.resource.resource_name},
                steps=["Revert default encryption to Google-managed."],
                estimated_recovery_time_seconds=10,
            )
            tool_name = "gcp_storage_enforce_cmek"
            tool_params = {"bucket_name": finding.resource.resource_name, "kms_key_name": "projects/payments-prod/locations/us-central1/keyRings/kms-prod/cryptoKeys/audit-key"}

        else:
            rem_meta = finding.metadata.get("remediation") if isinstance(finding.metadata, dict) else None
            if rem_meta:
                action_title = rem_meta.get("action_title", f"Remediation for {cat_val}")
                rationale = rem_meta.get("rationale", "Enforce organizational compliance standard.")
                tool_name = rem_meta.get("tool_name", "generic_tool")
                tool_params = rem_meta.get("tool_parameters", {})
                rb_data = rem_meta.get("rollback_procedure", {})
                rollback = RollbackProcedure(
                    strategy_type=rb_data.get("strategy_type", "AUTOMATIC_RESTORE"),
                    snapshot_state=rb_data.get("snapshot_state", {}),
                    steps=rb_data.get("steps", ["Revert changes"]),
                    estimated_recovery_time_seconds=rb_data.get("estimated_recovery_time_seconds", 30),
                )
                diffs = [
                    TechnicalDiff(
                        parameter="state",
                        current_value="NON_COMPLIANT",
                        proposed_value="COMPLIANT",
                        description=action_title,
                    )
                ]
            else:
                action_title = f"Remediation for {cat_val}"
                rationale = "Enforce organizational compliance standard."
                diffs = []
                rollback = RollbackProcedure(strategy_type="MANUAL_RUNBOOK", snapshot_state={}, steps=["Review logs."], estimated_recovery_time_seconds=60)
                tool_name = "generic_tool"
                tool_params = {}

        risk = self.risk_engine.assess_risk(finding, action_title)

        return RemediationPlan(
            plan_id=plan_id,
            finding_id=finding.finding_id,
            target_resource_id=finding.resource.resource_id,
            action_title=action_title,
            rationale=rationale,
            governing_standard=finding.compliance_standard,
            diffs=diffs,
            risk_assessment=risk,
            rollback_procedure=rollback,
            tool_name=tool_name,
            tool_parameters=tool_params,
            status=PlanStatus.DRAFTED,
        )
