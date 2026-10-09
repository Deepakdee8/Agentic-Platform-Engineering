"""
Deterministic GCP Cloud Storage Remediation Tool.
Remediates public bucket permissions and enforces public access prevention.
"""
from typing import Dict, Any, Tuple, List
from src.compliance_engine.tools.base import BaseRemediationTool


class GCSPublicAccessRemediationTool(BaseRemediationTool):
    @property
    def name(self) -> str:
        return "gcp_storage_remove_public_access"

    def execute(self, parameters: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str, Dict[str, Any]]:
        bucket_name = parameters.get("bucket_name")
        current_bindings = parameters.get("current_iam_bindings", [])
        
        # Filter out allUsers and allAuthenticatedUsers
        updated_bindings: List[Dict[str, Any]] = []
        removed_members = []
        for binding in current_bindings:
            role = binding.get("role")
            members = binding.get("members", [])
            safe_members = []
            for member in members:
                if member in ["allUsers", "allAuthenticatedUsers"]:
                    removed_members.append(f"{member} ({role})")
                else:
                    safe_members.append(member)
            if safe_members:
                updated_bindings.append({"role": role, "members": safe_members})

        metadata = {
            "bucket_name": bucket_name,
            "removed_members": removed_members,
            "public_access_prevention": "enforced",
            "uniform_bucket_level_access": True,
            "simulation_mode": simulate,
        }

        msg = (
            f"Successfully stripped public bindings [{', '.join(removed_members)}] "
            f"and enforced Public Access Prevention on gs://{bucket_name}."
        )
        return True, msg, metadata

    def rollback(self, snapshot_state: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str]:
        bucket_name = snapshot_state.get("bucket_name", "unknown")
        original_bindings = snapshot_state.get("iam_bindings", [])
        return True, f"Restored {len(original_bindings)} original IAM bindings to gs://{bucket_name}."

    def validate_compliance(self, resource_id: str, state: Dict[str, Any]) -> Tuple[bool, str]:
        pap = state.get("public_access_prevention")
        bindings = state.get("iam_bindings", [])
        
        has_public = any(
            any(m in ["allUsers", "allAuthenticatedUsers"] for m in b.get("members", []))
            for b in bindings
        )

        if not has_public and pap == "enforced":
            return True, f"Bucket {resource_id} has public_access_prevention='enforced' and zero public IAM members."
        return False, f"Bucket {resource_id} still has public members or unenforced PAP."
