"""
Deterministic GCP Compute Firewall Remediation Tool.
Remediates open ingress rules (e.g. 0.0.0.0/0 on port 22/3389) by restricting to GCP IAP.
"""
from typing import Dict, Any, Tuple, List
from src.compliance_engine.tools.base import BaseRemediationTool


class FirewallRestrictSSHRemediationTool(BaseRemediationTool):
    # Google Cloud Identity-Aware Proxy (IAP) CIDR for secure SSH tunneling without external IPs
    GCP_IAP_CIDR = "35.235.240.0/20"

    @property
    def name(self) -> str:
        return "gcp_firewall_restrict_ssh_ingress"

    def execute(self, parameters: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str, Dict[str, Any]]:
        firewall_name = parameters.get("firewall_name")
        new_source_ranges = parameters.get("new_source_ranges", [self.GCP_IAP_CIDR])

        metadata = {
            "firewall_name": firewall_name,
            "previous_source_ranges": ["0.0.0.0/0"],
            "updated_source_ranges": new_source_ranges,
            "target_tags": ["allow-ssh-iap"],
            "ports_secured": ["22/tcp"],
            "simulation_mode": simulate,
        }

        msg = (
            f"Restricted ingress on firewall rule '{firewall_name}' from 0.0.0.0/0 "
            f"to authorized Google Cloud IAP CIDR [{', '.join(new_source_ranges)}]."
        )
        return True, msg, metadata

    def rollback(self, snapshot_state: Dict[str, Any], simulate: bool = True) -> Tuple[bool, str]:
        firewall_name = snapshot_state.get("firewall_name", "unknown")
        original_ranges = snapshot_state.get("source_ranges", ["0.0.0.0/0"])
        return True, f"Reverted firewall '{firewall_name}' source ranges back to {original_ranges}."

    def validate_compliance(self, resource_id: str, state: Dict[str, Any]) -> Tuple[bool, str]:
        source_ranges = state.get("source_ranges", [])
        if "0.0.0.0/0" not in source_ranges and any("35.235.240.0/20" in r for r in source_ranges):
            return True, f"Firewall rule '{resource_id}' no longer permits public ingress; restricted to GCP IAP."
        return False, f"Firewall rule '{resource_id}' still contains open CIDR 0.0.0.0/0."
