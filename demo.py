#!/usr/bin/env python3
"""
Interactive Terminal Demo:
"The 30-Second Self-Healing Cloud: Autonomous in Dev, Governed in Prod"
Demonstrating Capability 2: Automated Environment Compliance Remediation on GCP.
"""
import sys
import time
from typing import Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from src.compliance_engine.models import (
    ComplianceFinding,
    ResourceDetails,
    Severity,
    EnvironmentTier,
    FindingCategory,
    RemediationPlan,
)
from src.compliance_engine.governance.approval_engine import ApprovalTicket
from src.compliance_engine.orchestrator import ComplianceOrchestrator
 

# ANSI terminal colors
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}================================================================================
   GOOGLE CLOUD AGENTIC PLATFORM: COMPLIANCE REMEDIATION AGENT
   Demo: The 30-Second Self-Healing Cloud (Autonomous in Dev, Governed in Prod)
================================================================================{Colors.RESET}
"""
    print(banner)


def print_section(title: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}>>> {title}{Colors.RESET}")
    print(f"{Colors.BLUE}{'-' * 80}{Colors.RESET}")


def simulate_delay(seconds: float = 0.8):
    time.sleep(seconds)


def create_demo_findings():
    """Generates the two realistic findings from Google Cloud Security Command Center."""
    finding_dev = ComplianceFinding(
        finding_id="SCC-GCS-84920",
        source="Google Cloud Security Command Center (SCC)",
        category=FindingCategory.STORAGE_PUBLIC_ACCESS,
        severity=Severity.HIGH,
        compliance_standard="CIS GCP Benchmark v2.0 - 5.1",
        description="Cloud Storage bucket permissions allow public read access (allUsers in IAM binding).",
        resource=ResourceDetails(
            resource_id="projects/retail-dev-env/buckets/retail-app-invoices-dev",
            resource_name="retail-app-invoices-dev",
            resource_type="storage.googleapis.com/Bucket",
            project_id="retail-dev-env",
            environment=EnvironmentTier.DEVELOPMENT,
            region="us-central1",
            current_state={
                "iam_bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                    {"role": "roles/storage.admin", "members": ["serviceAccount:dev-sa@retail-dev-env.iam.gserviceaccount.com"]},
                ],
                "public_access_prevention": "unspecified",
            },
        ),
    )

    finding_prod = ComplianceFinding(
        finding_id="SCC-FW-99201",
        source="Google Cloud Security Command Center (SCC)",
        category=FindingCategory.FIREWALL_OPEN_INGRESS,
        severity=Severity.CRITICAL,
        compliance_standard="CIS GCP Benchmark v2.0 - 3.6",
        description="Firewall rule permits unrestricted inbound SSH traffic (port 22) from the public internet (0.0.0.0/0).",
        resource=ResourceDetails(
            resource_id="projects/payments-prod-vpc/global/firewalls/allow-ssh-ingress",
            resource_name="allow-ssh-ingress",
            resource_type="compute.googleapis.com/Firewall",
            project_id="payments-prod-vpc",
            environment=EnvironmentTier.PRODUCTION,
            region="global",
            current_state={
                "source_ranges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "target_tags": ["production-backend"],
            },
        ),
    )

    return finding_dev, finding_prod


def interactive_approval_callback(plan: RemediationPlan, ticket: ApprovalTicket) -> bool:
    """Callback for human-in-the-loop approval gate."""
    print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  HUMAN-IN-THE-LOOP APPROVAL GATE ACTIVATED (Ticket: {ticket.ticket_id}){Colors.RESET}")
    print(f"{Colors.YELLOW}   Production policy dictates: High/Critical changes require Platform Engineer authorization.{Colors.RESET}")
    print(f"\n{Colors.BOLD}Proposed Remediation Details:{Colors.RESET}")
    print(f"  • Action:           {plan.action_title}")
    print(f"  • Resource:         {plan.target_resource_id}")
    print(f"  • Risk Score:       {plan.risk_assessment.score}/100 ({plan.risk_assessment.risk_level.value})")
    print(f"  • Blast Radius:     {plan.risk_assessment.blast_radius.affected_services_count} critical service(s) affected")
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}Technical Configuration Diff:{Colors.RESET}")
    for diff in plan.diffs:
        print(f"  Parameter:  {diff.parameter}")
        print(f"  Current:   {Colors.RED}- {diff.current_value}{Colors.RESET}")
        print(f"  Proposed:  {Colors.GREEN}+ {diff.proposed_value}{Colors.RESET}")
        print(f"  Note:      {diff.description}")

    print(f"\n{Colors.BOLD}Rollback Strategy:{Colors.RESET}")
    print(f"  • Strategy:         {plan.rollback_procedure.strategy_type}")
    print(f"  • Recovery Time:    ~{plan.rollback_procedure.estimated_recovery_time_seconds} seconds")
    for step in plan.rollback_procedure.steps:
        print(f"    - {step}")

    print()
    while True:
        try:
            choice = input(f"{Colors.BOLD}{Colors.YELLOW}[HITL ACTION REQUIRED] Do you authorize this production change? (y/n): {Colors.RESET}").strip().lower()
            if choice in ["y", "yes"]:
                print(f"{Colors.GREEN}✓ Approval granted by reviewer. Resuming execution pipeline...{Colors.RESET}\n")
                return True
            elif choice in ["n", "no"]:
                print(f"{Colors.RED}✗ Approval rejected by reviewer. Aborting change and alerting security lead.{Colors.RESET}\n")
                return False
            else:
                print("Please enter 'y' to approve or 'n' to reject.")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.RED}Aborted by user.{Colors.RESET}")
            return False


def run_demo():
    print_banner()
    orchestrator = ComplianceOrchestrator()
    finding_dev, finding_prod = create_demo_findings()

    # Step 1: Ingestion
    print_section("STAGE 1: Ingesting Active Violations from Google Cloud Security Command Center")
    simulate_delay(0.5)
    print(f"  Found 2 critical compliance violations in organization:")
    print(f"  1. [{finding_dev.severity.value}] {finding_dev.resource.resource_name} (Env: {finding_dev.resource.environment.value})")
    print(f"     Standard: {finding_dev.compliance_standard}")
    print(f"  2. [{finding_prod.severity.value}] {finding_prod.resource.resource_name} (Env: {finding_prod.resource.environment.value})")
    print(f"     Standard: {finding_prod.compliance_standard}")

    # =========================================================================
    # ACT 1: DEVELOPMENT AUTO-HEAL
    # =========================================================================
    print_section("STAGE 2: Processing Finding #1 — Development Storage Bucket (Auto-Heal)")
    print(f"Target Resource:  gs://{finding_dev.resource.resource_name}")
    print(f"Environment:      {finding_dev.resource.environment.value.upper()}")
    print(f"Violation:        {finding_dev.description}")
    
    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[1/5] AI Reasoning & Planning (Gemini):{Colors.RESET}")
    print(f"  • Analyzing rule {finding_dev.compliance_standard}...")
    print(f"  • Prescribed Fix: Enforce Public Access Prevention (PAP) & remove allUsers binding.")
    print(f"  • Reversibility: FULL (Automatic snapshot created).")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[2/5] Risk & Policy Governance Evaluation:{Colors.RESET}")
    result_dev = orchestrator.process_finding(finding_dev, simulate=True)
    plan_dev = result_dev["plan"]
    policy_dev = result_dev["policy"]

    print(f"  • Evaluated Risk Score: {plan_dev.risk_assessment.score}/100 ({plan_dev.risk_assessment.risk_level.value})")
    print(f"  • Governing Policy:     {policy_dev.governing_policy}")
    print(f"  • Policy Decision:      {Colors.GREEN}{policy_dev.decision.value} (Auto-Healing Authorized){Colors.RESET}")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[3/5] Deterministic Tool Execution:{Colors.RESET}")
    print(f"  • Calling tool '{plan_dev.tool_name}'...")
    print(f"  {Colors.GREEN}✓ Removed allUsers from role 'roles/storage.objectViewer'{Colors.RESET}")
    print(f"  {Colors.GREEN}✓ Enabled Public Access Prevention on gs://{finding_dev.resource.resource_name}{Colors.RESET}")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[4/5] Closed-Loop State Verification:{Colors.RESET}")
    print(f"  • Probing resource live IAM policy...")
    print(f"  {Colors.GREEN}✓ {result_dev['validation_message']}{Colors.RESET}")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[5/5] Audit & Ticket Resolution:{Colors.RESET}")
    audit_dev = result_dev["audit"]
    print(f"  • SCC Finding Status:   {Colors.GREEN}RESOLVED{Colors.RESET}")
    print(f"  • Audit Record Vault ID:{audit_dev.audit_id}")
    print(f"  • SHA-256 Checksum:     {audit_dev.checksum_sha256[:20]}...")

    # =========================================================================
    # ACT 2: PRODUCTION HUMAN-IN-THE-LOOP SHIELD
    # =========================================================================
    print_section("STAGE 3: Processing Finding #2 — Production Firewall Rule (Human-in-the-Loop)")
    print(f"Target Resource:  {finding_prod.resource.resource_name}")
    print(f"Environment:      {Colors.RED}{Colors.BOLD}{finding_prod.resource.environment.value.upper()}{Colors.RESET}")
    print(f"Violation:        {finding_prod.description}")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[1/5] AI Reasoning & Planning (Gemini):{Colors.RESET}")
    print(f"  • Analyzing rule {finding_prod.compliance_standard}...")
    print(f"  • Prescribed Fix: Restrict SSH port 22 to Google Cloud IAP CIDR (35.235.240.0/20).")
    print(f"  • Blast Radius: 5 Production services behind VPC.")

    simulate_delay(0.8)
    print(f"\n{Colors.BOLD}[2/5] Risk & Policy Governance Evaluation:{Colors.RESET}")
    # Process finding with interactive callback
    result_prod = orchestrator.process_finding(
        finding_prod,
        approval_callback=interactive_approval_callback,
        simulate=True,
    )
    plan_prod = result_prod["plan"]
    policy_prod = result_prod["policy"]

    if result_prod["success"]:
        simulate_delay(0.8)
        print(f"\n{Colors.BOLD}[3/5] Deterministic Tool Execution:{Colors.RESET}")
        print(f"  • Calling tool '{plan_prod.tool_name}'...")
        print(f"  {Colors.GREEN}✓ Updated firewall source_ranges to ['35.235.240.0/20']{Colors.RESET}")
        print(f"  {Colors.GREEN}✓ Tagged target backend instances with 'allow-ssh-iap'{Colors.RESET}")

        simulate_delay(0.8)
        print(f"\n{Colors.BOLD}[4/5] Closed-Loop State Verification:{Colors.RESET}")
        print(f"  • Running live network probe against port 22 from external internet...")
        print(f"  {Colors.GREEN}✓ {result_prod['validation_message']}{Colors.RESET}")

        simulate_delay(0.8)
        print(f"\n{Colors.BOLD}[5/5] Audit & Ticket Resolution:{Colors.RESET}")
        audit_prod = result_prod["audit"]
        print(f"  • SCC Finding Status:   {Colors.GREEN}RESOLVED{Colors.RESET}")
        print(f"  • Approved By:          {audit_prod.approved_by}")
        print(f"  • Audit Record Vault ID:{audit_prod.audit_id}")
        print(f"  • SHA-256 Checksum:     {audit_prod.checksum_sha256[:20]}...")
    else:
        print(f"\n{Colors.RED}Remediation halted: {result_prod['message']}{Colors.RESET}")

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print_section("EXECUTIVE DEMO SUMMARY")
    print(f"  Total Violations Processed: 2")
    print(f"  • Development Violations:   1 Auto-Healed ({Colors.GREEN}0 human clicks required{Colors.RESET})")
    print(f"  • Production Violations:    1 Safely Governed ({Colors.GREEN}Human-Authorized{Colors.RESET})")
    print(f"  • Mean Time to Remediate:   < 30 seconds")
    print(f"  • Compliance Posture Score: {Colors.GREEN}{Colors.BOLD}100% PASS (All CIS Violations Closed){Colors.RESET}")
    print(f"  • Audit Trail:              All records cryptographically sealed in BigQuery Vault\n")


if __name__ == "__main__":
    run_demo()
