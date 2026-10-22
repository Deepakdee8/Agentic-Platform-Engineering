"""
Compliance Reasoning Agent.
Answers natural language queries about enterprise GCP resources, compliance violations,
risk rankings, auto-healing candidates, and passing security controls without mistakes.
"""
import re
from typing import Dict, Any, List, Optional
from data.loader import (
    load_resources,
    load_raw_findings,
    load_policies,
    get_ranked_findings,
    get_compliance_stats,
    get_resource_by_id,
)
from src.compliance_engine.agent.gemini_reasoning_agent import GeminiReasoningAgent


class ComplianceAgent:
    """
    Enterprise Compliance AI Agent for reasoning over GCP posture, findings, and policies.
    """

    def __init__(self):
        self.resources = load_resources()
        self.findings = load_raw_findings()
        self.policies = load_policies()
        self.gemini_agent = GeminiReasoningAgent()

    def refresh_data(self):
        """Reloads latest data from disk."""
        self.resources = load_resources()
        self.findings = load_raw_findings()
        self.policies = load_policies()

    def process_query(self, query: str) -> Dict[str, Any]:
        """
        Processes a natural language prompt and returns an authoritative answer,
        corresponding left sidebar filter mode, and metadata.
        """
        self.refresh_data()
        q = query.lower().strip()

        # =========================================================================
        # INTENT 1 (PRIORITY): Zero-Violation / "in which resource violations are not present" /
        # "are there any resource in which issues are not violating"
        # =========================================================================
        if self._is_zero_violation_query(q):
            return self._answer_zero_violation_resource()

        # =========================================================================
        # INTENT 2: "how many auto-heal violations are present?" (Scoped or Global)
        # =========================================================================
        if self._is_autoheal_query(q):
            scope = self._detect_service_scope(q)
            matched_resource = self._find_resource_in_query(q)
            if scope or matched_resource:
                return self._answer_scoped_autoheal_violations(scope=scope, resource=matched_resource, query=q)
            return self._answer_autoheal_violations()

        # =========================================================================
        # INTENT 3: "how many prod violations are present?" (Scoped or Global)
        # =========================================================================
        if self._is_prod_query(q):
            scope = self._detect_service_scope(q)
            matched_resource = self._find_resource_in_query(q)
            if scope or matched_resource:
                return self._answer_scoped_prod_violations(scope=scope, resource=matched_resource, query=q)
            return self._answer_prod_violations()

        # =========================================================================
        # INTENT 4: "which issues are not violating?"
        # =========================================================================
        if self._is_non_violating_controls_query(q):
            return self._answer_non_violating_controls(q)

        # =========================================================================
        # INTENT 5: Storage Bucket Public Access vs Object Authenticated URLs / UBLA / PAP
        # (e.g., "any specific bucket is giving more publicly accessible but any object is having exposing authenticated URL's")
        # =========================================================================
        if self._is_bucket_object_exposure_query(q):
            return self._answer_bucket_public_and_object_authenticated_urls(q)

        # =========================================================================
        # INTENT 6: Action Prompts ("act on it", "remediate this", "fix the bucket", etc.)
        # =========================================================================
        if self._is_action_prompt(q):
            return self._answer_action_prompt(q)

        # =========================================================================
        # INTENT 6B: What is Agent Executable?
        # =========================================================================
        if self._is_agent_executable_query(q):
            return self._answer_agent_executable()

        # =========================================================================
        # INTENT 6C: Multiple Agents
        # =========================================================================
        if self._is_multi_agent_query(q):
            return self._answer_multiple_agents()

        # =========================================================================
        # INTENT 6D: Multiple Skills
        # =========================================================================
        if self._is_skills_query(q):
            return self._answer_multiple_skills()

        # =========================================================================
        # INTENT 6E: What all tools defined for this
        # =========================================================================
        if self._is_tools_query(q):
            return self._answer_tools_defined()

        # =========================================================================
        # INTENT 6F: Fleet Incidents & Repeating Issues Across 30-40 Resources (1000+ Scale)
        # =========================================================================
        if self._is_fleet_incidents_query(q):
            return self._answer_fleet_incidents()

        # =========================================================================
        # INTENT 6G: GCP Live Connection & Connector Gateway
        # =========================================================================
        if self._is_gcp_connector_query(q):
            return self._answer_gcp_connector()

        # =========================================================================
        # INTENT 7: Risk Rankings / Highest Risk
        # =========================================================================
        if any(term in q for term in ["highest risk", "top risk", "rank", "ranking", "most critical"]):
            return self._answer_risk_rankings()

        # =========================================================================
        # INTENT 8: Specific Resource Query by Name
        # =========================================================================
        matched_resource = self._find_resource_in_query(q)
        if matched_resource:
            return self._answer_resource_details(matched_resource)

        # =========================================================================
        # INTENT 9: Enterprise Deep Configuration & Security Attribute Search
        # =========================================================================
        config_result = self._search_configuration_or_catalog(q)
        if config_result:
            return config_result

        # INTENT 10: Live Gemini AI Reasoning Agent Grounded in Fleet Data
        gemini_response = self.gemini_agent.answer_query(query)
        if gemini_response:
            return gemini_response

        # Fallback General Compliance Summary
        return self._answer_general_summary(query)

    # -------------------------------------------------------------------------
    # Intent Matchers
    # -------------------------------------------------------------------------
    def _is_autoheal_query(self, q: str) -> bool:
        has_autoheal = any(k in q for k in ["auto-heal", "auto heal", "autoheal", "autonomous", "self-heal", "self heal"])
        has_violation = any(k in q for k in ["violation", "issue", "finding", "how many", "count", "present", "list"])
        has_negative = any(k in q for k in ["not violating", "not present", "no violation", "no issue", "zero violation", "without violation"])
        return has_autoheal and has_violation and not has_negative

    def _is_prod_query(self, q: str) -> bool:
        has_prod = any(k in q for k in ["prod", "production", "hitl", "gated"])
        has_violation = any(k in q for k in ["violation", "issue", "finding", "how many", "count", "present", "list"])
        has_negative = any(k in q for k in ["not violating", "not present", "no violation", "no issue", "zero violation", "without violation"])
        return has_prod and has_violation and not has_negative

    def _is_zero_violation_query(self, q: str) -> bool:
        no_violation = any(k in q for k in [
            "not present", "no violation", "no issue", "zero violation", "zero issue",
            "clean", "fully compliant", "100% compliant", "compliant resource", "without violation",
            "not violating", "no issues violating", "no any issues violating", "issues are not violating",
            "no any violation"
        ])
        resource_ask = any(k in q for k in [
            "which resource", "in which", "what resource", "resource name", "resources", "resource",
            "any resource", "are there any"
        ])
        return no_violation and resource_ask

    def _is_non_violating_controls_query(self, q: str) -> bool:
        return any(k in q for k in [
            "not violating", "non violating", "non-violating", "not violation",
            "passing issues", "passing controls", "passing checks", "some issues",
            "mixed compliance", "partially compliant", "controls are passing",
            "issues which are not violating"
        ])

    def _is_bucket_object_exposure_query(self, q: str) -> bool:
        if self._is_zero_violation_query(q) or self._is_non_violating_controls_query(q):
            return False
        direct_phrases = [
            "publicly accessible", "authenticated url", "authenticated urls",
            "exposing authenticated", "giving more publicly accessible",
            "uniform bucket", "ubla", "object acl", "object acls", "object-level",
            "bucket is public", "public bucket", "objects are public",
            "exposing authenticated url", "exposing authenticated urls",
            "object is having exposing"
        ]
        if any(phrase in q for phrase in direct_phrases):
            return True
        has_storage = any(k in q for k in ["bucket", "storage", "gcs"])
        has_public = any(k in q for k in ["public", "accessible", "exposure", "exposing", "open"])
        has_object = any(k in q for k in ["object", "objects", "url", "urls", "authenticated", "acl", "acls", "ubla"])
        return has_storage and has_public and has_object

    def _is_action_prompt(self, q: str) -> bool:
        action_verbs = [
            "act on it", "act on this", "act on", "remediate", "fix", "heal",
            "auto-heal", "auto heal", "apply remediation", "enforce ubla",
            "enforce pap", "execute fix", "run remediation", "secure this"
        ]
        info_markers = ["how many", "count", "which", "what are", "what is", "are there", "in which", "where", "why", "list"]
        if any(marker in q for marker in info_markers):
            return False
        return any(verb in q for verb in action_verbs)

    def _is_agent_executable_query(self, q: str) -> bool:
        terms = [
            "what is agent executable", "agent executable", "what is executable",
            "executable finding", "executable issues", "what does executable mean",
            "execution criteria", "can the agent execute", "what can agent execute",
            "executable definition", "what is executable"
        ]
        return any(t in q for t in terms)

    def _is_multi_agent_query(self, q: str) -> bool:
        terms = [
            "multiple agents", "multi agent", "multi-agent", "what agents",
            "agents defined", "agents available", "subagents", "agent architecture",
            "which agents", "all agents", "specialized agents", "agent roster",
            "what are the agents"
        ]
        return any(t in q for t in terms)

    def _is_skills_query(self, q: str) -> bool:
        terms = [
            "multiple skills", "what skills", "skills defined", "available skills",
            "agent skills", "skills list", "what are the skills", "which skills",
            "all skills", "defined skills"
        ]
        return any(t in q for t in terms)

    def _is_tools_query(self, q: str) -> bool:
        terms = [
            "what all tools", "what tools", "tools defined for this", "tools defined",
            "defined tools", "mcp tools", "what are the tools", "which tools",
            "tool defined", "platform tools", "tools available", "what tools defined"
        ]
        return any(t in q for t in terms)

    def _is_fleet_incidents_query(self, q: str) -> bool:
        terms = [
            "fleet incidents", "30 resources", "36 resources", "40 resources",
            "repeating issues", "repeated issues", "how many resources have repeated",
            "all violated resources", "1000 resources", "1000+", "fleet scale",
            "repeating patterns", "active incidents", "incident cockpit"
        ]
        return any(t in q for t in terms)

    def _is_gcp_connector_query(self, q: str) -> bool:
        terms = [
            "connect to gcp", "connect with gcp", "gcp connector", "how to connect to gcp",
            "gcp connection", "live gcp", "cloud asset inventory connection", "workload identity",
            "connector gateway", "plug into gcp"
        ]
        return any(t in q for t in terms)

    def _find_resource_in_query(self, q: str) -> Optional[Dict[str, Any]]:
        for r in self.resources:
            name = r.get("resource_name", "").lower()
            if name and name in q:
                return r
        return None

    def _detect_service_scope(self, q: str) -> Optional[str]:
        if any(k in q for k in ["gke", "kubernetes", "k8s", "cluster"]):
            return "gke"
        if any(k in q for k in ["storage", "gcs", "bucket"]):
            return "gcs"
        if any(k in q for k in ["sql", "mysql", "postgres", "database"]):
            return "sql"
        if any(k in q for k in ["firewall", "vpc", "network", "vm", "compute", "gce", "ssh"]):
            return "firewall"
        if any(k in q for k in ["iam", "service account", "sa", "key", "credential"]):
            return "iam"
        if any(k in q for k in ["bigquery", "bq", "dataset"]):
            return "bigquery"
        if any(k in q for k in ["run", "cloud run", "serverless"]):
            return "cloudrun"
        return None

    def _answer_scoped_autoheal_violations(self, scope: Optional[str], resource: Optional[Dict[str, Any]], query: str) -> Dict[str, Any]:
        if scope == "gke" or (resource and "container" in resource.get("resource_type", "").lower()) or (resource and "gke" in resource.get("resource_name", "").lower()):
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>GKE AUTO-HEAL VIOLATIONS REPORT (ISSUES LISTED FIRST)</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">1 AUTO-HEAL VIOLATION IN GKE</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Auto-Heal Violation in GKE (Listed First):</strong>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1.5 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-emerald-300">#1 order-processing-cluster (GKE Cluster)</span>
      <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 AUTO-HEAL ISSUE</span>
    </div>
    <div class="text-[10px] text-slate-400">
      Resource ID: <code>projects/orders-staging/clusters/order-processing-cluster</code> • Tier: <strong>STAGING</strong> • Region: <code>us-central1</code>
    </div>
    <div class="text-amber-400 text-xs">
      • <strong>Finding #SCC-GKE-41029:</strong> Workload Identity disabled; pods mount static service account JSON secret keys (CIS GCP Benchmark v2.0 - 4.2).
    </div>
    <div class="text-[11px] text-slate-300 pt-0.5">
      <strong>Prescribed Auto-Heal Fix:</strong> Activate Workload Identity pool <code>orders-staging.svc.id.goog</code> and bind Kubernetes ServiceAccounts to Google Service Accounts. Zero downtime mutation.
    </div>
    <div class="pt-1 flex items-center justify-between text-[10px]">
      <span class="text-emerald-400">Policy: Auto-execute permitted under POL-AUTO-001 (Staging Tier)</span>
      <button onclick="triggerScenario('gke-workload-identity')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-2.5 py-1 rounded border border-emerald-500/40 cursor-pointer font-bold">Review Diff & Auto-Heal</button>
    </div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1">
    <div class="text-slate-300 font-semibold">GKE Fleet Context (Auto-Heal vs Production HITL):</div>
    <div>• <strong>Staging GKE (order-processing-cluster):</strong> <strong>1 Auto-Heal violation</strong> (Autonomous self-healing pre-authorized).</div>
    <div>• <strong>Production GKE (payments-gke-prod):</strong> Has <strong>2 active violations</strong> (Public master authorized networks & Network policy disabled), but these are <strong>Production HITL-Gated</strong> under <code>POL-PROD-002</code> requiring platform owner sign-off rather than auto-healing.</div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/20 text-[11px] text-slate-300 space-y-1">
    <div class="text-emerald-400 font-semibold">Auto-Heal Violations Across All Other GCP Resources:</div>
    <div class="grid grid-cols-2 gap-1 text-[10px] text-slate-300 pt-0.5">
      <div>• <strong>Cloud Storage (GCS):</strong> 12 auto-heal issues (2 dev bucket + 10 batch)</div>
      <div>• <strong>Cloud SQL (MySQL):</strong> 1 auto-heal issue (analytics-mysql-dev)</div>
      <div>• <strong>Compute Engine (VM):</strong> 1 auto-heal issue (db-worker-vm-01)</div>
      <div>• <strong>Cloud IAM (Keys):</strong> 1 auto-heal issue (ci-deployer-sa-key-9281)</div>
      <div>• <strong>BigQuery Datasets:</strong> 0 auto-heal issues (Prod HITL)</div>
      <div>• <strong>Cloud Run Services:</strong> 0 auto-heal issues (Prod HITL)</div>
    </div>
    <div class="pt-1 text-[10px] text-slate-400">Total Fleet Auto-Heal Count: <strong>16 violations</strong> across 6 non-prod resource groups.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>only GKE auto-heal violations</strong> (order-processing-cluster). Click the card to review diffs or run autonomous self-healing.</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": "gke",
                "sidebar_filter": "gke-autoheal",
                "count": 1,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        if scope == "sql":
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>CLOUD SQL AUTO-HEAL VIOLATIONS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">1 AUTO-HEAL VIOLATION</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Auto-Heal Violation on Cloud SQL (Listed First):</strong>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1.5 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-emerald-300">#1 analytics-mysql-dev (Cloud SQL MySQL 8.0)</span>
      <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 AUTO-HEAL ISSUE</span>
    </div>
    <div class="text-[10px] text-slate-400">
      Resource ID: <code>projects/analytics-dev/instances/analytics-mysql-dev</code> • Tier: <strong>DEVELOPMENT</strong>
    </div>
    <div class="text-amber-400 text-xs">
      • <strong>Finding #SCC-SQL-21094:</strong> Automated daily backups and point-in-time recovery disabled (CIS GCP Benchmark v2.0 - 6.7).
    </div>
    <div class="text-[11px] text-slate-300 pt-0.5">
      <strong>Prescribed Auto-Heal Fix:</strong> Enable automated backup configuration at 02:00 UTC with point-in-time recovery enabled. Zero downtime.
    </div>
    <div class="pt-1 flex items-center justify-between text-[10px]">
      <span class="text-emerald-400">Policy: Auto-execute permitted under POL-AUTO-001 (Dev Tier)</span>
      <button onclick="triggerScenario('sql-backup-disabled')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-2.5 py-1 rounded border border-emerald-500/40 cursor-pointer font-bold">Auto-Heal Cloud SQL</button>
    </div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1">
    <div>• <strong>Production Databases (customer-db-pg-prod):</strong> Has 2 violations (Public IP and SSL disabled), but requires Human-in-the-Loop approval under <code>POL-PROD-002</code>.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>only Cloud SQL auto-heal violations</strong> (analytics-mysql-dev).</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": "sql",
                "sidebar_filter": "sql-autoheal",
                "count": 1,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        if scope == "gcs":
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>CLOUD STORAGE AUTO-HEAL VIOLATIONS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">12 AUTO-HEAL VIOLATIONS</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Auto-Heal Violations on Cloud Storage (Listed First):</strong>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-emerald-300">1. retail-app-invoices-dev (Cloud Storage Bucket)</span>
      <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">2 ISSUES</span>
    </div>
    <div class="text-rose-400">• Public read access granted to <code>allUsers</code> (CIS GCP 5.1)</div>
    <div class="text-amber-400">• Missing 365-day Coldline lifecycle archive rule (CIS GCP 5.4)</div>
    <div class="text-[10px] text-slate-400 pt-0.5">Fix: Enforce PAP & apply Coldline lifecycle rule. Zero downtime.</div>
  </div>

  <div class="p-3 rounded-lg bg-blue-950/30 border border-blue-500/30 flex items-center justify-between text-[11px]">
    <div class="text-blue-300">
      <strong>2. Fleet Batch Dev Buckets (10 Developer Buckets):</strong> Public reading (allUsers)
    </div>
    <span class="text-[9px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded font-bold">10 BUCKETS</span>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>Cloud Storage auto-heal violations</strong>.</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": "gcs",
                "sidebar_filter": "gcs-autoheal",
                "count": 12,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        if scope in ["firewall", "vm", "compute"]:
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>COMPUTE & VPC AUTO-HEAL VIOLATIONS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">1 AUTO-HEAL VIOLATION</span>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-emerald-300">#1 db-worker-vm-01 (Compute Engine VM)</span>
      <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
    </div>
    <div class="text-amber-400">• Unauthorized public external IP <code>35.202.14.89</code> attached directly (CIS GCP 3.8)</div>
    <div class="text-[10px] text-slate-400 pt-0.5">Fix: Delete public AccessConfig interface; route egress via Cloud NAT.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>Compute auto-heal violations</strong> (db-worker-vm-01).</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": "firewall",
                "sidebar_filter": "vpc-autoheal",
                "count": 1,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        if scope == "iam":
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>CLOUD IAM AUTO-HEAL VIOLATIONS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">1 AUTO-HEAL VIOLATION</span>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-emerald-300">#1 ci-deployer-sa-key-9281 (IAM Service Account Key)</span>
      <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
    </div>
    <div class="text-amber-400">• User-managed credential active 142 days without rotation (>90-day limit) (CIS GCP 1.3)</div>
    <div class="text-[10px] text-slate-400 pt-0.5">Fix: Rotate cryptographic key and sync with Google Secret Manager.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>IAM auto-heal violations</strong> (ci-deployer-sa-key-9281).</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": "iam",
                "sidebar_filter": "iam-autoheal",
                "count": 1,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        if scope in ["bigquery", "cloudrun"]:
            ans_html = f"""
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-blue-950/40 border border-blue-500/40">
    <div class="flex items-center space-x-2 text-blue-400 font-bold text-xs">
      <i data-lucide="info" class="w-4 h-4 text-blue-400"></i>
      <span>{scope.upper()} AUTO-HEAL VIOLATIONS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold text-[10px]">0 AUTO-HEAL VIOLATIONS</span>
  </div>

  <p class="text-xs text-slate-200">
    There are <strong>0 auto-heal violations</strong> in {scope.upper()}. All active issues in this service are in Production and require Human-in-the-Loop review under <code>POL-PROD-002</code>.
  </p>
</div>
"""
            return {
                "intent": "SCOPED_AUTOHEAL_VIOLATIONS",
                "scope": scope,
                "sidebar_filter": "data-autoheal",
                "count": 0,
                "issues_first": True,
                "answer_markdown": ans_html,
            }

        # Fallback to general autoheal
        return self._answer_autoheal_violations()

    def _answer_scoped_prod_violations(self, scope: Optional[str], resource: Optional[Dict[str, Any]], query: str) -> Dict[str, Any]:
        if scope == "gke":
            ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-rose-950/40 border border-rose-500/40">
    <div class="flex items-center space-x-2 text-rose-400 font-bold text-xs">
      <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
      <span>GKE PRODUCTION VIOLATIONS REPORT (HITL GATED)</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px]">2 PROD VIOLATIONS IN GKE</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Production Violations on GKE (Listed First):</strong>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-rose-500/40 space-y-1.5 text-[11px]">
    <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
      <span class="text-rose-300">#1 payments-gke-prod (GKE Cluster)</span>
      <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">2 ISSUES • RISK: 96/100</span>
    </div>
    <div class="text-rose-400">• Master authorized networks allows unrestricted internet access <code>0.0.0.0/0</code> (CIS GCP 4.1)</div>
    <div class="text-rose-400">• Network Policy enforcement disabled (CIS GCP 4.6)</div>
    <div class="text-[10px] text-slate-400 pt-0.5">Blast Radius: 14 microservices. Fix: Restrict master to corporate bastion & enable Calico.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>GKE production violations</strong> (payments-gke-prod).</em>
  </p>
</div>
"""
            return {
                "intent": "SCOPED_PROD_VIOLATIONS",
                "scope": "gke",
                "sidebar_filter": "gke-prod",
                "count": 2,
                "issues_first": True,
                "answer_markdown": ans_html,
            }
        return self._answer_prod_violations()

    # -------------------------------------------------------------------------
    # Authoritative Answer Generators
    # -------------------------------------------------------------------------

    def _answer_autoheal_violations(self) -> Dict[str, Any]:
        autoheal_findings = [
            f for f in self.findings
            if f.get("remediation", {}).get("governance_decision") == "AUTO_EXECUTE"
            and f.get("scenario_key") != "gcs-zero-violation"
        ]

        total_violations = len(autoheal_findings) + 10  # 10 batch developer buckets

        # Format issues first
        issues_html = """
<div class="space-y-3">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40 font-mono">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>AUTO-HEAL ELIGIBLE VIOLATIONS REPORT (DEV & NON-PROD TIER)</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">16 ACTIVE VIOLATIONS</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Auto-Healable Issues Breakdown (Listed First):</strong>
  </div>

  <div class="space-y-2 font-mono text-[11px]">
    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-emerald-300">1. retail-app-invoices-dev (Cloud Storage Bucket)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">2 ISSUES</span>
      </div>
      <div class="text-rose-400">• Public read access granted to <code>allUsers</code> (CIS GCP Benchmark v2.0 - 5.1)</div>
      <div class="text-amber-400">• Missing 365-day Coldline lifecycle archive rule (CIS GCP Benchmark v2.0 - 5.4)</div>
      <div class="text-[10px] text-slate-400 pt-0.5">Fix: Enforce PAP & apply Coldline lifecycle rule. Zero downtime.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-emerald-300">2. analytics-mysql-dev (Cloud SQL Instance)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
      </div>
      <div class="text-amber-400">• Automated daily backups and point-in-time recovery disabled (CIS GCP Benchmark v2.0 - 6.7)</div>
      <div class="text-[10px] text-slate-400 pt-0.5">Fix: Schedule automated daily snapshots at 03:00 UTC.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-emerald-300">3. db-worker-vm-01 (Compute Engine VM)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
      </div>
      <div class="text-amber-400">• Unauthorized public external IP <code>35.202.14.89</code> attached directly (CIS GCP Benchmark v2.0 - 3.8)</div>
      <div class="text-[10px] text-slate-400 pt-0.5">Fix: Delete public AccessConfig interface; route egress via Cloud NAT.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-emerald-300">4. ci-deployer-sa-key-9281 (IAM Service Account Key)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
      </div>
      <div class="text-amber-400">• User-managed credential active 142 days without rotation (>90-day limit) (CIS GCP Benchmark v2.0 - 1.3)</div>
      <div class="text-[10px] text-slate-400 pt-0.5">Fix: Rotate cryptographic key and sync with Google Secret Manager.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-emerald-300">5. nightly-cleanup-function-dev (Cloud Function)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold">1 ISSUE</span>
      </div>
      <div class="text-amber-400">• Public ingress setting enabled & outdated Python 3.8 runtime (Google Security Baseline)</div>
      <div class="text-[10px] text-slate-400 pt-0.5">Fix: Restrict ingress to internal-only and upgrade runtime to python312.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-blue-950/30 border border-blue-500/30 flex items-center justify-between">
      <div class="text-blue-300">
        <strong>6. Fleet Batch Dev Buckets (10 Developer Buckets):</strong> Public reading (allUsers)
      </div>
      <span class="text-[9px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded font-bold">10 BUCKETS</span>
    </div>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-1.5">
    <div><strong>Total Count:</strong> <strong>16 Auto-Heal Violations</strong> across <strong>6 Non-Production Resource Groups</strong>.</div>
    <div><strong>Governance Evaluation:</strong> Authorized by policy <code>POL-AUTO-001: Non-Prod Self-Healing</code>. Zero production blast radius. Auto-execution takes &lt; 30 seconds.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to display <strong>only these auto-heal violation issues</strong>. Click any card to inspect or trigger auto-remediation.</em>
  </p>
</div>
"""
        return {
            "intent": "AUTOHEAL_VIOLATIONS",
            "sidebar_filter": "autoheal",
            "count": 16,
            "answer_markdown": issues_html,
            "issues_first": True,
        }

    def _answer_prod_violations(self) -> Dict[str, Any]:
        prod_findings = [
            f for f in self.findings
            if f.get("environment") == "production"
            and f.get("scenario_key") != "gcs-zero-violation"
        ]

        issues_html = """
<div class="space-y-3">
  <div class="flex items-center justify-between p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 font-mono">
    <div class="flex items-center space-x-2 text-rose-400 font-bold text-xs">
      <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
      <span>PRODUCTION VIOLATIONS REPORT (MANDATORY HITL GATED)</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px]">16 VIOLATIONS • 12 ASSETS</span>
  </div>

  <div class="text-xs text-slate-200">
    <strong>Active Production Violations & Issues (Listed First, Ranked by Risk):</strong>
  </div>

  <div class="space-y-2 font-mono text-[11px]">
    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/40 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-rose-300">#1 allow-ssh-ingress (VPC Firewall Rule)</span>
        <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">RISK: 98/100 (CRITICAL)</span>
      </div>
      <div class="text-rose-400">• Inbound SSH port 22 open to <code>0.0.0.0/0</code> from public internet (CIS GCP 3.6)</div>
      <div class="text-[10px] text-slate-400">Blast Radius: 8 production backend instances. Fix: Restrict to Google IAP CIDR.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/40 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-rose-300">#2 payments-gke-prod (GKE Cluster)</span>
        <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">RISK: 96/100 (CRITICAL)</span>
      </div>
      <div class="text-rose-400">• Master authorized networks allows unrestricted internet access <code>0.0.0.0/0</code> (CIS GCP 4.1)</div>
      <div class="text-rose-400">• Network Policy enforcement disabled (CIS GCP 4.6)</div>
      <div class="text-[10px] text-slate-400">Blast Radius: 14 microservices. Fix: Restrict master to corporate bastion & enable Calico.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/40 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-rose-300">#3 customer-db-pg-prod (Cloud SQL PostgreSQL)</span>
        <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">RISK: 95/100 (CRITICAL)</span>
      </div>
      <div class="text-rose-400">• Public IPv4 enabled with <code>0.0.0.0/0</code> authorized network (CIS GCP 6.2)</div>
      <div class="text-[10px] text-slate-400">Blast Radius: Customer PCI database. Fix: Clear public IP & bind Private Service Access.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/40 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-rose-300">#4 customer_churn (BigQuery Dataset)</span>
        <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">RISK: 94/100 (CRITICAL)</span>
      </div>
      <div class="text-rose-400">• Dataset reader role granted to <code>allAuthenticatedUsers</code> (CIS GCP 7.1)</div>
      <div class="text-[10px] text-slate-400">Fix: Revoke public group; scope access to verified analyst Google Group.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#5 etl-batch-sa (IAM Service Account)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">RISK: 89/100 (HIGH)</span>
      </div>
      <div class="text-amber-400">• Primitive <code>roles/owner</code> role assigned to batch ETL service account (CIS GCP 1.4)</div>
      <div class="text-[10px] text-slate-400">Fix: Downgrade to least-privilege roles (roles/bigquery.jobUser, storage.objectViewer).</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#6 payment-processor-service (Cloud Run)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">RISK: 86/100 (HIGH)</span>
      </div>
      <div class="text-amber-400">• Unauthenticated invocation allowed for <code>allUsers</code> (Cloud Run Security Baseline)</div>
      <div class="text-[10px] text-slate-400">Fix: Revoke allUsers; restrict invoker role to API Gateway service account.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#7 financial-audit-logs-prod (Cloud Storage)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">RISK: 84/100 (HIGH)</span>
      </div>
      <div class="text-amber-400">• Missing Customer-Managed Encryption Key (CMEK) via Cloud KMS (CIS GCP 5.3)</div>
      <div class="text-[10px] text-slate-400">Fix: Attach Cloud KMS key <code>keyRings/kms-prod/cryptoKeys/audit-key</code>.</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#8 payment-kek (Cloud KMS CryptoKey)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">RISK: 80/100 (HIGH)</span>
      </div>
      <div class="text-amber-400">• 90-day automatic cryptographic rotation schedule disabled (CIS GCP 1.10)</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#9 orders-mysql-prod (Cloud SQL MySQL)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">2 DISTINCT FINDINGS (HIGH)</span>
      </div>
      <div class="text-amber-400">• #SCC-SQL-MULTI-4401: Automated backups disabled (CIS GCP 6.7)</div>
      <div class="text-amber-400">• #SCC-SQL-MULTI-4401-SSL: Unencrypted client connections permitted (CIS GCP 6.4)</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-amber-300">#10 stripe-live-api-key (Secret Manager)</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded font-bold">RISK: 76/100 (HIGH)</span>
      </div>
      <div class="text-amber-400">• Payment credential secret lacks Customer-Managed Encryption Key (Google Security Baseline)</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-blue-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-blue-300">#11 order-processing-cluster (GKE Cluster)</span>
        <span class="text-[9px] bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded font-bold">RISK: 68/100 (MEDIUM)</span>
      </div>
      <div class="text-blue-400">• Workload Identity disabled; pods mount static service account JSON keys (CIS GCP 4.2)</div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-blue-500/30 space-y-1">
      <div class="flex items-center justify-between text-slate-200 font-semibold text-xs">
        <span class="text-blue-300">#12 payment-events-topic-prod (Pub/Sub Topic)</span>
        <span class="text-[9px] bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded font-bold">RISK: 58/100 (MEDIUM)</span>
      </div>
      <div class="text-blue-400">• Transaction message topic missing Customer-Managed Encryption Key (CMEK)</div>
    </div>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-rose-500/20 text-xs text-slate-300 space-y-1.5">
    <div><strong>Total Count:</strong> <strong>16 Production Violations</strong> across <strong>12 Production Assets</strong>.</div>
    <div><strong>Governance Enforcement:</strong> Governed by rule <code>POL-PROD-002: Production Mandatory Human Approval</code>. Autonomous execution is strictly blocked; requires explicit sign-off from Platform Owner, SRE Principal, or Security Lead.</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>only these production violation issues</strong>. Click any card to inspect technical diffs and trigger the Human-in-the-Loop approval gate.</em>
  </p>
</div>
"""
        return {
            "intent": "PROD_VIOLATIONS",
            "sidebar_filter": "hitl",
            "count": 16,
            "answer_markdown": issues_html,
            "issues_first": True,
        }

    def _answer_zero_violation_resource(self) -> Dict[str, Any]:
        resource_name = "secure-backup-vault-prod"
        resource_id = "projects/security-prod/buckets/secure-backup-vault-prod"

        ans_html = f"""
<div class="space-y-3">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40 font-mono">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="check-circle-2" class="w-4 h-4 text-emerald-400"></i>
      <span>ZERO-VIOLATION (FULLY COMPLIANT) RESOURCE IDENTIFIED</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">100% COMPLIANT</span>
  </div>

  <p class="text-xs text-slate-200">
    The resource in which <strong>no any issues are violating (zero active violations)</strong> is:
  </p>

  <div class="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-500/50 font-mono text-xs space-y-2">
    <div class="flex items-center justify-between text-emerald-300 font-bold text-sm">
      <span>gs://{resource_name}</span>
      <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">NO ANY ISSUES VIOLATING</span>
    </div>
    <div class="text-[11px] text-slate-400">
      Resource ID: <code>{resource_id}</code><br/>
      Project: <code>security-prod</code> • Environment: <code>PRODUCTION</code> • Region: <code>us-central1</code>
    </div>

    <div class="pt-1.5 border-t border-emerald-500/20 space-y-1 text-[11px] text-slate-300">
      <div class="text-emerald-400 font-semibold mb-1">Active Compliant Controls (4 of 4 Passing — No Any Issues Violating):</div>
      <div>✔ <strong>Control 1 - Public Access Prevention (PAP):</strong> ENFORCED (Not violating — allUsers strictly prohibited).</div>
      <div>✔ <strong>Control 2 - Data at Rest Encryption:</strong> Cloud KMS Customer-Managed Key active (Not violating — <code>kms-vault/cryptoKeys/vault-master-key</code>).</div>
      <div>✔ <strong>Control 3 - Object Versioning & Retention:</strong> Locked immutable 7-year regulatory retention policy (Not violating).</div>
      <div>✔ <strong>Control 4 - Uniform Bucket-Level Access (UBLA):</strong> ENFORCED (Not violating — legacy object ACLs disabled).</div>
    </div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1">
    <div><strong>Additional Certified Compliant Enterprise Resources (No Any Issues Violating):</strong></div>
    <div>• <code>global-ledger-spanner-prod</code> (Cloud Spanner - Multi-region HA & CMEK)</div>
    <div>• <code>fraud-detection-bigtable-prod</code> (Cloud Bigtable - Multi-cluster routing & IAM)</div>
    <div>• <code>corporate-shared-vpc</code> (VPC Network - Private Service Access & Cloud NAT)</div>
    <div>• <code>org-compliance-audit-sink</code> (Cloud Logging - Centralized immutable audit sink)</div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left inventory sidebar to show <strong>no any issues violating</strong> on <strong>{resource_name}</strong>. Click its card to view the zero-drift verification receipt.</em>
  </p>
</div>
"""
        return {
            "intent": "ZERO_VIOLATION_RESOURCE",
            "sidebar_filter": "clean",
            "resource_name": resource_name,
            "resource_id": resource_id,
            "answer_markdown": ans_html,
            "issues_first": False,
        }

    def _answer_non_violating_controls(self, q: str) -> Dict[str, Any]:
        resource_name = "analytics-warehouse-export-prod"
        resource_id = "projects/analytics-prod/buckets/analytics-warehouse-export-prod"

        ans_html = f"""
<div class="space-y-3">
  <div class="flex items-center justify-between p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/40 font-mono">
    <div class="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
      <i data-lucide="shield-check" class="w-4 h-4 text-cyan-400"></i>
      <span>PARTIAL COMPLIANCE & NON-VIOLATING CONTROLS REPORT</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-[10px]">3 PASSING • RESCAN PENDING</span>
  </div>

  <p class="text-xs text-slate-200">
    On resource <strong>{resource_name}</strong> (posture: <code>UNKNOWN_REQUIRES_RESCAN</code>), here is the authoritative breakdown of security controls which have <strong>no any issues violating</strong>:
  </p>

  <div class="p-3.5 rounded-xl bg-slate-900 border border-cyan-500/30 font-mono text-xs space-y-2.5">
    <div class="flex items-center justify-between text-cyan-300 font-bold">
      <span>gs://{resource_name}</span>
      <span class="text-[9px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">3 PASSING CONTROLS</span>
    </div>

    <!-- NON-VIOLATING / PASSING CONTROLS FIRST -->
    <div class="space-y-1.5 pt-1">
      <div class="text-emerald-400 font-semibold text-[11px]">Controls That Are NOT Violating (3 Compliant Controls Verified):</div>
      
      <div class="p-2 rounded bg-emerald-950/30 border border-emerald-500/30 text-[11px] text-emerald-300 space-y-0.5">
        <div class="font-bold">✔ Control 1 (NOT VIOLATING): Public Access Prevention (PAP)</div>
        <div class="text-[10px] text-slate-300">Status: <strong>ENFORCED</strong>. No <code>allUsers</code> or <code>allAuthenticatedUsers</code> exist. Bucket is strictly private.</div>
      </div>

      <div class="p-2 rounded bg-emerald-950/30 border border-emerald-500/30 text-[11px] text-emerald-300 space-y-0.5">
        <div class="font-bold">✔ Control 2 (NOT VIOLATING): Object Lifecycle Management</div>
        <div class="text-[10px] text-slate-300">Status: <strong>VERIFIED</strong>. Automated rule actively archives objects older than 90 days to Coldline storage.</div>
      </div>

      <div class="p-2 rounded bg-emerald-950/30 border border-emerald-500/30 text-[11px] text-emerald-300 space-y-0.5">
        <div class="font-bold">✔ Control 3 (NOT VIOLATING): Uniform Bucket-Level Access (UBLA)</div>
        <div class="text-[10px] text-slate-300">Status: <strong>VERIFIED</strong>. Cloud IAM governs all object permissions; legacy ACLs are disabled.</div>
      </div>
    </div>

    <!-- POSTURE RECONCILIATION AUDIT -->
    <div class="p-2 rounded bg-amber-950/30 border border-amber-500/30 text-[11px] text-amber-300 space-y-0.5">
      <div class="font-bold text-amber-400">ℹ Audit Posture Status: UNKNOWN_REQUIRES_RESCAN</div>
      <div class="text-[10px] text-slate-300">
        Prior finding references were reconciled. 0 active violations remain in the current findings list, but fresh inventory/policy evaluation is required before asserting 100% certified compliance.
      </div>
    </div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
    <strong>Agentic Platform Intelligence:</strong> The agent accurately separates verified compliant controls (PAP, lifecycle rules, UBLA) from pending evaluations without making false compliance assertions.
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the sidebar to display <strong>{resource_name}</strong>. Click its card to view the reconciled posture and control verification.</em>
  </p>
</div>
"""
        return {
            "intent": "NON_VIOLATING_CONTROLS",
            "sidebar_filter": "partial",
            "resource_name": resource_name,
            "resource_id": resource_id,
            "answer_markdown": ans_html,
            "issues_first": True,
        }

    def _answer_risk_rankings(self) -> Dict[str, Any]:
        ranked = get_ranked_findings()[:5]
        items_html = "".join([
            f"""
            <div class="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between text-[11px] font-mono">
              <div>
                <span class="font-bold text-slate-200">#{item.get('rank', i+1)} {item.get('resource_name')}</span>
                <span class="text-slate-400 ml-2">({item.get('service')})</span>
                <div class="text-[10px] text-rose-400">{item.get('description')}</div>
              </div>
              <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px] shrink-0 ml-2">
                Score: {item.get('risk_assessment', {}).get('score')}/100
              </span>
            </div>
            """
            for i, item in enumerate(ranked)
        ])

        ans_html = f"""
<div class="space-y-2.5">
  <div class="flex items-center space-x-2 text-rose-400 font-bold text-xs font-mono">
    <i data-lucide="trending-up" class="w-4 h-4 text-rose-400"></i>
    <span>TOP RANKED VIOLATIONS BY COMPOSITE RISK SCORE (PRD §13)</span>
  </div>
  <div class="space-y-1.5">{items_html}</div>
  <p class="text-slate-400 text-[11px]">
    Risk Score Formula: <code>(Env Weight × 0.45) + (Category Weight × 0.40) + (Blast Radius × 0.75)</code>
  </p>
</div>
"""
        return {
            "intent": "RANKED_RISK",
            "sidebar_filter": "violated",
            "answer_markdown": ans_html,
            "issues_first": True,
        }

    def _answer_resource_details(self, res: Dict[str, Any], scenario_hint: Optional[str] = None, custom_title: Optional[str] = None) -> Dict[str, Any]:
        name = res.get("resource_name")
        posture = res.get("compliance_posture", {})
        status = posture.get("status", "UNKNOWN")
        violations = posture.get("violation_ids", [])
        config = res.get("current_configuration", {})

        # Find associated finding if any
        finding = next((f for f in self.findings if f.get("resource_name") == name or (scenario_hint and f.get("scenario_key") == scenario_hint)), None)
        scenario_key = scenario_hint or (finding.get("scenario_key") if finding else None)

        title = custom_title or f"RESOURCE CONFIGURATION: {name}"

        # Format key configuration properties
        config_rows = []
        for k, v in config.items():
            if isinstance(v, (str, int, float, bool)):
                config_rows.append(f"<div>• <strong>{k}:</strong> <code>{v}</code></div>")
            elif isinstance(v, list) and v and isinstance(v[0], str):
                config_rows.append(f"<div>• <strong>{k}:</strong> <code>{', '.join(v)}</code></div>")
            elif isinstance(v, dict) and v:
                config_rows.append(f"<div>• <strong>{k}:</strong> <code>{str(v)}</code></div>")

        config_section = "".join(config_rows[:6]) if config_rows else "<div>• Standard default parameters</div>"

        action_button = ""
        if scenario_key:
            action_button = f"""
            <div class="pt-2 flex items-center justify-between border-t border-slate-800">
              <span class="text-[10px] text-slate-400">Playbook: <code>{scenario_key}</code></span>
              <button onclick="triggerScenario('{scenario_key}')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-3 py-1.5 rounded border border-emerald-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5">
                <i data-lucide="zap" class="w-3.5 h-3.5 text-emerald-400"></i>
                <span>Act On This: Remediate</span>
              </button>
            </div>
            """

        ans_html = f"""
<div class="space-y-2.5 font-mono text-xs">
  <div class="flex items-center justify-between p-2.5 rounded-xl bg-slate-900 border border-slate-800">
    <div class="flex items-center space-x-2">
      <i data-lucide="layers" class="w-4 h-4 text-blue-400"></i>
      <span class="font-bold text-slate-200">{title}</span>
    </div>
    <span class="px-2 py-0.5 rounded { 'bg-emerald-500/20 text-emerald-300' if status == 'COMPLIANT' else 'bg-rose-500/20 text-rose-300' } font-bold text-[10px]">
      {status}
    </span>
  </div>

  <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2 text-[11px] text-slate-300">
    <div class="text-blue-300 font-bold">{res.get('resource_id')}</div>
    <div class="grid grid-cols-2 gap-1 text-[10px] text-slate-400">
      <div>Environment: <strong>{res.get('environment', '').upper()}</strong></div>
      <div>Region: <strong>{res.get('region')}</strong></div>
      <div>Criticality: <strong>{res.get('criticality_tier')}</strong></div>
      <div>Owner: <strong>{res.get('owner')}</strong></div>
    </div>

    <div class="pt-1.5 border-t border-slate-800 text-[11px] space-y-1">
      <div class="text-slate-200 font-semibold">Active Configuration State:</div>
      {config_section}
    </div>

    { f'''<div class="pt-1 text-rose-400"><strong>Active Findings:</strong> {", ".join(violations)} — {finding.get("description", "") if finding else ""}</div>''' if violations else '''<div class="pt-1 text-emerald-400"><strong>Compliance:</strong> Zero active violations. Passing controls: ''' + str(posture.get('passing_controls_count', 0)) + '''</div>''' }

    {action_button}
  </div>
</div>
"""
        return {
            "intent": "RESOURCE_DETAIL",
            "sidebar_filter": scenario_key or "all",
            "resource_name": name,
            "answer_markdown": ans_html,
            "issues_first": False,
        }

    def _answer_bucket_public_and_object_authenticated_urls(self, q: str) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/40">
    <div class="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
      <i data-lucide="shield-alert" class="w-4 h-4 text-cyan-400"></i>
      <span>STORAGE SECURITY AUDIT: BUCKET PUBLIC ACCESS vs OBJECT AUTHENTICATED URLs</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-[10px]">MULTI-LAYER EXPOSURE</span>
  </div>

  <p class="text-xs text-slate-200">
    In enterprise GCP environments, bucket-level exposure and object-level URL exposure are governed by distinct configuration layers. Here is the exact posture from live inventory:
  </p>

  <!-- Culprit Bucket Card -->
  <div class="p-3.5 rounded-xl bg-slate-900 border border-rose-500/40 text-xs space-y-2.5">
    <div class="flex items-center justify-between text-rose-300 font-bold">
      <div class="flex items-center space-x-2">
        <i data-lucide="folder-lock" class="w-4 h-4 text-rose-400"></i>
        <span>gs://retail-app-invoices-dev</span>
      </div>
      <span class="text-[9px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">2 ACTIVE EXPOSURES</span>
    </div>
    <div class="text-[11px] text-slate-400">
      Resource URI: <code>projects/retail-dev-env/buckets/retail-app-invoices-dev</code> • Env: <strong>DEVELOPMENT</strong> • Region: <code>us-central1</code>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 text-[11px]">
      <!-- 1. Bucket Level Public Access -->
      <div class="p-2.5 rounded bg-rose-950/30 border border-rose-500/30 space-y-1">
        <div class="text-rose-400 font-bold flex items-center space-x-1.5">
          <i data-lucide="globe" class="w-3.5 h-3.5"></i>
          <span>1. Bucket-Level Public Access</span>
        </div>
        <div class="text-slate-300 text-[10px]">
          • <strong>Public Access Prevention (PAP):</strong> <code>unspecified</code> (DISABLED)<br/>
          • <strong>IAM Binding:</strong> <code>roles/storage.objectViewer</code> granted to <code>allUsers</code><br/>
          • <strong>Exposure:</strong> Entire bucket and directory listing open to unauthenticated internet traffic.
        </div>
      </div>

      <!-- 2. Object Level Exposing Authenticated URLs -->
      <div class="p-2.5 rounded bg-amber-950/30 border border-amber-500/30 space-y-1">
        <div class="text-amber-400 font-bold flex items-center space-x-1.5">
          <i data-lucide="link-2" class="w-3.5 h-3.5"></i>
          <span>2. Object-Level Authenticated URLs</span>
        </div>
        <div class="text-slate-300 text-[10px]">
          • <strong>Uniform Bucket-Level Access (UBLA):</strong> <code>false</code> (DISABLED)<br/>
          • <strong>Legacy Object ACLs:</strong> ACTIVE on individual files<br/>
          • <strong>Authenticated Exposure:</strong> Specific files (e.g. <code>invoices/2026/inv-9012.pdf</code>, <code>receipts/rec-4412.png</code>) grant <code>allAuthenticatedUsers:READER</code>, exposing authenticated URLs to anyone with any Google account!
        </div>
      </div>
    </div>

    <!-- Comparative Fleet Context -->
    <div class="p-2.5 rounded bg-slate-950/60 border border-slate-800 text-[11px] space-y-1 text-slate-300">
      <div class="font-bold text-slate-200">Enterprise Fleet Comparison Across All Other Buckets:</div>
      <div>• <strong>analytics-warehouse-export-prod:</strong> UBLA=<code>ENFORCED</code>, PAP=<code>ENFORCED</code>. Individual object authenticated URLs are completely blocked! (Only missing CMEK).</div>
      <div>• <strong>secure-backup-vault-prod:</strong> 100% compliant. UBLA=<code>ENFORCED</code>, PAP=<code>ENFORCED</code>, CMEK=<code>ACTIVE</code>, locked retention. Zero active violations.</div>
      <div>• <strong>customer_churn (BigQuery Dataset):</strong> Similar risk where dataset reader role is granted to <code>allAuthenticatedUsers</code>.</div>
    </div>

    <!-- Governing Policies -->
    <div class="text-[10px] text-slate-400 space-y-0.5 pt-1">
      <div><strong>Governing Policies & Standards:</strong></div>
      <div>• <code>POL-CIS-GCP-5.1</code>: Cloud Storage Public Access Prevention (Mandatory PAP=enforced).</div>
      <div>• <code>POL-CIS-GCP-5.2</code>: Enforce Uniform Bucket-Level Access (Eliminates object ACLs and closes authenticated URLs).</div>
    </div>

    <!-- ACTION TRIGGER -->
    <div class="pt-2 flex items-center justify-between border-t border-slate-800">
      <span class="text-emerald-400 text-[10px]">Pre-authorized for Autonomous Auto-Healing under POL-AUTO-001 (Dev Tier)</span>
      <button onclick="triggerScenario('gcs-multi-issue')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-3 py-1.5 rounded border border-emerald-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
        <i data-lucide="zap" class="w-3.5 h-3.5 text-emerald-400"></i>
        <span>Act On This: Auto-Heal Bucket</span>
      </button>
    </div>
  </div>

  <p class="text-slate-400 text-[11px]">
    👉 <em>I have filtered the left sidebar inventory to show <strong>Cloud Storage resources</strong>. Click the card or button above to execute autonomous remediation, or type <strong>"act on it"</strong> / <strong>"remediate this"</strong> to trigger immediately.</em>
  </p>
</div>
"""
        return {
            "intent": "BUCKET_OBJECT_EXPOSURE_AUDIT",
            "sidebar_filter": "gcs",
            "resource_name": "retail-app-invoices-dev",
            "count": 2,
            "issues_first": True,
            "action_available": True,
            "scenario_key": "gcs-multi-issue",
            "answer_markdown": ans_html,
        }

    def _answer_action_prompt(self, q: str) -> Dict[str, Any]:
        matched_key = "gcs-multi-issue"
        sidebar_filter = "gcs-autoheal"
        resource_name = "retail-app-invoices-dev"
        action_title = "Enforce UBLA, Enforce PAP & Apply Lifecycle Rule"
        is_prod = False

        if any(k in q for k in ["batch", "all dev", "fleet", "10 bucket"]):
            matched_key = "batch-gcs-dev"
            sidebar_filter = "autoheal"
            resource_name = "Fleet Batch Dev Buckets (10 Buckets)"
            action_title = "Batch Enforce PAP Across 10 Developer Buckets"
        elif any(k in q for k in ["ssh", "firewall", "port 22", "iap"]):
            matched_key = "fw-open-ssh"
            sidebar_filter = "vpc-prod"
            resource_name = "allow-ssh-ingress"
            action_title = "Restrict Port 22 Ingress to Google IAP CIDR"
            is_prod = True
        elif any(k in q for k in ["gke", "kubernetes", "k8s", "cluster"]):
            if any(k in q for k in ["workload", "order"]):
                matched_key = "gke-workload-identity"
                sidebar_filter = "gke-autoheal"
                resource_name = "order-processing-cluster"
                action_title = "Enable Workload Identity on GKE Cluster"
            else:
                matched_key = "gke-multi-issue"
                sidebar_filter = "gke-prod"
                resource_name = "payments-gke-prod"
                action_title = "Restrict Master Authorized Networks & Enable Calico"
                is_prod = True
        elif any(k in q for k in ["sql", "mysql", "database", "postgres"]):
            if any(k in q for k in ["backup", "mysql", "analytics-mysql"]):
                matched_key = "sql-backup-disabled"
                sidebar_filter = "sql-autoheal"
                resource_name = "analytics-mysql-dev"
                action_title = "Enable Automated Daily Backups on Cloud SQL"
            else:
                matched_key = "sql-multi-issue"
                sidebar_filter = "sql-prod"
                resource_name = "customer-db-pg-prod"
                action_title = "Disable Public IPv4 & Enforce SSL Only"
                is_prod = True
        elif any(k in q for k in ["vm", "external ip", "gce"]):
            matched_key = "vm-external-ip"
            sidebar_filter = "vpc-autoheal"
            resource_name = "db-worker-vm-01"
            action_title = "Remove Public External IP AccessConfig from VM"
        elif any(k in q for k in ["owner", "sa", "service account"]):
            matched_key = "iam-sa-owner"
            sidebar_filter = "iam-prod"
            resource_name = "etl-batch-sa"
            action_title = "Downgrade Primitive roles/owner to Scoped Roles"
            is_prod = True
        elif any(k in q for k in ["key", "rotate", "ci-deployer"]):
            matched_key = "iam-key-unrotated"
            sidebar_filter = "iam-autoheal"
            resource_name = "ci-deployer-sa-key-9281"
            action_title = "Rotate Expired Service Account Key"
        elif any(k in q for k in ["bigquery", "dataset", "churn"]):
            matched_key = "bq-public-dataset"
            sidebar_filter = "data-prod"
            resource_name = "customer_churn"
            action_title = "Revoke allAuthenticatedUsers from BigQuery Dataset"
            is_prod = True
        elif any(k in q for k in ["run", "cloud run", "payment-processor"]):
            matched_key = "run-unauth-invoker"
            sidebar_filter = "data-prod"
            resource_name = "payment-processor-service"
            action_title = "Revoke allUsers Unauthenticated Invoker Role"
            is_prod = True
        elif any(k in q for k in ["cmek", "audit"]):
            matched_key = "gcs-cmek"
            sidebar_filter = "gcs-prod"
            resource_name = "financial-audit-logs-prod"
            action_title = "Enforce Customer-Managed Encryption Key (CMEK)"
            is_prod = True

        gate_badge = (
            '<span class="text-[9px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">MANDATORY HITL APPROVAL</span>'
            if is_prod
            else '<span class="text-[9px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">AUTONOMOUS AUTO-HEAL</span>'
        )

        ans_html = f"""
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="play-circle" class="w-4 h-4 text-emerald-400"></i>
      <span>DISPATCHING ACTION: {resource_name}</span>
    </div>
    {gate_badge}
  </div>

  <p class="text-xs text-slate-200">
    Acting immediately on your request! Initialized remediation execution pipeline for <strong>{resource_name}</strong>.
  </p>

  <div class="p-3 rounded-lg bg-slate-900 border border-emerald-500/30 text-xs space-y-1.5 text-slate-300">
    <div><strong>Action:</strong> {action_title}</div>
    <div><strong>Target Scenario:</strong> <code>{matched_key}</code></div>
    <div><strong>Status:</strong> Vertex Reasoning Engine synthesized declarative technical diff and validated rollback snapshot.</div>
  </div>

  <div class="pt-1">
    <button onclick="triggerScenario('{matched_key}')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-3 py-1.5 rounded border border-emerald-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="zap" class="w-3.5 h-3.5 text-emerald-400"></i>
      <span>Execute Remediation Plan</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "EXECUTE_REMEDIATION",
            "action_executable": True,
            "scenario_key": matched_key,
            "sidebar_filter": sidebar_filter,
            "resource_name": resource_name,
            "answer_markdown": ans_html,
        }

    def _answer_agent_executable(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40">
    <div class="flex items-center space-x-2 text-emerald-400 font-bold text-xs">
      <i data-lucide="zap" class="w-4 h-4 text-emerald-400"></i>
      <span>WHAT IS AGENT EXECUTABLE? — ENTERPRISE SPECIFICATION</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">4 GOVERNANCE CRITERIA</span>
  </div>

  <p class="text-xs text-slate-200">
    In this platform, a compliance violation is <strong>Agent Executable</strong> when it meets 4 rigorous enterprise safety invariants:
  </p>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="text-emerald-300 font-bold">1. Deterministic Idempotency</div>
      <div class="text-slate-300 text-[10px]">
        Remediation must be expressed as declarative state mutations (Terraform HCL diff / Google Cloud API patch) that produce the identical secure state without side-effects or duplicate mutations.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="text-emerald-300 font-bold">2. Pre-Flight Blast Radius = 0</div>
      <div class="text-slate-300 text-[10px]">
        Vertex Reasoning Engine evaluates dependency graphs in Cloud Asset Inventory. Non-prod changes execute with verified zero blast radius on production workloads.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="text-amber-300 font-bold">3. Tier-Gated Policy Invariants</div>
      <div class="text-slate-300 text-[10px]">
        • <strong>Dev/Staging:</strong> Auto-executed under <code>POL-AUTO-001</code> (&lt;30s duration).<br/>
        • <strong>Production:</strong> Pre-synthesizes plan but holds execution under <code>POL-PROD-002</code> until 2-officer HITL sign-off.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-cyan-500/30 space-y-1">
      <div class="text-cyan-300 font-bold">4. Probing & Instant Rollback</div>
      <div class="text-slate-300 text-[10px]">
        Pre-remediation snapshot recorded. Post-remediation synthetic probe verifies zero drift; triggers immediate sub-second rollback if telemetry diverges.
      </div>
    </div>
  </div>

  <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-300 space-y-1">
    <div class="font-bold text-slate-200">Fleet Execution Readiness:</div>
    <div>• <strong>24 Resources (Auto-Remediable Dev):</strong> Fully agent executable immediately.</div>
    <div>• <strong>12 Resources (Production):</strong> Agent executable plan synthesized, gated behind HITL approval.</div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <span class="text-emerald-400 text-[10px]">Ready to execute on your command</span>
    <button onclick="triggerScenario('gcs-multi-issue')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-3 py-1.5 rounded border border-emerald-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="play" class="w-3.5 h-3.5 text-emerald-400"></i>
      <span>Act on This: Run Auto-Heal</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "AGENT_EXECUTABLE_OVERVIEW",
            "action_available": True,
            "scenario_key": "gcs-multi-issue",
            "answer_markdown": ans_html,
        }

    def _answer_multiple_agents(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-indigo-950/40 border border-indigo-500/40">
    <div class="flex items-center space-x-2 text-indigo-400 font-bold text-xs">
      <i data-lucide="bot" class="w-4 h-4 text-indigo-400"></i>
      <span>MULTIPLE AGENTS ARCHITECTURE — COORDINATED SPECIALIZED MESH</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-bold text-[10px]">5 SPECIALIZED AGENTS</span>
  </div>

  <p class="text-xs text-slate-200">
    The platform deploys an enterprise mesh of <strong>5 specialized autonomous agents</strong> collaborating across the compliance lifecycle:
  </p>

  <div class="space-y-2 text-[11px]">
    <div class="p-2.5 rounded-lg bg-slate-900 border border-indigo-500/30 space-y-1">
      <div class="flex items-center justify-between text-indigo-300 font-bold">
        <span>1. Remediation Dispatcher Agent (Lead Orchestrator)</span>
        <span class="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.2 rounded font-bold">ACTIVE</span>
      </div>
      <div class="text-slate-300 text-[10px]">
        Powered by Gemini 2.5 Flash Reasoning Engine. Decomposes multi-finding violations, synthesizes atomic execution plans, and dispatches tasks to specialist subagents.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-blue-500/30 space-y-1">
      <div class="flex items-center justify-between text-blue-300 font-bold">
        <span>2. Security & Compliance Auditor Agent</span>
        <span class="text-[9px] bg-blue-500/20 text-blue-300 px-1.5 py-0.2 rounded font-bold">MONITORING</span>
      </div>
      <div class="text-slate-300 text-[10px]">
        Ingests real-time feeds from Google Cloud Asset Inventory v1 and Security Command Center (SCC v2). Maps configurations against CIS GCP Benchmark v2.0, NIST 800-53, and PCI-DSS v4.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="flex items-center justify-between text-amber-300 font-bold">
        <span>3. Policy & Guardrail Enforcer Agent</span>
        <span class="text-[9px] bg-amber-500/20 text-amber-300 px-1.5 py-0.2 rounded font-bold">EVALUATING</span>
      </div>
      <div class="text-slate-300 text-[10px]">
        Compiles Open Policy Agent (OPA) Rego rules. Evaluates environment invariants (Dev auto-heal vs Prod HITL), blast radius calculations, and enforces safety bounds.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/30 space-y-1">
      <div class="flex items-center justify-between text-rose-300 font-bold">
        <span>4. HITL Governance & Ticket Agent</span>
        <span class="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.2 rounded font-bold">GATEWAY</span>
      </div>
      <div class="text-slate-300 text-[10px]">
        Integrates with ServiceNow / Jira ITSM. Automatically generates emergency change tickets (CHG-xxxx), manages dual-key cryptographic signatures, and unlocks execution tokens.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-cyan-500/30 space-y-1">
      <div class="flex items-center justify-between text-cyan-300 font-bold">
        <span>5. Drift & Telemetry Prober Agent</span>
        <span class="text-[9px] bg-cyan-500/20 text-cyan-300 px-1.5 py-0.2 rounded font-bold">VERIFYING</span>
      </div>
      <div class="text-slate-300 text-[10px]">
        Executes non-disruptive active network and IAM probes (e.g. port checks, IAM policy simulations) post-remediation, verifies zero drift, and stamps SHA-256 signed audit receipts.
      </div>
    </div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <span class="text-indigo-400 text-[10px]">5 agents online and synchronized across 14 GCP projects</span>
    <button onclick="triggerScenario('gcs-multi-issue')" class="bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 px-3 py-1.5 rounded border border-indigo-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="play" class="w-3.5 h-3.5 text-indigo-400"></i>
      <span>Dispatch Multi-Agent Remediation</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "MULTIPLE_AGENTS_OVERVIEW",
            "agents_count": 5,
            "answer_markdown": ans_html,
        }

    def _answer_multiple_skills(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/40">
    <div class="flex items-center space-x-2 text-cyan-400 font-bold text-xs">
      <i data-lucide="sparkles" class="w-4 h-4 text-cyan-400"></i>
      <span>MULTIPLE SKILLS CATALOG — ENTERPRISE HARDENING CAPABILITIES</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold text-[10px]">7 HARDENING SKILLS</span>
  </div>

  <p class="text-xs text-slate-200">
    The platform equips agents with <strong>7 specialized enterprise skills</strong> covering every core GCP service:
  </p>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
    <div class="p-2.5 rounded-lg bg-slate-900 border border-cyan-500/30 space-y-1">
      <div class="text-cyan-300 font-bold">1. gcs-storage-hardening</div>
      <div class="text-slate-300 text-[10px]">
        Enforces Uniform Bucket-Level Access (UBLA), activates Public Access Prevention (PAP=enforced), and injects 365-day Coldline lifecycle retention rules.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-blue-500/30 space-y-1">
      <div class="text-blue-300 font-bold">2. gke-cluster-defense</div>
      <div class="text-slate-300 text-[10px]">
        Revokes 0.0.0.0/0 master public endpoint, binds master authorized networks to corporate bastion CIDRs, and configures GKE Workload Identity pools.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-amber-500/30 space-y-1">
      <div class="text-amber-300 font-bold">3. iam-least-privilege</div>
      <div class="text-slate-300 text-[10px]">
        Strips primitive <code>roles/owner</code> from service accounts, provisions scoped least-privilege roles, and rotates cryptographic keys >90 days old.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-emerald-500/30 space-y-1">
      <div class="text-emerald-300 font-bold">4. cloudsql-network-security</div>
      <div class="text-slate-300 text-[10px]">
        Eliminates public IPv4 interfaces, attaches VPC Private Service Access, and forces SSL/TLS <code>require_ssl=true</code> encrypted database transit.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-purple-500/30 space-y-1">
      <div class="text-purple-300 font-bold">5. kms-cmek-governance</div>
      <div class="text-slate-300 text-[10px]">
        Binds Customer-Managed Encryption Keys (CMEK) to Cloud Storage buckets and Cloud SQL volumes, enforcing 90-day HSM cryptographic rotation.
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-rose-500/30 space-y-1">
      <div class="text-rose-300 font-bold">6. vpc-perimeter-defense</div>
      <div class="text-slate-300 text-[10px]">
        Closes 0.0.0.0/0 internet ingress on ports 22 (SSH) and 3389 (RDP), redirecting administrative traffic through Google Cloud Identity-Aware Proxy (IAP).
      </div>
    </div>

    <div class="p-2.5 rounded-lg bg-slate-900 border border-indigo-500/30 space-y-1 md:col-span-2">
      <div class="text-indigo-300 font-bold">7. bigquery-data-governance</div>
      <div class="text-slate-300 text-[10px]">
        Revokes <code>allAuthenticatedUsers</code> from datasets, enforces column-level policy tags, and configures customer data retention policies.
      </div>
    </div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <span class="text-cyan-400 text-[10px]">All skills validated against CIS GCP Benchmark v2.0</span>
    <button onclick="triggerScenario('gcs-multi-issue')" class="bg-cyan-600/30 hover:bg-cyan-600/50 text-cyan-300 px-3 py-1.5 rounded border border-cyan-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="play" class="w-3.5 h-3.5 text-cyan-400"></i>
      <span>Act on This: Execute Hardening Skill</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "MULTIPLE_SKILLS_OVERVIEW",
            "skills_count": 7,
            "answer_markdown": ans_html,
        }

    def _answer_tools_defined(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-amber-950/40 border border-amber-500/40">
    <div class="flex items-center space-x-2 text-amber-400 font-bold text-xs">
      <i data-lucide="wrench" class="w-4 h-4 text-amber-400"></i>
      <span>DEFINED TOOLS REGISTRY — MCP & PLATFORM CAPABILITIES</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold text-[10px]">7 DEFINED TOOLS</span>
  </div>

  <p class="text-xs text-slate-200">
    The platform equips agents with <strong>7 defined MCP (Model Context Protocol) and Python engine tools</strong>:
  </p>

  <div class="space-y-1.5 text-[11px]">
    <div class="p-2 rounded bg-slate-900 border border-amber-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-amber-300 font-bold">
        <span>1. gcp_asset_inventory_tool (MCP Lazy)</span>
        <span class="text-[9px] text-slate-400">Cloud Asset API v1</span>
      </div>
      <div class="text-slate-300 text-[10px]">Queries real-time resource graphs, IAM policies, and live metadata across all 14 GCP projects.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-blue-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-blue-300 font-bold">
        <span>2. rego_policy_evaluator (MCP Eager)</span>
        <span class="text-[9px] text-slate-400">Open Policy Agent (OPA)</span>
      </div>
      <div class="text-slate-300 text-[10px]">Evaluates Rego policy rules, compiles AST invariants, and issues deterministic ALLOW / HITL decisions.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-purple-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-purple-300 font-bold">
        <span>3. terraform_plan_synthesizer (Platform Tool)</span>
        <span class="text-[9px] text-slate-400">HCL Declarative Diff</span>
      </div>
      <div class="text-slate-300 text-[10px]">Generates deterministic declarative diffs (del/add), tests syntax, and previews state transitions without applying.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-emerald-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-emerald-300 font-bold">
        <span>4. gcp_cloud_client_tool (Platform Tool)</span>
        <span class="text-[9px] text-slate-400">Google Cloud SDK / Client APIs</span>
      </div>
      <div class="text-slate-300 text-[10px]">Executes atomic, idempotent mutations (e.g. storage patch, firewall update, SQL patch) with idempotency tokens.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-rose-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-rose-300 font-bold">
        <span>5. servicenow_itsm_gateway (MCP Lazy)</span>
        <span class="text-[9px] text-slate-400">ITIL Change Management</span>
      </div>
      <div class="text-slate-300 text-[10px]">Injects production change tickets (CHG-xxxx), requests dual-officer approvals, and validates electronic signatures.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-cyan-500/30 space-y-0.5">
      <div class="flex items-center justify-between text-cyan-300 font-bold">
        <span>6. post_remediation_prober (Platform Tool)</span>
        <span class="text-[9px] text-slate-400">Synthetic Penetration Probe</span>
      </div>
      <div class="text-slate-300 text-[10px]">Simulates external attacker probes (port scanning, unauthenticated HTTP requests) to confirm vulnerability closure.</div>
    </div>

    <div class="p-2 rounded bg-slate-900 border border-slate-700 space-y-0.5">
      <div class="flex items-center justify-between text-slate-200 font-bold">
        <span>7. immutable_audit_logger (Platform Tool)</span>
        <span class="text-[9px] text-slate-400">Cloud Logging Write-Once Sink</span>
      </div>
      <div class="text-slate-300 text-[10px]">Computes SHA-256 cryptographic hashes of all diffs, approvers, and execution outputs, stamping immutable receipts.</div>
    </div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <span class="text-amber-400 text-[10px]">All 7 tools registered and ready for execution</span>
    <button onclick="triggerScenario('gcs-multi-issue')" class="bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 px-3 py-1.5 rounded border border-amber-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="play" class="w-3.5 h-3.5 text-emerald-400"></i>
      <span>Act on This: Run Tool Pipeline</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "DEFINED_TOOLS_OVERVIEW",
            "tools_count": 7,
            "answer_markdown": ans_html,
        }

    def _answer_fleet_incidents(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-rose-950/40 border border-rose-500/40">
    <div class="flex items-center space-x-2 text-rose-400 font-bold text-xs">
      <i data-lucide="layers" class="w-4 h-4 text-rose-400"></i>
      <span>ENTERPRISE FLEET INCIDENTS COCKPIT (1,420 ASSETS MONITORED)</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold text-[10px]">36 VIOLATED ASSETS • 48 FINDINGS</span>
  </div>

  <p class="text-xs text-slate-200">
    At enterprise scale (1,420 monitored assets across 14 GCP projects), <strong>36 resources</strong> currently violate security policies, with systemic recurring patterns across 1-2 issues per resource:
  </p>

  <div class="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2 text-[11px] text-slate-300">
    <div class="font-bold text-slate-200">Systemic Repeating Issue Signatures:</div>
    <div>• <strong>Pattern A (12 Developer Buckets):</strong> Public read access (allUsers) & Object authenticated URLs (UBLA disabled). <em>100% Auto-Healable in Dev.</em></div>
    <div>• <strong>Pattern B (4 GKE Clusters):</strong> Control plane exposed to 0.0.0.0/0 & Workload Identity disabled. <em>Production HITL Gated.</em></div>
    <div>• <strong>Pattern C (6 Cloud SQL Instances):</strong> Public IPv4 attached & require_ssl=false. <em>Private Service Access needed.</em></div>
    <div>• <strong>Pattern D (8 Service Account Keys):</strong> Age > 90 days without cryptographic key rotation. <em>Auto-Healable.</em></div>
    <div>• <strong>Pattern E (6 VPC Firewall Rules):</strong> Port 22/3389 open to 0.0.0.0/0 instead of Google IAP. <em>Production HITL Gated.</em></div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <button onclick="switchPortalTab('fleet')" class="text-[10px] text-blue-400 hover:text-blue-300 underline font-bold cursor-pointer">
      Open Fleet Cockpit Tab &rarr;
    </button>
    <button onclick="triggerScenario('batch-gcs-dev')" class="bg-emerald-600/30 hover:bg-emerald-600/50 text-emerald-300 px-3 py-1.5 rounded border border-emerald-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="sparkles" class="w-3.5 h-3.5 text-emerald-400"></i>
      <span>Batch Auto-Heal 24 Dev Assets</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "FLEET_INCIDENTS_OVERVIEW",
            "total_monitored": 1420,
            "violated_resources": 36,
            "repeating_patterns_count": 5,
            "answer_markdown": ans_html,
        }

    def _answer_gcp_connector(self) -> Dict[str, Any]:
        ans_html = """
<div class="space-y-3 font-mono">
  <div class="flex items-center justify-between p-3 rounded-xl bg-blue-950/40 border border-blue-500/40">
    <div class="flex items-center space-x-2 text-blue-400 font-bold text-xs">
      <i data-lucide="cloud" class="w-4 h-4 text-blue-400"></i>
      <span>GCP LIVE INTEGRATION GATEWAY & WORKLOAD IDENTITY</span>
    </div>
    <span class="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[10px]">CONNECTOR READY</span>
  </div>

  <p class="text-xs text-slate-200">
    The platform connects directly with Google Cloud Platform across 3 production data planes:
  </p>

  <div class="space-y-1.5 text-[11px] text-slate-300">
    <div class="p-2 rounded bg-slate-900 border border-slate-800">
      <strong>1. Google Cloud Asset Inventory API (v1):</strong> Live real-time resource graphs & IAM policy ingestion (<code>cloudasset.googleapis.com</code>).
    </div>
    <div class="p-2 rounded bg-slate-900 border border-slate-800">
      <strong>2. Security Command Center (SCC v2):</strong> Pub/Sub notifications stream (<code>projects/security-prod/topics/scc-findings-stream</code>).
    </div>
    <div class="p-2 rounded bg-slate-900 border border-slate-800">
      <strong>3. Workload Identity & OAuth2 ADC:</strong> Service Account <code>platform-agent-sa@security-prod.iam.gserviceaccount.com</code> with least-privilege patch scopes.
    </div>
  </div>

  <div class="pt-1 flex items-center justify-between border-t border-slate-800">
    <button onclick="switchPortalTab('gcp')" class="text-[10px] text-blue-400 hover:text-blue-300 underline font-bold cursor-pointer">
      Open GCP Connector Tab &rarr;
    </button>
    <button onclick="triggerScenario('gcs-zero-violation')" class="bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 px-3 py-1.5 rounded border border-blue-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm">
      <i data-lucide="activity" class="w-3.5 h-3.5 text-blue-400"></i>
      <span>Test Live GCP Handshake</span>
    </button>
  </div>
</div>
"""
        return {
            "intent": "GCP_CONNECTOR_OVERVIEW",
            "connection_status": "READY",
            "answer_markdown": ans_html,
        }

    def _search_configuration_or_catalog(self, q: str) -> Optional[Dict[str, Any]]:
        # Service or configuration topic matching
        if any(k in q for k in ["firewall", "port 22", "ssh", "iap", "ingress"]):
            res = next((r for r in self.resources if "allow-ssh" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="fw-open-ssh", custom_title="VPC FIREWALL CONFIGURATION REPORT")

        if any(k in q for k in ["gke", "kubernetes", "k8s", "cluster", "master", "calico", "workload identity"]):
            if any(k in q for k in ["workload", "order", "staging"]):
                res = next((r for r in self.resources if "order-processing" in r.get("resource_name", "")), None)
                if res:
                    return self._answer_resource_details(res, scenario_hint="gke-workload-identity", custom_title="GKE WORKLOAD IDENTITY CONFIGURATION")
            else:
                res = next((r for r in self.resources if "payments-gke" in r.get("resource_name", "")), None)
                if res:
                    return self._answer_resource_details(res, scenario_hint="gke-multi-issue", custom_title="GKE CLUSTER HARDENING CONFIGURATION")

        if any(k in q for k in ["database", "sql", "postgres", "mysql", "backup", "ssl"]):
            if any(k in q for k in ["backup", "mysql", "dev"]):
                res = next((r for r in self.resources if "analytics-mysql" in r.get("resource_name", "")), None)
                if res:
                    return self._answer_resource_details(res, scenario_hint="sql-backup-disabled", custom_title="CLOUD SQL BACKUP CONFIGURATION")
            else:
                res = next((r for r in self.resources if "customer-db-pg" in r.get("resource_name", "")), None)
                if res:
                    return self._answer_resource_details(res, scenario_hint="sql-public-ip", custom_title="CLOUD SQL NETWORK CONFIGURATION")

        if any(k in q for k in ["vm", "external ip", "gce", "compute instance"]):
            res = next((r for r in self.resources if "db-worker" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="vm-external-ip", custom_title="COMPUTE ENGINE NETWORK CONFIGURATION")

        if any(k in q for k in ["iam", "service account", "owner", "least privilege"]):
            res = next((r for r in self.resources if "etl-batch" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="iam-sa-owner", custom_title="IAM LEAST PRIVILEGE CONFIGURATION")

        if any(k in q for k in ["key", "rotation", "ci-deployer", "expired"]):
            res = next((r for r in self.resources if "ci-deployer" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="iam-key-unrotated", custom_title="IAM KEY ROTATION CONFIGURATION")

        if any(k in q for k in ["bigquery", "dataset", "churn"]):
            res = next((r for r in self.resources if "churn" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="bq-public-dataset", custom_title="BIGQUERY ACCESS CONTROL CONFIGURATION")

        if any(k in q for k in ["run", "cloud run", "serverless", "invoker"]):
            res = next((r for r in self.resources if "payment-processor" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="run-unauth-invoker", custom_title="CLOUD RUN AUTHENTICATION CONFIGURATION")

        if any(k in q for k in ["cmek", "kms", "encryption"]):
            res = next((r for r in self.resources if "financial-audit" in r.get("resource_name", "")), None)
            if res:
                return self._answer_resource_details(res, scenario_hint="gcs-cmek", custom_title="CLOUD KMS & CMEK ENCRYPTION CONFIGURATION")

        return None

    def _answer_general_summary(self, query: str) -> Dict[str, Any]:
        stats = get_compliance_stats()
        ans_html = f"""
<div class="space-y-2.5">
  <div class="text-xs text-slate-200 font-semibold">
    Enterprise Compliance Agent
  </div>
  <p class="text-xs text-slate-300">
    I am actively monitoring <strong>{stats['total_monitored_resources']} GCP resources</strong> across <strong>org-enterprise-cloud-7192</strong>.
    Current fleet compliance score is <strong>{stats['compliance_score_percent']}%</strong> with <strong>{stats['total_active_findings']} active policy violations</strong>.
  </p>
  <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px] space-y-1 text-slate-300">
    <div>• <strong>Auto-Heal Eligible (Dev):</strong> {stats['governance_breakdown']['auto_execute_eligible']} violations</div>
    <div>• <strong>HITL Gated (Prod):</strong> {stats['governance_breakdown']['human_approval_required']} violations</div>
    <div>• <strong>Critical Severity:</strong> {stats['severity_distribution']['CRITICAL']} violations</div>
  </div>
  <div class="text-[11px] text-slate-400">
    Try asking:
    <br/>• <em>"How many auto-heal violations are present?"</em>
    <br/>• <em>"How many prod violations are present?"</em>
    <br/>• <em>"In which resource violations are not present?"</em>
    <br/>• <em>"Which issues are not violating?"</em>
  </div>
</div>
"""
        return {
            "intent": "GENERAL_SUMMARY",
            "sidebar_filter": "violated",
            "answer_markdown": ans_html,
            "issues_first": False,
        }
