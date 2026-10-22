"""
Gemini Reasoning Agent with Tool Calling & Grounding for GCP Platform Engineering.
Answers complex conversational questions by querying the fleet inventory, findings, and policies.
"""
import os
import json
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

from data.loader import (
    load_resources,
    load_raw_findings,
    load_policies,
    get_compliance_stats,
    get_finding_by_key,
    get_resource_by_id,
)
from src.compliance_engine.graph.agents import get_gemini_model, extract_text_content

load_dotenv()


# Tool functions available to the reasoning agent
def search_resources_tool(query: str, env: Optional[str] = None, service: Optional[str] = None) -> str:
    """Search monitored GCP resources by keyword, environment (production/development), or service."""
    resources = load_resources()
    q = query.lower()
    matches = []
    for r in resources:
        if env and r.get("environment", "").lower() != env.lower():
            continue
        if service and service.lower() not in r.get("resource_type", "").lower() and service.lower() not in r.get("service", "").lower():
            continue
        text = f"{r.get('resource_name', '')} {r.get('resource_id', '')} {r.get('resource_type', '')}".lower()
        if q in text or any(k in text for k in q.split()):
            matches.append({
                "resource_name": r.get("resource_name"),
                "resource_id": r.get("resource_id"),
                "environment": r.get("environment"),
                "service": r.get("service", r.get("resource_type")),
                "compliant": r.get("compliant", True),
                "active_issues_count": len(r.get("active_issues", [])),
                "active_issues": r.get("active_issues", []),
            })
    return json.dumps(matches[:8], indent=2)


def get_finding_details_tool(finding_id_or_resource: str) -> str:
    """Retrieve detailed compliance finding dossier including current state, risk score, and policy."""
    findings = load_raw_findings()
    term = finding_id_or_resource.lower()
    for f in findings:
        if term in f.get("finding_id", "").lower() or term in f.get("resource_name", "").lower() or term in f.get("scenario_key", "").lower():
            return json.dumps({
                "finding_id": f.get("finding_id"),
                "scenario_key": f.get("scenario_key"),
                "resource_name": f.get("resource_name"),
                "environment": f.get("environment"),
                "service": f.get("service"),
                "severity": f.get("severity"),
                "compliance_standard": f.get("compliance_standard"),
                "policy_id": f.get("policy_id"),
                "description": f.get("description"),
                "risk_score": f.get("risk_assessment", {}).get("score"),
                "risk_level": f.get("risk_assessment", {}).get("risk_level"),
                "current_state": f.get("current_state"),
            }, indent=2)
    return json.dumps({"error": f"Finding or resource matching '{finding_id_or_resource}' not found."})


def get_fleet_stats_tool() -> str:
    """Get aggregated fleet security metrics, monitored assets, and severity breakdown."""
    stats = get_compliance_stats()
    return json.dumps(stats, indent=2)


def get_policy_details_tool(policy_id_or_standard: str) -> str:
    """Retrieve enterprise security policy rules (CIS GCP Benchmark, NIST, POL-AUTO-001, POL-PROD-002)."""
    policies = load_policies()
    term = policy_id_or_standard.lower()
    matches = []
    for p in policies:
        text = f"{p.get('policy_id', '')} {p.get('title', '')} {p.get('standard', '')} {p.get('description', '')}".lower()
        if term in text:
            matches.append({
                "policy_id": p.get("policy_id"),
                "title": p.get("title"),
                "standard": p.get("standard"),
                "governance_mode": p.get("governance_mode"),
                "description": p.get("description"),
            })
    return json.dumps(matches[:5], indent=2)


class GeminiReasoningAgent:
    """
    Conversational Agent powered by Gemini 2.5 Flash.
    Executes reasoning with access to enterprise GCP fleet tools.
    """

    def __init__(self):
        self.model = get_gemini_model(temperature=0.2)

    def answer_query(self, user_prompt: str) -> Optional[Dict[str, Any]]:
        """
        Processes a prompt using Gemini. Returns structured answer dict or None if offline.
        """
        if not self.model:
            return None

        # Build tools catalog description
        fleet_summary = get_fleet_stats_tool()

        system_instruction = f"""
You are the Lead Autonomous Platform Engineering & Compliance Agent for an enterprise Google Cloud Platform.
You oversee 1,420 monitored cloud assets across 14 GCP projects in organization 'org-enterprise-cloud-7192'.

GOVERNANCE RULES:
1. You are the 'Autonomous Compliance Agent' or 'Platform Engineering Agent'.
2. When answering about non-compliant resources, explain:
   - Root cause and violation details
   - Governing compliance standard (e.g. CIS GCP Benchmark v2.0 or NIST)
   - Risk & blast radius
   - Policy gate: POL-AUTO-001 (Dev tier, pre-authorized auto-heal) vs POL-PROD-002 (Production tier, requires dual-officer HITL sign-off).
3. If an actionable finding is identified, provide an interactive button for the user:
   `<button onclick="triggerScenario('SCENARIO_KEY')" class="bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 px-3 py-1.5 rounded border border-blue-500/40 cursor-pointer font-bold text-xs flex items-center space-x-1.5 shadow-sm mt-2"><i data-lucide="zap" class="w-3.5 h-3.5 text-blue-400"></i><span>Act On This: Remediate</span></button>`
   (Replace SCENARIO_KEY with the finding scenario key, e.g., 'fw-open-ssh', 'gcs-multi-issue', 'sql-multi-issue', etc.)

FLEET CONTEXT OVERVIEW:
{fleet_summary}
"""
        from langchain_core.messages import SystemMessage, HumanMessage

        # Quick grounded lookup for context enhancement
        prompt_lower = user_prompt.lower()
        context_data = ""
        if any(k in prompt_lower for k in ["ssh", "firewall", "port 22"]):
            context_data += "\nFINDING DATA:\n" + get_finding_details_tool("fw-open-ssh")
        elif any(k in prompt_lower for k in ["bucket", "storage", "gcs"]):
            context_data += "\nFINDING DATA:\n" + get_finding_details_tool("gcs-multi-issue")
        elif any(k in prompt_lower for k in ["sql", "database", "postgres", "mysql"]):
            context_data += "\nFINDING DATA:\n" + get_finding_details_tool("customer-db-pg")
        elif any(k in prompt_lower for k in ["gke", "kubernetes", "k8s"]):
            context_data += "\nFINDING DATA:\n" + get_finding_details_tool("payments-gke")
        elif any(k in prompt_lower for k in ["iam", "service account", "owner"]):
            context_data += "\nFINDING DATA:\n" + get_finding_details_tool("etl-batch")
        elif any(k in prompt_lower for k in ["policy", "cis", "nist"]):
            context_data += "\nPOLICIES DATA:\n" + get_policy_details_tool(user_prompt)

        full_prompt = f"{user_prompt}\n\nRELEVANT TELEMETRY DOSSIER:{context_data}"

        try:
            response = self.model.invoke([
                SystemMessage(content=system_instruction),
                HumanMessage(content=full_prompt),
            ])
            text = extract_text_content(response.content).strip()
            active_model = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite").upper()

            # Format into rich HTML container for index.html UI
            formatted_html = f"""
<div class="space-y-3 font-mono text-xs">
  <div class="flex items-center justify-between p-2 rounded-lg bg-blue-950/40 border border-blue-500/40">
    <div class="flex items-center space-x-2 text-blue-400 font-bold text-xs">
      <i data-lucide="sparkles" class="w-4 h-4 text-blue-400"></i>
      <span>{active_model} — PLATFORM REASONING</span>
    </div>
    <span class="text-[9px] px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold">LIVE AGENT</span>
  </div>
  <div class="text-slate-200 leading-relaxed space-y-2">
    {text.replace(chr(10), '<br/>')}
  </div>
</div>
"""
            return {
                "intent": "GEMINI_REASONING",
                "sidebar_filter": "all",
                "answer_markdown": formatted_html,
                "issues_first": False,
            }
        except Exception as e:
            print(f"[GeminiReasoningAgent] Error: {e}")
            return None
