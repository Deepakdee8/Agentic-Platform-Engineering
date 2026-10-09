"""
GCP Agentic Platform Backend API.
Serves the full Compliance Engine, Resource Catalog, and Live Remediation Pipelines via FastAPI.
Includes static hosting for index.html.
"""
import os
import sys
import uuid
import time
from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure workspace is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from data.loader import (
    load_raw_findings,
    get_finding_by_key,
    get_all_findings,
    load_resources,
    load_policies,
    load_remediations,
    get_ranked_findings,
    get_compliance_stats,
)
from src.compliance_engine.comprehensive_orchestrator import ComprehensiveComplianceOrchestrator
from src.compliance_engine.models import ActionDecision, PlanStatus

app = FastAPI(
    title="GCP Agentic Platform Control Plane API",
    description="Backend API powering the autonomous live self-healing and Human-in-the-Loop engineering copilot.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from src.compliance_engine.agent.compliance_copilot_agent import ComplianceCopilotAgent

# Initialize master orchestrator singleton
orchestrator = ComprehensiveComplianceOrchestrator()

# Initialize AI Copilot Agent
agent = ComplianceCopilotAgent()

# Store active pending tickets in memory
pending_tickets: Dict[str, Dict[str, Any]] = {}


class PlanRequest(BaseModel):
    scenario_key: str
    simulate: bool = True


class ApprovalRequest(BaseModel):
    ticket_id: str
    decision: str  # "APPROVE" or "REJECT"
    approver: Optional[str] = "Platform-Engineer@corp.internal"
    reason: Optional[str] = "Approved via Agentic Console"


class AgentQueryRequest(BaseModel):
    prompt: str


@app.post("/api/agent/query")
def query_agent(req: AgentQueryRequest):
    """
    Submits a conversational query to the Compliance Copilot Agent.
    Returns authoritative analysis, filtered issues, and UI sidebar synchronization commands.
    """
    return agent.process_query(req.prompt)


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "orchestrator": "ComprehensiveComplianceOrchestrator",
        "model": "Gemini 2.5 Flash / Vertex AI Reasoning Engine",
        "tools_registered": len(orchestrator.tool_registry),
        "timestamp": time.time(),
    }


@app.get("/api/resources")
def get_resources():
    """Returns all GCP resources and findings from data/findings.json."""
    return load_raw_findings()


@app.get("/api/resources/{scenario_key}")
def get_resource_detail(scenario_key: str):
    """Returns single resource finding specification."""
    findings = load_raw_findings()
    for f in findings:
        if f.get("scenario_key") == scenario_key or f.get("finding_id") == scenario_key:
            return f
    raise HTTPException(status_code=404, detail="Resource scenario not found")


@app.get("/api/inventory/resources")
def get_resource_inventory():
    """Returns the complete enterprise GCP resource catalog across all projects."""
    return load_resources()


@app.get("/api/policies")
def get_compliance_policies():
    """Returns the enterprise compliance policy library (CIS, NIST, PCI-DSS, SOC 2)."""
    return load_policies()


@app.get("/api/findings")
def get_findings_ranked():
    """Returns all compliance findings ranked strictly by Risk Score descending."""
    return get_ranked_findings()


@app.get("/api/remediations")
def get_remediations_catalog():
    """Returns the enterprise remediation playbooks, tools, and runbooks."""
    return load_remediations()


@app.get("/api/compliance/summary")
def get_compliance_summary():
    """Returns aggregated fleet compliance posture metrics and KPIs."""
    return get_compliance_stats()


@app.post("/api/remediate/plan")
def create_remediation_plan(req: PlanRequest):
    """
    Step 1 & 2: Analyzes finding, runs Policy & Risk Engine, prepares plan, diffs, and evaluates approval gate.
    If Non-Prod: Automatically executes!
    If Production: Creates Approval Ticket and holds execution for human decision.
    """
    finding = get_finding_by_key(req.scenario_key)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Scenario key '{req.scenario_key}' not found.")

    # 1. AI Planning
    plan = orchestrator.planner.plan_remediation(finding)

    # 2. Policy Governance
    policy = orchestrator.policy_engine.evaluate(finding, plan.risk_assessment)

    # Format diffs
    diff_dicts = []
    for d in plan.diffs:
        diff_dicts.append({
            "parameter": d.parameter,
            "current_value": d.current_value,
            "proposed_value": d.proposed_value,
            "description": d.description,
        })

    # Prepare response payload
    response_data = {
        "scenario_key": req.scenario_key,
        "finding_id": finding.finding_id,
        "service": finding.metadata.get("service", "GCP Service"),
        "resource_name": finding.resource.resource_name,
        "resource_id": finding.resource.resource_id,
        "environment": finding.resource.environment.value,
        "compliance_standard": finding.compliance_standard,
        "risk": {
            "score": plan.risk_assessment.score,
            "level": plan.risk_assessment.risk_level.value,
            "blast_radius": {
                "affected_services": plan.risk_assessment.blast_radius.affected_services_count,
                "data_loss_risk": plan.risk_assessment.blast_radius.data_loss_risk,
            },
        },
        "plan": {
            "plan_id": plan.plan_id,
            "action_title": plan.action_title,
            "rationale": plan.rationale,
            "tool_name": plan.tool_name,
            "diffs": diff_dicts,
            "rollback_strategy": plan.rollback_procedure.strategy_type,
            "recovery_time_seconds": plan.rollback_procedure.estimated_recovery_time_seconds,
        },
        "policy": {
            "governing_policy": policy.governing_policy,
            "decision": policy.decision.value,
            "rationale": policy.rationale,
            "requires_hitl": policy.decision == ActionDecision.REQUIRE_HUMAN_APPROVAL,
        },
    }

    # Case A: Production requires Human-in-the-Loop
    if policy.decision == ActionDecision.REQUIRE_HUMAN_APPROVAL:
        ticket = orchestrator.approval_engine.create_request(plan)
        pending_tickets[ticket.ticket_id] = {
            "finding": finding,
            "plan": plan,
            "policy": policy,
            "ticket": ticket,
        }
        response_data["status"] = "PENDING_APPROVAL"
        response_data["ticket_id"] = ticket.ticket_id
        return response_data

    # Case B: Non-Production Auto-Heal (Execute deterministically!)
    tool = orchestrator.tool_registry.get(plan.tool_name)
    if not tool:
        raise HTTPException(status_code=500, detail=f"Tool '{plan.tool_name}' not registered.")

    exec_success, exec_msg, exec_metadata = tool.execute(plan.tool_parameters, simulate=req.simulate)
    val_success, val_msg = tool.validate_compliance(finding.resource.resource_id, {})

    audit = orchestrator.audit_vault.log_remediation_event(
        finding=finding,
        plan=plan,
        policy=policy,
        approval_status="AUTO_APPROVED",
        approved_by="System-Autonomous-Policy-Engine",
        execution_status="SUCCESS" if exec_success else "FAILED",
        validation_status="VERIFIED" if val_success else "UNVERIFIED",
        proof_evidence=exec_metadata,
    )

    response_data["status"] = "RESOLVED"
    response_data["execution"] = {
        "success": exec_success,
        "message": exec_msg,
        "metadata": exec_metadata,
    }
    response_data["verification"] = {
        "success": val_success,
        "message": val_msg,
    }
    response_data["audit"] = {
        "audit_id": audit.audit_id,
        "checksum_sha256": audit.checksum_sha256,
                "timestamp": str(audit.timestamp),
    }
    return response_data


@app.post("/api/remediate/approve")
def handle_approval(req: ApprovalRequest):
    """
    Step 3: Human-in-the-Loop gate execution.
    Executes or rejects the pending remediation ticket.
    """
    item = pending_tickets.get(req.ticket_id)
    if not item:
        raise HTTPException(status_code=404, detail=f"Pending ticket '{req.ticket_id}' not found or already processed.")

    finding = item["finding"]
    plan = item["plan"]
    policy = item["policy"]
    ticket = item["ticket"]

    if req.decision.upper() == "APPROVE":
        orchestrator.approval_engine.approve(req.ticket_id, approver=req.approver or "Platform-Engineer")
        plan.status = PlanStatus.APPROVED

        # Execute tool
        tool = orchestrator.tool_registry.get(plan.tool_name)
        if not tool:
            raise HTTPException(status_code=500, detail=f"Tool '{plan.tool_name}' not in registry.")

        exec_success, exec_msg, exec_metadata = tool.execute(plan.tool_parameters, simulate=True)
        val_success, val_msg = tool.validate_compliance(finding.resource.resource_id, {})

        audit = orchestrator.audit_vault.log_remediation_event(
            finding=finding,
            plan=plan,
            policy=policy,
            approval_status="MANUALLY_APPROVED",
            approved_by=req.approver,
            execution_status="SUCCESS" if exec_success else "FAILED",
            validation_status="VERIFIED" if val_success else "UNVERIFIED",
            proof_evidence=exec_metadata,
        )

        del pending_tickets[req.ticket_id]
        return {
            "status": "APPROVED_AND_EXECUTED",
            "ticket_id": req.ticket_id,
            "execution": {"success": exec_success, "message": exec_msg, "metadata": exec_metadata},
            "verification": {"success": val_success, "message": val_msg},
            "audit": {
                "audit_id": audit.audit_id,
                "checksum_sha256": audit.checksum_sha256,
                "timestamp": str(audit.timestamp),
            },
        }
    else:
        orchestrator.approval_engine.reject(req.ticket_id, approver=req.approver or "Platform-Engineer", reason=req.reason or "Rejected")
        plan.status = PlanStatus.REJECTED

        audit = orchestrator.audit_vault.log_remediation_event(
            finding=finding,
            plan=plan,
            policy=policy,
            approval_status="REJECTED",
            approved_by=req.approver,
            execution_status="CANCELLED",
            validation_status="SKIPPED",
            proof_evidence={"rejection_reason": req.reason},
        )

        del pending_tickets[req.ticket_id]
        return {
            "status": "REJECTED",
            "ticket_id": req.ticket_id,
            "message": "Production change aborted. Escalated to Security Operations Center.",
            "audit": {
                "audit_id": audit.audit_id,
                "checksum_sha256": audit.checksum_sha256,
                "timestamp": str(audit.timestamp),
            },
        }


@app.get("/")
def serve_index():
    """Serves the main dashboard application."""
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "index.html not found"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8501, reload=True)
