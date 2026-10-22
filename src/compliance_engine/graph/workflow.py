"""
LangGraph Multi-Agent Workflow for Automated Environment Compliance Remediation.
Constructs and compiles the StateGraph with checkpointer and conditional routing.
"""
from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from src.compliance_engine.graph.state import ComplianceGraphState
from src.compliance_engine.graph.nodes import (
    node_triage,
    node_risk_assessment,
    node_plan_remediation,
    node_evaluate_policy,
    node_hitl_approval_gate,
    node_execute_remediation,
    node_verify_and_audit,
    node_abort_and_escalate,
)


def route_after_policy(state: ComplianceGraphState) -> str:
    """
    Routes based on policy evaluation and existing approval decision:
    - If auto-approved: routes to 'executor'
    - If requires human approval:
        - If already APPROVED: routes to 'executor'
        - If REJECTED: routes to 'abort'
        - Otherwise: routes to 'approval_gate' (waiting for human review)
    """
    policy = state.get("policy", {})
    if not policy.get("requires_hitl", False):
        return "executor"

    decision = state.get("approval_decision", "PENDING")
    if decision == "APPROVE":
        return "executor"
    elif decision == "REJECT":
        return "abort"

    return "approval_gate"


def route_after_approval(state: ComplianceGraphState) -> str:
    """
    Routes based on human reviewer decision:
    - If 'APPROVE': routes to 'executor'
    - If 'REJECT': routes to 'abort'
    - Else: halts at 'end_pending' (waiting for human review)
    """
    decision = state.get("approval_decision", "PENDING")
    if decision == "APPROVE":
        return "executor"
    elif decision == "REJECT":
        return "abort"
    return "end_pending"


def build_compliance_graph(checkpointer: Optional[MemorySaver] = None):
    """
    Assembles the StateGraph for Capability 2.
    """
    workflow = StateGraph(ComplianceGraphState)

    # Register Nodes
    workflow.add_node("triage", node_triage)
    workflow.add_node("risk", node_risk_assessment)
    workflow.add_node("planner", node_plan_remediation)
    workflow.add_node("policy", node_evaluate_policy)
    workflow.add_node("approval_gate", node_hitl_approval_gate)
    workflow.add_node("executor", node_execute_remediation)
    workflow.add_node("verifier", node_verify_and_audit)
    workflow.add_node("abort", node_abort_and_escalate)

    # Helper node for pending state pause
    def node_hold_pending(state: ComplianceGraphState) -> Dict[str, Any]:
        return {"status": "WAITING_APPROVAL"}
    workflow.add_node("end_pending", node_hold_pending)

    # Define Linear Edges
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "risk")
    workflow.add_edge("risk", "planner")
    workflow.add_edge("planner", "policy")

    # Conditional Branching
    workflow.add_conditional_edges(
        "policy",
        route_after_policy,
        {
            "approval_gate": "approval_gate",
            "executor": "executor",
            "abort": "abort",
        },
    )

    workflow.add_conditional_edges(
        "approval_gate",
        route_after_approval,
        {
            "executor": "executor",
            "abort": "abort",
            "end_pending": "end_pending",
        },
    )

    workflow.add_edge("executor", "verifier")
    workflow.add_edge("verifier", END)
    workflow.add_edge("abort", END)
    workflow.add_edge("end_pending", END)

    # Compile with MemorySaver checkpointer
    if checkpointer is None:
        checkpointer = MemorySaver()

    app = workflow.compile(checkpointer=checkpointer)
    return app


# Singleton graph instance with active in-memory checkpointer
memory_checkpointer = MemorySaver()
compliance_graph = build_compliance_graph(memory_checkpointer)


class ComplianceWorkflowRunner:
    """
    High-level controller for launching, streaming, and resuming LangGraph remediation runs.
    """

    def __init__(self):
        self.graph = compliance_graph

    def start_remediation(self, finding: Dict[str, Any], thread_id: str) -> ComplianceGraphState:
        """
        Runs the multi-agent graph from START.
        If non-prod: Runs to completion (auto-heal).
        If prod: Runs up to the approval gate and pauses at WAITING_APPROVAL.
        """
        initial_state: ComplianceGraphState = {
            "thread_id": thread_id,
            "scenario_key": finding.get("scenario_key", finding.get("finding_id", "unknown")),
            "finding": finding,
            "finding_id": finding.get("finding_id", "FINDING-UNKNOWN"),
            "resource_id": finding.get("resource_id", "gcp-asset"),
            "resource_name": finding.get("resource_name", "gcp-asset"),
            "service": finding.get("service", "GCP Service"),
            "environment": finding.get("environment", "production"),
            "current_step": "START",
            "status": "INGESTED",
            "messages": [],
        }

        config = {"configurable": {"thread_id": thread_id}}
        final_state = self.graph.invoke(initial_state, config=config)
        return final_state

    def resume_with_decision(
        self,
        thread_id: str,
        decision: str,  # "APPROVE" | "REJECT"
        approver: str = "Platform-Engineer@corp.internal",
        reason: Optional[str] = None,
    ) -> ComplianceGraphState:
        """
        Resumes the paused graph from the checkpoint with human reviewer authorization.
        """
        config = {"configurable": {"thread_id": thread_id}}
        current_state = self.graph.get_state(config)
        if not current_state or not current_state.values:
            raise ValueError(f"No checkpoint found for thread {thread_id}")

        resume_payload: Dict[str, Any] = {
            "approval_decision": decision.upper(),
            "approved_by": approver,
            "approval_reason": reason or f"Decided {decision} via Enterprise Platform Console",
        }

        # Update state and continue graph from approval_gate
        updated_state = self.graph.invoke(resume_payload, config=config)
        return updated_state

    def stream_remediation_events(self, finding: Dict[str, Any], thread_id: str):
        """
        Runs the StateGraph in stream mode and yields JSON events as each agent finishes.
        """
        initial_state: ComplianceGraphState = {
            "thread_id": thread_id,
            "scenario_key": finding.get("scenario_key", finding.get("finding_id", "unknown")),
            "finding": finding,
            "finding_id": finding.get("finding_id", "FINDING-UNKNOWN"),
            "resource_id": finding.get("resource_id", "gcp-asset"),
            "resource_name": finding.get("resource_name", "gcp-asset"),
            "service": finding.get("service", "GCP Service"),
            "environment": finding.get("environment", "production"),
            "current_step": "START",
            "status": "INGESTED",
            "messages": [],
        }

        config = {"configurable": {"thread_id": thread_id}}

        node_titles = {
            "triage": ("Triage & Classification Agent", "Classified finding and mapped security standards."),
            "risk": ("Blast Radius & Risk Assessment Agent", "Evaluated dependent services and risk level."),
            "planner": ("Remediation Planner Agent", "Synthesized declarative Terraform HCL mutation diff."),
            "policy": ("Policy & Governance Enforcer", "Evaluated enterprise security guardrails (POL-AUTO-001 / POL-PROD-002)."),
            "approval_gate": ("Human-in-the-Loop Checkpoint", "Paused execution waiting for Platform Engineer approval."),
            "end_pending": ("Approval Gate Holding State", "Workflow paused pending reviewer authorization."),
            "executor": ("Autonomous Execution Dispatcher", "Applied state mutation idempotently."),
            "verifier": ("Verification & Audit Agent", "Verified zero drift and committed SHA-256 audit record."),
            "abort": ("Escalation & Abort Node", "Production change safely aborted and escalated to SOC."),
        }

        yield {
            "event": "workflow_started",
            "thread_id": thread_id,
            "scenario_key": finding.get("scenario_key"),
            "resource_name": finding.get("resource_name"),
        }

        current_full_state = dict(initial_state)

        for chunk in self.graph.stream(initial_state, config=config, stream_mode="updates"):
            for node_name, node_update in chunk.items():
                current_full_state.update(node_update)
                title, desc = node_titles.get(node_name, (f"{node_name.capitalize()} Node", "Node executed"))

                detail = desc
                if node_name == "triage" and "triage" in node_update:
                    detail = f"Matched {node_update['triage'].get('compliance_standard', 'CIS GCP Benchmark')}: {node_update['triage'].get('description', '')}"
                elif node_name == "risk" and "risk" in node_update:
                    detail = f"Risk Score: {node_update['risk'].get('score')}/100 ({node_update['risk'].get('level')}). Affected: {node_update['risk'].get('affected_services')} services."
                elif node_name == "planner" and "plan" in node_update:
                    detail = f"Action: {node_update['plan'].get('action_title')}. Tool: {node_update['plan'].get('tool_name')}."
                elif node_name == "policy" and "policy" in node_update:
                    detail = f"Policy Decision: {node_update['policy'].get('decision')} under {node_update['policy'].get('governing_policy')}."
                elif node_name == "executor" and "execution" in node_update:
                    detail = node_update["execution"].get("message", "Mutation applied.")
                elif node_name == "verifier" and "verification" in node_update:
                    detail = node_update["verification"].get("message", "Verification passed.")

                yield {
                    "event": "node_complete",
                    "node": node_name,
                    "title": title,
                    "detail": detail,
                    "status": current_full_state.get("status", "RUNNING"),
                    "ticket_id": current_full_state.get("approval_ticket_id"),
                    "plan": current_full_state.get("plan"),
                    "risk": current_full_state.get("risk"),
                    "policy": current_full_state.get("policy"),
                    "triage": current_full_state.get("triage"),
                    "execution": current_full_state.get("execution"),
                    "verification": current_full_state.get("verification"),
                    "audit": current_full_state.get("audit"),
                }

        yield {
            "event": "workflow_finished",
            "thread_id": thread_id,
            "status": current_full_state.get("status"),
            "ticket_id": current_full_state.get("approval_ticket_id"),
            "final_state": current_full_state,
        }
