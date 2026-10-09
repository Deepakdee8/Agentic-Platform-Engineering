# GCP Agentic Platform — Automated Environment Compliance Remediation

> **Demo Storyline:** *"The 30-Second Self-Healing Cloud: Autonomous in Dev, Governed in Prod"*  
> **Reference Document:** [Agentic_GCP_Platform_Engineering_PRD.md](Agentic_GCP_Platform_Engineering_PRD.md) (Capability 2)

---

## 🌟 Overview

The **Automated Environment Compliance Remediation Agent** turns security alert fatigue into governed, autonomous cloud operations.

Instead of human engineers manually triaging hundreds of daily cloud compliance violations, this platform operates as a **closed-loop control system**:

$$\text{Detect (SCC)} \longrightarrow \text{Plan (AI)} \longrightarrow \text{Govern (Risk \& Policy)} \longrightarrow \text{Approve (HITL)} \longrightarrow \text{Execute} \longrightarrow \text{Validate} \longrightarrow \text{Audit}$$

---

## 🎭 The Two Demo Scenarios

1. **Act 1: Autonomous Self-Healing (Development)**
   * **Violation:** Cloud Storage bucket (`gs://retail-app-invoices-dev`) has `allUsers` IAM public access.
   * **Governance:** Evaluated as `MEDIUM` risk in `development`.
   * **Outcome:** Pre-authorized for autonomous execution. The agent strips the public binding, enforces Public Access Prevention, validates the state, and closes the ticket in seconds—**zero human clicks required**.

2. **Act 2: Human-in-the-Loop Shield (Production)**
   * **Violation:** Production firewall rule allows `0.0.0.0/0` on SSH port 22.
   * **Governance:** Evaluated as `HIGH / CRITICAL` risk in `production`.
   * **Outcome:** Autonomous mutation is **blocked**. The agent pauses, calculates blast radius, presents a technical diff and rollback plan, and prompts the platform engineer for approval (`y/n`). Once approved, it restricts ingress to the Google Cloud IAP tunnel range (`35.235.240.0/20`), validates the fix, and cryptographically logs the audit trail.

---

## 🚀 How to Run the Interactive Demo

### Prerequisites
* Python 3.9+ (Works out of the box with standard library; no heavy external packages required).

### dummy dashboard 

the dummy dashboard is available in index.html 

### Run the Demo
Open your terminal in this workspace and run:

```bash
python demo.py
```

Follow the prompts on screen:
* Watch Act 1 auto-heal in real time.
* When prompted in Act 2, enter **`y`** to approve the production firewall change!

---

## 🧪 Running Unit & Integration Tests

To run the automated test suite:

```bash
python -m unittest tests/test_compliance.py -v
```

All 6 test cases validate:
* Risk score environment scaling (Dev vs. Prod)
* Policy engine governance invariants
* Deterministic GCS & Firewall remediation tools
* Closed-loop verification
* Autonomous and Human-in-the-Loop workflows

---

## 📁 Project Architecture

```text
src/compliance_engine/
├── models/                  # Strong domain models
│   ├── finding.py           # Ingested SCC finding schema
│   ├── plan.py              # Remediation plan & technical diffs
│   ├── risk.py              # Blast radius & risk assessment models
│   ├── policy.py            # Governance decisions (Auto vs. HITL)
│   └── audit.py             # Cryptographic, tamper-evident audit records
│
├── governance/              # The "Seatbelts & Brakes"
│   ├── risk_engine.py       # Composite risk scoring (0-100)
│   ├── policy_engine.py     # Enterprise rules (Dev auto-heal, Prod sign-off)
│   └── approval_engine.py   # Human-in-the-loop state & token manager
│
├── planner/                 # The "Brain"
│   └── remediation_planner.py # Plans fix against CIS GCP benchmarks
│
├── tools/                   # The "Hands" (Deterministic Execution Plane)
│   ├── base.py              # Tool interface with execute & rollback
│   ├── gcs_tools.py         # Strips public IAM members & enforces PAP
│   └── firewall_tools.py    # Restricts open ingress to GCP IAP tunnel
│
├── validation/              # The "Verifier"
│   └── validator.py         # Probes live resource state post-execution
│
├── audit/                   # The "Paper Trail"
│   └── audit_logger.py      # SHA-256 sealed audit records for SOC2/ISO
│
└── orchestrator.py          # Master Compliance Control Plane Controller
```

---

## 🔒 Enterprise Safety Guarantees

* **No LLM Hallucinations in Execution:** The AI only formulates the plan and reasons about compliance; deterministic, tested Python tools perform all cloud mutations.
* **Anti-Data-Loss Invariant:** Any action with data loss risk is strictly rejected by the policy engine.
* **Closed-Loop Verification:** The ticket is never closed merely because an API returned success; the agent actively re-probes the resource to verify compliance.
