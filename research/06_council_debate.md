# RunbookPilot Council Debate (5 Experts, 3 Rounds)

## Council Members
1. **Maya** — Senior SOC Analyst (10 years in SOCs, daily SOAR user)
2. **Derek** — Detection Engineer (writes Sigma/YARA rules daily)
3. **Priya** — Platform Architect (distributed security systems)
4. **Tomas** — Security Automation Lead (3 enterprise SOAR deployments)
5. **Rachel** — Hiring Manager (hires $130K-200K detection engineering roles)

---

## FINAL CONSENSUS (All 5 Experts Converged)

### The Breakthrough: L2 Simulation Mode
Tomas proposed and all 5 accepted: **Build the L2 engine but run it in dry-run/simulation mode for v1**. L0-L1 execute in production. L2 actions log what they WOULD do, surface in an approval panel with one-click execute. This resolves the trust vs. demo-value tension.

### Architecture Decisions (Unanimous)

| Decision | Consensus | Rationale |
|----------|-----------|-----------|
| **Autonomy Levels** | L0-L2 (L2 simulation only) | Demo value + trust-first adoption |
| **Decision Engine** | Deterministic state machine | No ML/LLM in execution path |
| **Schema** | YAML with CACAO vocabulary | Human-readable, CACAO-convertible later |
| **LLM Role** | Analyst assistant ONLY | Enrichment summaries, playbook suggestions — never decisions |
| **Living Runbooks** | CUT from v1 | Self-modifying playbooks = uncontrolled drift |
| **DetectForge Coupling** | Loose (ECS events + ATT&CK IDs) | File-based handoff, no API coupling |
| **Event Format** | ECS (Elastic Common Schema) | Industry standard, tool-agnostic |
| **Reference Playbooks** | 3 (credential dump, lateral movement, C2 beacon) | Prove L0→L1→L2 progression |

---

## Round 1: Initial Positions

### Maya (SOC Analyst)
- Start L0-L1 only. Analysts need to trust the tool before any automation.
- Deterministic-only for v1. No ML, no LLM decision-making in the execution path.
- Simple YAML playbooks, NOT CACAO v2.0. Analysts won't adopt what they can't read/edit.
- Cut living runbooks entirely from v1. Self-modifying playbooks terrify SOC teams.
- Loose DetectForge coupling via shared ATT&CK technique IDs.
- OpenRouter fine with graceful degradation fallback to deterministic-only mode.

### Derek (Detection Engineer)
- Start L0-L2. The detection→response handoff is where value lives.
- Deterministic engine for v1. Agrees on no ML/LLM in execution.
- YAML playbooks. Agrees.
- Cut living runbooks. Agrees.
- Loose DetectForge coupling via ATT&CK technique IDs + shared event format.
- "Cut scope. Ship fast. Prove the handoff works."

### Priya (Platform Architect)
- L0-L2 only. L2 (supervised auto) is where the demo value is.
- Deterministic-only v1. Agrees.
- YAML over CACAO. But design YAML schema to be CACAO-convertible later.
- Cut living runbooks. Agrees.
- Loose coupling via normalized adapter pattern.
- 5 sprints max (S0-S4). "The MVP that ships is worth 10x the perfect system that doesn't."

### Tomas (Security Automation Lead)
- L0-L1 only. L2 is premature — trust must be earned through analyst adoption.
- Kill hybrid engine entirely. Deterministic state machine only.
- YAML over CACAO. CACAO adoption is near-zero in small teams.
- Cut living runbooks. "Self-modifying security playbooks" is an oxymoron.
- Loose coupling via shared JSON event schema.
- "Build trust before building autonomy."

### Rachel (Hiring Manager)
- L0-L2 for v1. Hiring managers want to see supervised automation working.
- Deterministic-only. Agrees.
- Simple YAML. Agrees.
- Cut living runbooks. Agrees.
- Loose coupling. Agrees.
- "Can you ship something real that shows you understand the problem space?"

**Round 1 Split:** L0-L1 (Maya, Tomas) vs L0-L2 (Derek, Priya, Rachel). All else unanimous.

---

## Round 2: Responses & Challenges

### Maya — Trust vs Demo Value
- Pushed back on L2 advocates: "Everyone is designing for demos, not adoption."
- Conceded LLM-powered analyst assistance (not decision-making) is valuable at L0-L1.
- Proposed ECS (Elastic Common Schema) as shared event format — open, documented, widely used.
- Challenged Derek: "The handoff that matters is L0→L1, not L1→L2. You can't skip trust-building."
- Challenged Rachel: "Show me high L0-L1 adoption metrics and I'm more impressed than unused L2 features."

### Derek — The Handoff Gap
- Defended L2: "Without L2, RunbookPilot is just a fancy alert enrichment tool."
- Proposed 3 reference playbooks as concrete success criteria:
  - L0: LSASS credential dumping → enrich with EDR + AD context
  - L1: Lateral movement → create ticket, notify analyst
  - L2: C2 beaconing → suggest host isolation, wait for approval
- "LLM should assist but not decide" — parse obfuscated PowerShell, generate summaries.
- Proposed ATT&CK technique mapping in YAML schema (`mitigates: [T1003.001]`).

### Priya — Architecture Middle Ground
- Proposed "L2 with training wheels" — build the engine, default to manual approval.
- Defined specific YAML schema with CACAO vocabulary:
  - Approval gates as first-class citizens (not bolted on)
  - Rollback mandatory for L2 steps
  - No vendor lock-in (generic actions, vendor adapters)
- "Define the shared event schema FIRST, then build runbook schema to consume it."

### Tomas — The Breakthrough Compromise
**Proposed "L2 Simulation Mode":**
- L0-L1 execute in production mode
- L2 actions run in dry-run only — log what they WOULD do
- Surface in review panel: "L2 Action Simulated: Isolate endpoint — Review & Execute?"
- One-click approval button for human-triggered execution
- Gives: demo capability (Rachel), trust foundation (Maya), L2 telemetry (Priya), handoff visibility (Derek)
- "We don't auto-execute containment in v1. But I can live with building the L2 engine if we gate it."

### Rachel — Portfolio Differentiation
- Confirmed L2 separates $85K analyst from $140K+ detection engineer roles.
- "Stopping at L1 signals you don't understand where the value is."
- Defined standout features: metrics dashboard (MTTD/MTTR), approval gate UX, error handling, integration testing.
- "Portfolios aren't production deployments. They're proof-of-concept demonstrations of capability."
- Emphasized the DetectForge→RunbookPilot pipeline story as interview gold.

---

## Round 3: Final Synthesis

### Maya — ACCEPTED L2 Simulation
"Yes. L2 simulation mode works for me. It's the unlock."
- Changed mind: Rachel is right about market value. L2 capability (even simulated) is the differentiator.
- Changed mind: Derek is right about the handoff gap living at L2.
- Holds firm: No auto-execution of L2 in v1. Simulation only.
- Holds firm: ECS as shared event format.
- Final: L0-L1 production + L2 simulation. Deterministic engine. LLM as analyst assistant only.
- Risk flagged: "L2 simulation feels like vaporware if the review UX is weak."

### Derek — 3 Reference Playbooks Finalized
Accepted Tomas's compromise. Finalized playbooks:
1. **L0 — LSASS Credential Dumping:** Sigma trigger → EDR enrichment → VirusTotal → asset criticality → SOAR queue
2. **L1 — WMI Lateral Movement:** Sigma trigger → isolate host via EDR → snapshot connections → notify analyst → rollback if FP
3. **L2 — Cobalt Strike Beaconing (Simulation):** Suricata trigger → simulate block C2 domain + quarantine host + pull memory → approval request

Proposed DetectForge handoff via `x-detectforge` metadata in Sigma YAML:
```yaml
x-detectforge:
  threat_actor: APT29
  attack_techniques: [T1003.001]
  suggested_runbook: lsass_credential_dump_l0.yaml
  confidence: 0.87
```
"No API coupling — pure file-based handoff."

### Priya — Sprint Structure & Schema
Proposed graduated execution tiers with simulation as a mode (not a level):
- L0 (Manual): Checklist only
- L1 (Semi-Auto): Direct execution with approval gates
- L2 (Full Auto): Approval-gated, requires `--enable-l2` flag + audit logging
- Simulation: Dry-run for ANY level

**Finalized YAML Schema:**
```yaml
runbook:
  id: uuid
  version: "1.0"
  metadata:
    name: "Contain Ransomware Lateral Movement"
    created: ISO8601
    updated: ISO8601
    tags: [ransomware, containment]
  triggers:
    detection_sources: [sigma, edr_alert, siem_correlation]
    mitre_techniques: [T1021.002, T1570]
    platforms: [windows]
  config:
    automation_level: L1
    max_execution_time: 600s
    requires_approval: true
  steps:
    - id: step-01
      name: "Isolate host from network"
      action: isolate_host
      executor: sentinel_api | crowdstrike_api | local_firewall
      parameters:
        host_id: "{{ alert.host_id }}"
      approval_required: true
      rollback:
        action: restore_connectivity
        timeout: 300s
      on_error: halt | continue | skip
```

**Sprint Structure (S0-S5):**
- S0: Foundation (CLI, schema validator, YAML parser)
- S1: Execution engine (L0-L1, approval gates, rollback)
- S2: Adapter layer (3 integrations: IP block, host isolation, log collection)
- S3: L2 + simulation mode (policy enforcement, audit log, dry-run)
- S4: Reference runbooks (3 playbooks working end-to-end)
- S5: Dashboard (execution history, MTTD/MTTR, approval queue)

**Integration:** Event bus pattern (Redis Streams/RabbitMQ). Docker Compose for demo. Standalone mode via STDIN/webhook.

### Tomas — Technical Specification for Simulation
Confirmed consensus achieved. Defined simulation mode technically:

**Production (L0-L1):** Execute queries, enrichment, data aggregation. No writes to production systems.

**Simulation (L2):** Log intended action as structured JSON:
```json
{
  "action": "isolate_host",
  "target": "WS-2401",
  "justification": "C2 callback detected",
  "confidence": 0.87
}
```
Store in approval queue. Surface in UI. Track what WOULD have happened.

**Technical constraint:** Executor returns `SimulationResult` vs `ExecutionResult`. Same code paths, different commit modes.

**LLM Permitted:** Translate queries to ECS filters, suggest playbook matches, summarize enrichment, generate investigation notes.
**LLM BANNED:** Choosing L2 actions, overriding approvals, modifying playbooks at runtime, determining confidence thresholds.

**Sprint recommendation:** S0-S4 (5 sprints). Demo L2 simulation in S3.

### Rachel — The Interview Playbook
Confirmed simulation mode is a STRONG hiring signal — "actually better than blind auto-execution."

**Winning 45-Minute Interview:**
- **First 10 min:** Pipeline story (threat report → Sigma rule → alert → containment playbook). Key metric: MTTR reduction.
- **Next 20 min:** Deep dive 3 playbooks (L0 phishing, L1 host isolation, L2 lateral movement). Show approval gate UX.
- **Final 15 min:** Production readiness (metrics dashboard, test coverage, ATT&CK mapping, error handling).

**Good Project vs Instant Hire:**
| Good Project | Instant Hire Signal |
|---|---|
| Works in demo | Error handling that tells a story |
| Handles happy path | Metrics you'd put in a board deck |
| Clean code | Security boundaries (RBAC, encryption, audit) |
| | Integration test suite (mocked EDR/SIEM) |

"Budget: 5 sprints, ship by end of March. This gets you $140K+ offers."

---

## Key Recommendations Summary

### Must Build (v1)
1. **L0-L2 deterministic execution engine** with L2 in simulation mode
2. **YAML playbook schema** with CACAO vocabulary, approval gates, rollback blocks
3. **3 reference playbooks** (credential dumping L0, lateral movement L1, C2 beaconing L2-sim)
4. **ECS-normalized event format** for DetectForge integration
5. **Approval gate UI** (the "3-second UX" that is the entire value prop)
6. **Metrics dashboard** (MTTD/MTTR, approval latency, simulation vs execution)
7. **LLM analyst assistant** (enrichment summaries, playbook suggestions — never decisions)

### Must NOT Build (v1)
1. Auto-executing L2 actions
2. Living/self-updating runbooks
3. Hybrid decision engine (ML + LLM)
4. Tight DetectForge coupling (no shared DB, no API dependencies)
5. CACAO v2.0 parser (use CACAO vocabulary in YAML instead)
6. LLM in the decision/execution path

### Sprint Consensus (S0-S5)
- **S0:** Foundation (CLI, schema, test harness, ECS format)
- **S1:** Execution engine (L0-L1, approval gates, rollback)
- **S2:** Adapter layer (3 vendor integrations)
- **S3:** L2 simulation mode (policy enforcement, audit, dry-run)
- **S4:** Reference runbooks (3 playbooks end-to-end)
- **S5:** Dashboard & polish (metrics, approval queue UI)

### DetectForge Integration
- **Coupling:** Loose — ECS-normalized events + ATT&CK technique IDs
- **Mechanism:** File-based handoff via `x-detectforge` metadata in Sigma YAML
- **Demo:** Single Docker Compose showing alert→runbook flow
- **Standalone:** RunbookPilot accepts STDIN/webhook alerts independently
