# RunbookPilot Product Requirements Document (PRD)

**Version:** 1.0
**Date:** 2026-02-10
**Author:** Security Projects Team
**Status:** Approved

---

## 1. Executive Summary

RunbookPilot is an open-source, AI-assisted SOC runbook automation tool with graduated human-in-the-loop autonomy (L0-L2). It bridges the gap between enterprise SOAR platforms ($100K-250K/yr) and manual runbook execution, providing small-to-medium security teams with intelligent automation that never removes humans from critical decision paths. Built on a deterministic state machine with LLM enrichment (not execution), RunbookPilot operationalizes incident response through YAML-defined playbooks, enabling security professionals to automate containment, investigation, and remediation workflows while maintaining full control and auditability.

---

## 2. Problem Statement

### The Market Gap

**Enterprise SOAR is dying:**
- Gartner discontinued the SOAR Magic Quadrant in 2024
- Legacy platforms (Palo Alto XSOAR, Splunk SOAR, Swimlane) cost $100K-250K/yr
- High operational maturity requirements exclude teams under 10 analysts
- "SOAR hangover" — teams reject bloated platforms after failed implementations

**Manual runbooks don't scale:**
- Tier 1 analysts spend 60-80% of time on repetitive tasks (credential resets, IP blocks, log collection)
- Mean Time to Respond (MTTR) increases linearly with alert volume
- Tribal knowledge locked in Confluence/Notion, not executable
- No consistency across analyst actions or shift handoffs

**Existing LLM-based automation is unsafe:**
- Tools like AutoGPT put LLMs in the execution path (unacceptable for security)
- No graduated autonomy model — it's all-or-nothing automation
- Limited auditability and rollback capabilities
- Proprietary platforms lock teams into specific LLM vendors

### The Pain Point

Security teams need:
1. **Automation without risk** — deterministic execution with LLM enrichment, not LLM decisions
2. **Graduated control** — start with approval-required actions, earn trust through simulation
3. **Accessibility** — simple setup, human-readable configs, no PhD in SOAR required
4. **Integration** — works with existing SIEM/EDR/ticketing without rip-and-replace
5. **Portfolio value** — demonstrates real-world SOC/Detection Engineering skills

---

## 3. Product Vision

### What RunbookPilot Becomes

**Short-term (v1, 6 months):**
An open-source CLI tool that executes YAML-defined incident response playbooks with L0-L2 autonomy, integrates with 3 vendor APIs (firewall, EDR, SIEM), and provides LLM-powered analyst enrichment summaries. Ships with 3 reference playbooks (credential dumping, lateral movement, C2 beaconing) and a web dashboard for approval queues and audit logs.

**Mid-term (v2, 12 months):**
A community-driven runbook library with 20+ ATT&CK-mapped playbooks, 10+ vendor integrations, and a visual playbook editor. Supports webhook/STDIN ingestion from any SIEM. Becomes the go-to open-source alternative to enterprise SOAR for small teams.

**Long-term (v3, 24 months):**
The industry-standard bridge between threat detection (DetectForge, Sigma) and automated response. Full CACAO v2.0 interoperability, ML-powered runbook suggestions (not execution), and a SaaS-lite hosted option for teams without infra. Establishes graduated autonomy (L0-L3) as the safe AI automation model for security.

### Position in Market

**Lower-left quadrant:**
- **Accessible** — YAML configs, 30-min setup, works on localhost
- **AI-native** — LLM enrichment built-in, not bolted-on
- **Open-source** — MIT license, community playbooks, vendor-agnostic

**Differentiation:**
- Only AI-native runbook tool with graduated autonomy model
- Only tool enforcing "LLM enrichment, not execution" architecture
- Direct DetectForge integration (detection-to-response pipeline)
- Built for portfolio + production use (not academic toy)

---

## 4. Target Users

### Primary Persona: SOC Analyst (Tier 1/2)

**Name:** Alex (Tier 1 Analyst at 150-person company)
**Pain:** Drowning in repetitive tasks (password resets, IP blocks, log pulls), no time for real investigations
**Goals:** Automate toil, get promoted to Tier 2, learn detection engineering
**Needs:**
- One-click approval for common actions (IP block, host isolation)
- Clear audit trail for compliance reviews
- LLM-generated investigation notes to speed up escalations
- Simple YAML syntax to customize playbooks

**Success:** Reduces MTTR from 45 min to 10 min on credential dumping alerts, gets promoted after demonstrating automation initiative

---

### Secondary Persona: Detection Engineer

**Name:** Jordan (Detection Engineer building portfolio)
**Pain:** DetectForge generates rules, but no way to demo automated response
**Goals:** Build end-to-end detection-to-response pipeline, land $150K role
**Needs:**
- DetectForge integration (Sigma metadata → playbook triggers)
- 3 reference playbooks showing real-world scenarios
- Metrics dashboard (MTTD/MTTR) for resume bullet points
- Docker Compose demo for GitHub portfolio

**Success:** Demonstrates full pipeline in interviews ("I built DetectForge to detect lateral movement, RunbookPilot to auto-isolate hosts"), lands senior detection engineer role

---

### Tertiary Persona: Security Manager (Small Team)

**Name:** Morgan (Security Manager, 5-person SOC)
**Pain:** Can't afford $150K SOAR platform, team burns out on manual runbooks
**Goals:** Reduce analyst toil, improve MTTR, justify headcount with metrics
**Needs:**
- Low-cost automation (open-source, runs on existing infra)
- Approval gates for compliance (PCI-DSS, SOC 2)
- Audit logs for incident reviews
- Easy onboarding (no 6-month SOAR implementation)

**Success:** Reduces MTTR by 60%, presents metrics to leadership, gets budget for 2 more analysts

---

## 5. User Stories

### L0 Autonomy (Information Gathering, Always Approved)

**US-001:** As a Tier 1 analyst, I want RunbookPilot to automatically query VirusTotal for IP reputation when a C2 beaconing alert fires, so I don't have to manually copy-paste IPs into the web UI.

**US-002:** As a Tier 1 analyst, I want RunbookPilot to pull the last 24 hours of logs from Splunk for a suspicious user, so I can review their full activity timeline in one place.

**US-003:** As a detection engineer, I want L0 actions to log to SQLite with timestamps and request/response data, so I can audit what queries were made during an incident.

---

### L1 Autonomy (Low-Risk Actions, Approval Required)

**US-004:** As a Tier 2 analyst, I want RunbookPilot to surface a one-click approval button for blocking an IP at the firewall, so I can execute the action in 5 seconds instead of SSHing into the firewall CLI.

**US-005:** As a Tier 1 analyst, I want RunbookPilot to show me the full firewall API request before I approve it, so I can verify I'm not blocking a production service by accident.

**US-006:** As a security manager, I want L1 actions to require approval even if the playbook says "auto-approve," so I can enforce policy until my team is trained.

**US-007:** As a Tier 2 analyst, I want to rollback an IP block if it was a false positive, so I can restore service without filing a firewall change ticket.

---

### L2 Autonomy (Moderate-Risk Actions, Simulation Mode)

**US-008:** As a security manager, I want L2 actions (host isolation) to run in simulation mode, showing me what would have happened without actually executing, so I can build confidence before enabling auto-execution.

**US-009:** As a Tier 1 analyst, I want to review the L2 simulation log and click "Execute Now" if it looks correct, so I can manually trigger the action RunbookPilot recommended.

**US-010:** As a detection engineer, I want simulation mode to log to a separate audit table with "DRY_RUN" labels, so I can measure precision (% of simulations I would have approved).

---

### DetectForge Integration

**US-011:** As a detection engineer, I want RunbookPilot to read `x-detectforge` metadata from Sigma rules, automatically selecting the correct playbook based on ATT&CK technique IDs, so I don't have to manually configure alert-to-runbook mappings.

**US-012:** As a portfolio builder, I want a single `docker-compose up` command to demo DetectForge generating a lateral movement rule and RunbookPilot responding to a test alert, so I can show the full pipeline in 5 minutes.

---

### Administration & Visibility

**US-013:** As a Tier 2 analyst, I want a web dashboard showing pending approvals, recent executions, and failed actions, so I don't have to tail log files.

**US-014:** As a security manager, I want to see MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) metrics per playbook, so I can report ROI to leadership.

**US-015:** As a Tier 1 analyst, I want LLM-generated investigation summaries (ATT&CK context, recommended next steps) to appear in the approval UI, so I can learn detection engineering while responding to alerts.

---

## 6. Functional Requirements

### F1: Playbook Schema & Parser (S0)

**F1.1:** YAML-based playbook format with CACAO-inspired vocabulary (not full CACAO v2.0)
**F1.2:** Schema validator enforcing required fields: `id`, `name`, `trigger`, `steps[]`, `autonomy_level`
**F1.3:** Each step defines: `action_type` (query, block, isolate), `adapter` (vendor), `params`, `approval_required`
**F1.4:** ATT&CK technique IDs in `trigger.techniques[]` for DetectForge matching
**F1.5:** Human-readable comments allowed (YAML `#` syntax)
**F1.6:** Playbook versioning via `version` field (semantic versioning)

**Acceptance Criteria:**
- Schema validator rejects playbooks missing required fields (exit code 1)
- Parser loads 3 reference playbooks (credential dumping, lateral movement, C2 beaconing)
- Invalid YAML syntax returns actionable error message with line number
- Test coverage: 95%+ on parser and validator

---

### F2: Event Ingestion (S0)

**F2.1:** Accept ECS (Elastic Common Schema) formatted events via STDIN (JSON lines)
**F2.2:** Accept ECS events via HTTP webhook (`POST /events`)
**F2.3:** Normalize non-ECS events using adapter layer (future: S2)
**F2.4:** Extract ATT&CK technique IDs from `threat.technique.id` field (ECS standard)
**F2.5:** Queue events in SQLite `events` table with `status` (pending, running, completed, failed)

**Acceptance Criteria:**
- CLI accepts `cat alert.json | runbookpilot execute`
- Webhook endpoint returns 202 Accepted with event ID
- Malformed JSON returns 400 Bad Request with error details
- Events persisted to SQLite survive process restart

---

### F3: Execution Engine (S1)

**F3.1:** Deterministic state machine (no ML/LLM in execution path)
**F3.2:** Match events to playbooks via `trigger.techniques[]` or `trigger.conditions[]`
**F3.3:** Execute steps sequentially, halting on approval gates
**F3.4:** Retry failed API calls 3x with exponential backoff (1s, 2s, 4s)
**F3.5:** Log every step to `execution_log` table (timestamp, step_id, status, request, response)
**F3.6:** Support rollback for reversible actions (IP unblock, host un-isolate)

**Acceptance Criteria:**
- L0 action (VirusTotal query) executes without approval gate
- L1 action (IP block) halts at approval gate, resumes after `runbookpilot approve <execution_id>`
- Failed API call retries 3x before marking step as failed
- Rollback command (`runbookpilot rollback <execution_id>`) reverses L1 action
- Execution survives process restart (state persisted to SQLite)

---

### F4: Approval Gates (S1)

**F4.1:** L1 actions require explicit approval via CLI or API
**F4.2:** Approval UI shows: step description, target resource, full API request payload
**F4.3:** Policy enforcement: `global_policy.yaml` can override playbook `approval_required` flags
**F4.4:** Approval timeout: actions expire after 4 hours, marked as `expired`
**F4.5:** Bulk approve: `runbookpilot approve --all-pending --playbook lateral_movement`

**Acceptance Criteria:**
- Approval required actions create entry in `approvals` table with status `pending`
- CLI command `runbookpilot list-approvals` shows pending actions
- Expired approvals (>4 hours) auto-reject and log warning
- Policy override works: if `global_policy.yaml` sets `require_approval: true`, L0 actions also require approval

---

### F5: Adapter Layer (S2)

**F5.1:** Vendor-agnostic adapter interface: `execute(action, params) -> result`
**F5.2:** 3 reference adapters (v1): PaloAlto firewall (IP block), CrowdStrike EDR (host isolation), Splunk (log query)
**F5.3:** Adapter config in `adapters.yaml`: API endpoints, auth tokens (env vars), timeouts
**F5.4:** Dry-run mode for all adapters (logs request, returns mock response)
**F5.5:** Adapter health check: `runbookpilot test-adapter crowdstrike`

**Acceptance Criteria:**
- IP block action calls `PaloAltoAdapter.blockIP(ip, zone)` with correct parameters
- Adapters read credentials from env vars (never hardcoded)
- Dry-run mode (`--dry-run` flag) logs API request, does NOT call real API
- Health check returns HTTP status, API version, auth status

---

### F6: L2 Simulation Mode (S3)

**F6.1:** L2 actions run in simulation mode by default (never auto-execute)
**F6.2:** Simulation logs to separate `simulations` table with `DRY_RUN` label
**F6.3:** Simulation shows: what would execute, expected outcome, risk score (1-10)
**F6.4:** Manual trigger: `runbookpilot execute-simulation <simulation_id>` promotes to real execution
**F6.5:** Policy enforcement: `global_policy.yaml` can block L2 execution entirely

**Acceptance Criteria:**
- L2 action (host isolation) creates simulation entry, does NOT call EDR API
- Simulation log includes full request payload + "SIMULATED" status
- Analyst can review simulation and click "Execute Now" in dashboard
- Policy blocks execution even if analyst approves (compliance mode)

---

### F7: LLM Enrichment (S0-S3)

**F7.1:** LLM used for enrichment ONLY (summaries, suggestions), never execution
**F7.2:** OpenRouter integration (model-agnostic, defaults to `gpt-4o-mini`)
**F7.3:** Graceful degradation: if OpenRouter fails, log warning and continue without enrichment
**F7.4:** Enrichment types:
- ATT&CK technique context (description, common defenses)
- Investigation next steps (suggested queries, related alerts)
- Incident summary (plain-English explanation of playbook actions)
**F7.5:** Enrichment cached in `enrichments` table to avoid duplicate API calls

**Acceptance Criteria:**
- Alert triggers playbook, LLM generates ATT&CK context within 3 seconds
- If OpenRouter API key missing, execution proceeds without enrichment
- Same alert+playbook combo reuses cached enrichment (no duplicate API calls)
- Enrichment displayed in approval UI and logged to execution log

---

### F8: Reference Playbooks (S4)

**F8.1:** 3 production-ready playbooks:
1. **Credential Dumping (L0)** — Query VirusTotal, pull user logs, generate timeline
2. **Lateral Movement (L1)** — Block source IP at firewall, isolate source host (approval required), pull network logs
3. **C2 Beaconing (L2)** — Simulate DNS sinkhole, pull endpoint telemetry, recommend manual investigation

**F8.2:** Each playbook includes:
- ATT&CK technique mappings
- DetectForge `x-detectforge` metadata compatibility
- Inline comments explaining each step
- Rollback procedures (where applicable)

**Acceptance Criteria:**
- All 3 playbooks validate against schema
- End-to-end test: simulate alert → playbook executes → approval gate works → rollback succeeds
- DetectForge integration test: Sigma rule metadata → playbook auto-selected

---

### F9: Dashboard & UI (S5)

**F9.1:** Web dashboard (React + Tailwind) at `http://localhost:8080`
**F9.2:** Views:
- **Approval Queue** — Pending L1/L2 actions with one-click approve/reject
- **Execution History** — Last 100 runs with status, duration, playbook name
- **Metrics** — MTTD/MTTR per playbook, success rate, approval rate
- **Playbook Library** — Browse/search available playbooks

**F9.3:** Real-time updates via WebSocket (execution status changes push to UI)
**F9.4:** Authentication: basic auth (env vars `RBPILOT_USER`, `RBPILOT_PASS`)
**F9.5:** Mobile-responsive (80% of UI usable on tablet)

**Acceptance Criteria:**
- Approval queue shows pending actions within 1 second of creation
- Metrics dashboard loads in <2 seconds with 1000+ historical executions
- WebSocket updates appear without page refresh
- Basic auth prevents unauthorized access

---

### F10: DetectForge Integration (S0-S4)

**F10.1:** Read `x-detectforge` metadata from Sigma YAML:
```yaml
x-detectforge:
  suggested_runbook: lateral_movement_L1
  confidence: high
  techniques: [T1021.001, T1021.002]
```

**F10.2:** Auto-select playbook if `suggested_runbook` matches playbook `id`
**F10.3:** Fallback: match via `techniques[]` if no `suggested_runbook`
**F10.4:** Demo Docker Compose:
- DetectForge generates Sigma rule from threat intel report
- Test alert fired into Elastic
- Elastic webhook → RunbookPilot ingests ECS event
- RunbookPilot executes lateral movement playbook

**F10.5:** Loose coupling: RunbookPilot works standalone (no DetectForge dependency)

**Acceptance Criteria:**
- Sigma rule with `x-detectforge` metadata triggers correct playbook
- Alert without metadata falls back to technique-based matching
- Docker Compose demo runs end-to-end in <5 minutes
- RunbookPilot CLI works independently (no DetectForge installation required)

---

## 7. Non-Functional Requirements

### NFR-1: Performance

**NFR-1.1:** Playbook selection latency <100ms (from event ingestion to playbook match)
**NFR-1.2:** L0 action execution latency <3s (excluding external API call time)
**NFR-1.3:** Dashboard loads in <2s with 1000+ historical executions
**NFR-1.4:** SQLite supports 10,000+ events without performance degradation
**NFR-1.5:** Concurrent execution: 5 playbooks running in parallel (separate events)

---

### NFR-2: Security

**NFR-2.1:** API keys stored in env vars, never committed to git
**NFR-2.2:** Adapter config validates SSL certificates (no `verify=false`)
**NFR-2.3:** Approval UI requires authentication (basic auth minimum)
**NFR-2.4:** Audit log immutable (append-only SQLite table)
**NFR-2.5:** Secrets redacted in logs (`"password": "***"`)
**NFR-2.6:** LLM prompts sanitized (no event data injection attacks)

---

### NFR-3: Reliability

**NFR-3.1:** Execution survives process restart (state persisted to SQLite)
**NFR-3.2:** Failed API calls retry 3x with exponential backoff
**NFR-3.3:** Graceful degradation: LLM enrichment failure does not block execution
**NFR-3.4:** Rollback available for all reversible L1 actions
**NFR-3.5:** Health check endpoint (`/health`) returns 200 if DB accessible and all adapters configured

---

### NFR-4: Usability

**NFR-4.1:** Playbook syntax validated on load with actionable error messages
**NFR-4.2:** CLI help text includes examples (`runbookpilot --help`)
**NFR-4.3:** Dashboard tooltips explain autonomy levels (L0/L1/L2)
**NFR-4.4:** Setup time <30 minutes (clone repo → `docker-compose up` → first playbook runs)
**NFR-4.5:** Documentation includes 3 video walkthroughs (install, write playbook, DetectForge integration)

---

### NFR-5: Maintainability

**NFR-5.1:** Test coverage >90% (vitest)
**NFR-5.2:** TypeScript strict mode enabled
**NFR-5.3:** Adapter interface allows community contributions (plugin architecture)
**NFR-5.4:** Changelog follows Keep a Changelog format
**NFR-5.5:** CI/CD: GitHub Actions runs tests on every commit

---

## 8. Autonomy Model

### Level 0 (L0): Information Gathering

**Description:** Read-only actions with zero business impact. Always execute without approval.

**Examples:**
- Query VirusTotal/AbuseIPDB for IP reputation
- Pull logs from SIEM (Splunk, Elastic)
- Enumerate user group memberships (LDAP query)
- Check file hash against threat intel feeds

**Approval:** Never required
**Rollback:** Not applicable (read-only)
**Risk:** Minimal (no state changes)

**Policy Enforcement:**
- Global policy CAN override to require approval (training mode)
- Execution logged to audit trail
- LLM enrichment optional (summary of findings)

---

### Level 1 (L1): Low-Risk Actions

**Description:** Reversible, low-impact actions affecting single resources. Require approval before execution.

**Examples:**
- Block single IP at perimeter firewall
- Disable user account (AD/Okta)
- Quarantine email message
- Add IP to deny list (WAF, DNS firewall)

**Approval:** Always required (unless overridden by policy)
**Rollback:** Available (unblock IP, re-enable account)
**Risk:** Low (affects single user/IP, reversible)

**Policy Enforcement:**
- Global policy CAN auto-approve trusted playbooks (after 30-day validation period)
- Approval UI shows full API request payload
- Timeout: 4 hours (auto-reject if not approved)

---

### Level 2 (L2): Moderate-Risk Actions (SIMULATION MODE)

**Description:** Actions affecting multiple resources or critical services. Run in simulation mode by default (dry-run), surfaced for one-click manual execution.

**Examples:**
- Isolate host from network (EDR)
- Block domain at DNS firewall (affects all users)
- Restart service on production server
- Add firewall rule affecting subnet

**Approval:** Simulation runs without approval, execution requires approval
**Rollback:** Available (un-isolate host, remove firewall rule)
**Risk:** Moderate (production impact possible, false positive consequences)

**Policy Enforcement:**
- Global policy CAN block L2 execution entirely (compliance mode)
- Simulation log separate from execution log (`DRY_RUN` label)
- Analyst reviews simulation, clicks "Execute Now" if correct
- Execution treated as L1 (requires approval, logged, reversible)

**Simulation Output:**
```json
{
  "simulation_id": "sim_abc123",
  "playbook": "lateral_movement_L1",
  "action": "isolate_host",
  "target": "DESKTOP-5678",
  "would_execute": {
    "adapter": "crowdstrike",
    "method": "POST /hosts/isolate",
    "params": {"device_id": "abc123"}
  },
  "expected_outcome": "Host isolated from network, user sessions terminated",
  "risk_score": 7,
  "recommendation": "Review user activity logs before executing"
}
```

---

### Level 3 (L3): High-Risk Actions

**OUT OF SCOPE FOR V1.** Reserved for future (v2+): automated threat hunting, bulk account disables, infrastructure changes.

---

### Autonomy Progression Path

**Phase 1 (Weeks 1-4):** All L1/L2 actions require approval. Build confidence.
**Phase 2 (Weeks 5-8):** Enable L2 simulation mode. Review dry-run logs weekly.
**Phase 3 (Weeks 9-12):** Auto-approve trusted L1 actions (IP blocks for known threat intel IPs).
**Phase 4 (Month 4+):** One-click execution of L2 simulations after analyst review.

**Measurement:**
- Approval rate (% of simulations analyst would have approved)
- False positive rate (% of executed actions later rolled back)
- Time saved (MTTR before vs. after automation)

---

## 9. Integration Requirements

### I1: DetectForge Integration

**I1.1:** Parse `x-detectforge` metadata from Sigma YAML
**I1.2:** Match `suggested_runbook` to playbook ID
**I1.3:** Fallback to `techniques[]` matching if no `suggested_runbook`
**I1.4:** Demo Docker Compose: DetectForge → Elastic → RunbookPilot
**I1.5:** File-based handoff (no API coupling)

---

### I2: SIEM Integration

**I2.1:** Ingest ECS events via webhook (Elastic, Logstash)
**I2.2:** Ingest Splunk JSON via STDIN (forwarder script)
**I2.3:** Normalize Sentinel, Chronicle, Sumo Logic to ECS (adapter layer)

---

### I3: EDR Integration

**I3.1:** CrowdStrike Falcon adapter (host isolation, process kill)
**I3.2:** Carbon Black adapter (future: S6)
**I3.3:** SentinelOne adapter (future: S6)

---

### I4: Firewall Integration

**I4.1:** Palo Alto PAN-OS adapter (IP block, policy add)
**I4.2:** Fortinet FortiGate adapter (future: S6)
**I4.3:** pfSense adapter (community contribution)

---

### I5: Ticketing Integration

**I5.1:** Jira adapter (create ticket, add comment, close ticket)
**I5.2:** ServiceNow adapter (future: S6)
**I5.3:** PagerDuty adapter (trigger incident, acknowledge)

---

### I6: Threat Intel Integration

**I6.1:** VirusTotal API (IP/domain/hash reputation)
**I6.2:** AbuseIPDB API (IP reputation)
**I6.3:** MISP adapter (query indicators, add sightings)

---

## 10. Success Metrics

### Portfolio Metrics (Detection Engineer Persona)

**M1:** GitHub stars >100 within 6 months
**M2:** 3+ community-contributed playbooks within 6 months
**M3:** Featured in "Awesome Security Automation" list
**M4:** Mentioned in job interviews (self-reported)
**M5:** Portfolio demo completable in <5 minutes

---

### Operational Metrics (SOC Analyst Persona)

**M6:** MTTR reduction >50% on playbook-enabled alerts
**M7:** Tier 1 analyst time savings >10 hours/week
**M8:** False positive rate <5% (actions later rolled back)
**M9:** Approval rate >80% (analyst agrees with L2 simulations)
**M10:** Zero security incidents caused by automation errors

---

### Technical Metrics

**M11:** Test coverage >90%
**M12:** Zero critical security vulnerabilities (Snyk scan)
**M13:** Docker image size <500 MB
**M14:** Setup time <30 minutes (first-time user)
**M15:** API response time p95 <3s

---

### Adoption Metrics

**M16:** 50+ Docker Hub pulls within 3 months
**M17:** 10+ community members in Discord/Slack
**M18:** 3+ blog posts/tutorials by community
**M19:** 1+ conference talk accepted (BSides, SANS)

---

## 11. Out of Scope (v1)

### Explicitly NOT Building

**OS-1: Auto-executing L2 actions**
Rationale: Unacceptable risk. Simulation mode only until v2 after 6+ months of validation.

**OS-2: Living/self-updating runbooks**
Rationale: LLM reliability insufficient. Deterministic YAML only for v1.

**OS-3: Hybrid decision engine (ML + LLM)**
Rationale: Adds complexity without proven value. Deterministic state machine sufficient.

**OS-4: Tight DetectForge coupling**
Rationale: RunbookPilot must work standalone. Loose coupling via metadata only.

**OS-5: Full CACAO v2.0 parser**
Rationale: CACAO is verbose and complex. CACAO-inspired vocabulary, not full spec.

**OS-6: LLM in decision/execution path**
Rationale: Unsafe. LLM enrichment only, never decisions or actions.

**OS-7: Multi-tenancy**
Rationale: v1 targets single-team use. Multi-tenancy for SaaS version (v3).

**OS-8: Visual playbook editor**
Rationale: YAML-first for v1. Visual editor for v2 after validating schema.

**OS-9: Mobile app**
Rationale: Mobile-responsive web dashboard sufficient for v1.

**OS-10: Real-time collaboration**
Rationale: Single-analyst workflow for v1. Collaboration features in v2.

---

## 12. Risk Register

### R1: LLM Hallucination Causes Bad Recommendations

**Severity:** High
**Likelihood:** Medium
**Impact:** Analyst approves incorrect action based on LLM-generated summary

**Mitigation:**
- LLM enrichment clearly labeled as "AI-GENERATED" in UI
- Full API request payload shown (not just LLM summary)
- Analyst training: "Verify before approving"
- Graceful degradation: execution proceeds even if LLM fails

**Residual Risk:** Low (mitigations effective)

---

### R2: Feedback Loop Poisoning

**Severity:** Medium
**Likelihood:** Medium
**Impact:** Analysts rubber-stamp approvals to clear queue, reducing effectiveness

**Mitigation:**
- Approval timeout (4 hours) prevents queue buildup
- Metrics track approval rate (>95% = warning sign)
- Monthly review: "Are we auto-approving too much?"
- L2 simulation mode prevents high-risk auto-execution

**Residual Risk:** Medium (requires ongoing vigilance)

---

### R3: OpenRouter Dependency Failure

**Severity:** Low
**Likelihood:** Low
**Impact:** No LLM enrichment, execution continues but analyst loses context

**Mitigation:**
- Graceful degradation (log warning, continue without enrichment)
- Enrichment cache reduces API dependency (reuse previous summaries)
- Fallback to local LLM (future: S6, Ollama integration)
- Documentation: "How to run without OpenRouter"

**Residual Risk:** Very Low (non-blocking failure)

---

### R4: Adapter API Changes Break Integrations

**Severity:** Medium
**Likelihood:** Medium
**Impact:** Playbooks fail silently, actions not executed

**Mitigation:**
- Adapter health checks (daily cron job)
- Version pinning (Palo Alto PAN-OS v11, CrowdStrike API v2)
- Automated tests against vendor sandbox APIs (CI/CD)
- Community reports API breakage via GitHub issues

**Residual Risk:** Low (mitigations effective)

---

### R5: False Positive Causes Production Outage

**Severity:** High
**Likelihood:** Low
**Impact:** Auto-approved IP block cuts off legitimate traffic

**Mitigation:**
- L1 actions require approval (no auto-execution by default)
- Rollback available for all L1 actions (one-click unblock)
- Simulation mode for L2 (dry-run before execution)
- Policy enforcement: global override blocks auto-approval
- Pre-execution validation: "Is this IP in allow list?"

**Residual Risk:** Very Low (multiple safeguards)

---

## 13. Glossary

**Adapter:** Vendor-specific integration module (e.g., PaloAltoAdapter, CrowdStrikeAdapter). Implements standard interface for executing actions.

**ATT&CK:** MITRE ATT&CK framework. Taxonomy of adversary tactics and techniques (e.g., T1021.001 = Remote Desktop Protocol).

**Autonomy Level (L0-L2):** Graduated automation model. L0 = read-only, L1 = low-risk with approval, L2 = moderate-risk simulation.

**CACAO:** Collaborative Automated Course of Action Operations. OASIS standard for machine-readable playbooks. RunbookPilot uses CACAO-inspired vocabulary, not full spec.

**DetectForge:** Companion project. AI-powered tool for generating detection rules (Sigma/YARA/Suricata) from threat intelligence reports.

**ECS (Elastic Common Schema):** Standardized event format. RunbookPilot's native ingestion format (e.g., `source.ip`, `user.name`, `threat.technique.id`).

**Enrichment:** LLM-generated context added to alerts (ATT&CK descriptions, investigation tips). Never used for decisions or execution.

**Execution Log:** Append-only audit trail of all actions (timestamp, playbook, step, status, request, response). Stored in SQLite.

**Playbook:** YAML-defined incident response workflow. Contains trigger conditions, steps (actions), autonomy level, rollback procedures.

**Rollback:** Reversal of executed action (e.g., unblock IP, un-isolate host). Available for L1 actions, logged to audit trail.

**Simulation Mode:** Dry-run execution for L2 actions. Logs what would execute without calling real APIs. Analyst reviews and manually triggers if correct.

**SOAR (Security Orchestration, Automation, Response):** Category of enterprise security platforms. Legacy SOAR (Splunk, Palo Alto) costs $100K-250K/yr. RunbookPilot is open-source alternative.

**State Machine:** Deterministic execution engine. No ML/LLM in decision path. Steps execute sequentially based on playbook definition.

**x-detectforge:** Custom Sigma YAML metadata field. Contains DetectForge-generated data (suggested_runbook, confidence, ATT&CK techniques).

---

## Appendix A: Sprint Plan Summary

| Sprint | Focus | Key Deliverables | Duration |
|--------|-------|------------------|----------|
| **S0** | Foundation | CLI, schema validator, YAML parser, ECS format, test harness | 2 weeks |
| **S1** | Execution Engine | L0-L1 execution, approval gates, rollback, SQLite persistence | 3 weeks |
| **S2** | Adapter Layer | 3 vendor integrations (Palo Alto, CrowdStrike, Splunk), dry-run mode | 3 weeks |
| **S3** | L2 Simulation | Policy enforcement, simulation mode, audit log, manual trigger | 2 weeks |
| **S4** | Reference Playbooks | 3 production playbooks (credential dumping, lateral movement, C2), DetectForge integration | 3 weeks |
| **S5** | Dashboard & Polish | Web UI (approval queue, metrics, execution history), Docker Compose demo | 3 weeks |

**Total:** 16 weeks (4 months)

---

## Appendix B: Technology Stack

**Runtime:** Bun (TypeScript runtime, same as DetectForge for portfolio consistency)
**Language:** TypeScript (strict mode)
**Testing:** Vitest (unit + integration tests, >90% coverage)
**Database:** SQLite (events, executions, approvals, audit log)
**LLM:** OpenRouter (model-agnostic, defaults to gpt-4o-mini)
**Web Framework:** Hono (lightweight HTTP server for webhook + dashboard)
**Frontend:** React + Tailwind CSS
**WebSocket:** ws (real-time UI updates)
**Deployment:** Docker + Docker Compose
**CI/CD:** GitHub Actions
**License:** MIT

---

## Appendix C: Example Playbook (Lateral Movement L1)

```yaml
id: lateral_movement_L1
name: Lateral Movement Response (L1)
version: 1.0.0
description: Block source IP and isolate host when lateral movement detected
autonomy_level: L1

trigger:
  techniques:
    - T1021.001  # Remote Desktop Protocol
    - T1021.002  # SMB/Windows Admin Shares
  conditions:
    - field: event.category
      operator: equals
      value: intrusion_detection
    - field: threat.tactic.name
      operator: equals
      value: Lateral Movement

steps:
  - id: step_1
    name: Query VirusTotal for source IP reputation
    action_type: query
    adapter: virustotal
    autonomy_level: L0
    params:
      resource: "{{source.ip}}"
      resource_type: ip-address
    approval_required: false

  - id: step_2
    name: Pull network logs for source and destination hosts
    action_type: query
    adapter: splunk
    autonomy_level: L0
    params:
      query: "index=network (src_ip={{source.ip}} OR dest_ip={{destination.ip}}) earliest=-24h"
      output_format: json
    approval_required: false

  - id: step_3
    name: Block source IP at perimeter firewall
    action_type: block_ip
    adapter: paloalto
    autonomy_level: L1
    params:
      ip: "{{source.ip}}"
      zone: external
      policy_name: "AUTO_BLOCK_{{execution_id}}"
    approval_required: true
    rollback_available: true

  - id: step_4
    name: Isolate source host from network
    action_type: isolate_host
    adapter: crowdstrike
    autonomy_level: L2
    params:
      hostname: "{{source.host.name}}"
      device_id: "{{source.host.id}}"
    approval_required: true
    simulation_mode: true  # Dry-run by default, analyst triggers manually

enrichment:
  enabled: true
  provider: openrouter
  prompts:
    - type: technique_context
      template: "Explain ATT&CK technique {{technique_id}} in 2-3 sentences for a Tier 1 analyst."
    - type: investigation_steps
      template: "Given lateral movement from {{source.ip}} to {{destination.ip}}, what should an analyst investigate next? List 3 actions."

rollback:
  step_3:
    action_type: unblock_ip
    adapter: paloalto
    params:
      policy_name: "AUTO_BLOCK_{{execution_id}}"
  step_4:
    action_type: un_isolate_host
    adapter: crowdstrike
    params:
      device_id: "{{source.host.id}}"
```

---

## Appendix D: DetectForge Integration Example

**DetectForge Sigma Output (lateral_movement.yml):**
```yaml
title: Lateral Movement via RDP from Unusual Source
id: abc123-lateral-rdp
status: stable
description: Detects RDP connection from internal host not in approved jump server list
author: DetectForge AI
date: 2026-02-10

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4624
    LogonType: 10  # RDP
  filter:
    IpAddress:
      - 10.0.5.10  # Approved jump server
      - 10.0.5.11
  condition: selection and not filter

falsepositives:
  - New jump server added without updating allow list

level: high

tags:
  - attack.lateral_movement
  - attack.t1021.001

# DetectForge metadata (RunbookPilot integration)
x-detectforge:
  suggested_runbook: lateral_movement_L1
  confidence: high
  techniques:
    - T1021.001
  model: anthropic/claude-opus-4-6
  generated_at: 2026-02-10T15:30:00Z
```

**RunbookPilot Ingestion:**
1. Alert fires in Elastic/Splunk with Sigma rule ID `abc123-lateral-rdp`
2. Webhook sends ECS event to RunbookPilot
3. RunbookPilot reads `x-detectforge.suggested_runbook` → selects `lateral_movement_L1` playbook
4. Fallback: If no `suggested_runbook`, matches via `x-detectforge.techniques[]`
5. Playbook executes (L0 queries → L1 IP block approval → L2 host isolation simulation)

---

## Appendix E: Approval UI Mockup (Text)

```
┌─────────────────────────────────────────────────────────────┐
│ RunbookPilot - Approval Queue                       [Logout]│
├─────────────────────────────────────────────────────────────┤
│                                                               │
│ Pending Approvals (2)                                        │
│                                                               │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ Execution #1847 - lateral_movement_L1                 │   │
│ │ Triggered: 2026-02-10 15:32:18 (2 minutes ago)        │   │
│ │ Alert: RDP from 10.0.8.45 → 10.0.3.12                 │   │
│ │                                                         │   │
│ │ Step 3: Block source IP at perimeter firewall         │   │
│ │ Autonomy: L1 (Low-Risk, Approval Required)            │   │
│ │                                                         │   │
│ │ API Request:                                           │   │
│ │   POST https://firewall.example.com/api/v1/policy     │   │
│ │   {                                                    │   │
│ │     "action": "deny",                                  │   │
│ │     "source": "10.0.8.45",                             │   │
│ │     "zone": "external",                                │   │
│ │     "policy_name": "AUTO_BLOCK_exec1847"              │   │
│ │   }                                                    │   │
│ │                                                         │   │
│ │ AI Context (Claude Opus 4.6):                         │   │
│ │ "This IP has 2 prior lateral movement alerts in the   │   │
│ │  last 7 days. VirusTotal reputation: clean (0/89).    │   │
│ │  Recommend blocking and investigating host."          │   │
│ │                                                         │   │
│ │ Rollback: Available (one-click unblock)               │   │
│ │ Expires: 2026-02-10 19:32:18 (3h 58m remaining)       │   │
│ │                                                         │   │
│ │         [Approve & Execute]  [Reject]  [View Logs]    │   │
│ └───────────────────────────────────────────────────────┘   │
│                                                               │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ Simulation #1848 - c2_beaconing_L2                    │   │
│ │ Triggered: 2026-02-10 15:34:02 (28 seconds ago)       │   │
│ │ Alert: DNS beaconing to evil.com from 10.0.9.23       │   │
│ │                                                         │   │
│ │ Step 4: Isolate host from network (SIMULATION)        │   │
│ │ Autonomy: L2 (Moderate-Risk, Simulation Mode)         │   │
│ │                                                         │   │
│ │ Would Execute:                                         │   │
│ │   POST https://crowdstrike.example.com/api/v2/isolate│   │
│ │   {                                                    │   │
│ │     "device_id": "abc123def456",                       │   │
│ │     "hostname": "LAPTOP-9023"                          │   │
│ │   }                                                    │   │
│ │                                                         │   │
│ │ Expected Outcome: Host isolated, user sessions killed │   │
│ │ Risk Score: 7/10 (production laptop, active user)     │   │
│ │                                                         │   │
│ │ Recommendation: Review user activity logs before      │   │
│ │                 executing isolation.                   │   │
│ │                                                         │   │
│ │         [Execute Now]  [Dismiss]  [View Simulation]   │   │
│ └───────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

**END OF PRD**

---

## Document Control

**Approvals:**
- Product Owner: [Signature Required]
- Technical Lead: [Signature Required]
- Security Reviewer: [Signature Required]

**Revision History:**

| Version | Date       | Author | Changes |
|---------|------------|--------|---------|
| 1.0     | 2026-02-10 | Security Projects Team | Initial PRD |

**Next Review:** 2026-03-10 (after S0 completion)
