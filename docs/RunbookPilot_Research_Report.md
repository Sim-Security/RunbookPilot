# RunbookPilot: SOC Runbook Automation Research Report

**Date:** 2026-02-10
**Purpose:** Comprehensive research to inform the architecture and design of RunbookPilot — an AI-guided SOC runbook automation tool with human-in-the-loop decision support.

---

## Table of Contents

1. [Runbook Standards & Frameworks](#1-runbook-standards--frameworks)
2. [Runbook Schema Design](#2-runbook-schema-design)
3. [Human-in-the-Loop Decision Points](#3-human-in-the-loop-decision-points)
4. [AI/LLM in Incident Response](#4-aillm-in-incident-response)
5. [Integration Points](#5-integration-points)
6. [Open Source Runbook Resources](#6-open-source-runbook-resources)
7. [Design Implications for RunbookPilot](#7-design-implications-for-runbookpilot)

---

## 1. Runbook Standards & Frameworks

### 1.1 NIST SP 800-61 Revision 3 (April 2025)

NIST finalized SP 800-61r3 in April 2025 — the first update since 2012. This revision fundamentally restructures incident response guidance around the **NIST Cybersecurity Framework (CSF) 2.0** six functions:

| CSF 2.0 Function | Role in Incident Response |
|---|---|
| **Govern (GV)** | Establishes cybersecurity risk management strategy, expectations, and policy |
| **Identify (ID)** | Understands current cybersecurity risks; includes continuous improvement (ID.IM) |
| **Protect (PR)** | Safeguards to manage risks and prevent incidents |
| **Detect (DE)** | Finds and analyzes possible attacks and compromises |
| **Respond (RS)** | Takes actions regarding detected cybersecurity incidents |
| **Recover (RC)** | Restores assets and operations affected by incidents |

**Key changes from prior versions:**
- The scope differs significantly from previous versions — NIST acknowledges it is "no longer feasible to capture and maintain all procedural details in a single document" given how rapidly technologies and environments change.
- Incident response is now embedded into enterprise risk management rather than treated as a standalone discipline.
- NIST explicitly recommends formatting procedures into playbooks, referencing CISA's Cybersecurity Incident and Vulnerability Response Playbook as a model.
- Organizations with mature documented procedures reduce **Mean Time to Respond (MTTR) by up to 40%** compared to ad-hoc processes.

**Sources:**
- [NIST SP 800-61r3 Final (PDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- [NIST Incident Response Project](https://csrc.nist.gov/projects/incident-response)
- [Drata: Understanding the NIST Incident Response Guide](https://drata.com/blog/nist-incident-response-guide)
- [Morgan Lewis: NIST Releases Updated Incident Response Guidance](https://www.morganlewis.com/blogs/sourcingatmorganlewis/2025/06/nist-releases-updated-incident-response-guidance-under-its-cybersecurity-framework)

### 1.2 SANS Incident Response Framework

SANS defines a six-phase lifecycle (PICERL):

1. **Preparation** — Tools, training, and procedures
2. **Identification** — Detect and validate incidents
3. **Containment** — Limit the blast radius (short-term and long-term)
4. **Eradication** — Remove the threat
5. **Recovery** — Restore systems to normal operations
6. **Lessons Learned** — Post-incident review and improvement

The SANS Incident Handler's Handbook provides hands-on operational guidance bridging theory and execution. Most open-source playbook collections (including SOCFortress and austinsonger's Incident-Playbook) structure their playbooks around these PICERL phases.

**Source:** [Cynet: Incident Response SANS — The 6 Steps in Depth](https://www.cynet.com/incident-response/incident-response-sans-the-6-steps-in-depth/)

### 1.3 MITRE ATT&CK Mapping to Runbooks

MITRE ATT&CK provides a shared taxonomy of adversary tactics, techniques, and procedures (TTPs). The mapping flow for runbooks is:

```
Technique (e.g., T1003 Credential Dumping)
  -> Detection Rule (Sigma rule with attack.t1003 tag)
    -> Alert (fired when detection matches)
      -> Runbook (prescribes investigation + response steps)
```

**Practical mapping example:**

| ATT&CK Technique | Detection | Response Runbook Steps |
|---|---|---|
| T1003 - OS Credential Dumping | Sigma rule detecting LSASS memory access | 1. Isolate affected host 2. Check for lateral movement 3. Reset compromised credentials 4. Deploy EDR containment |
| T1566 - Phishing | Email gateway alert on suspicious attachment | 1. Quarantine email 2. Check delivery to other recipients 3. Extract IOCs 4. Scan endpoints for payload |
| T1486 - Data Encrypted for Impact | EDR alert on mass file encryption | 1. Network isolate host 2. Identify ransomware variant 3. Check backup integrity 4. Engage IR team |

Palo Alto Networks' Unit 42 MITRE ATT&CK Courses of Action (COA) content pack demonstrates automated mapping of incident response to ATT&CK techniques and sub-techniques.

**Sources:**
- [Graylog: Using MITRE ATT&CK for Incident Response Playbooks](https://graylog.org/post/using-mitre-attck-for-incident-response-playbooks/)
- [Panther: MITRE ATT&CK as an Incident Response Framework](https://panther.com/cyber-explained/mitre-attack-framework-incident-response)
- [Palo Alto Networks: MITRE ATT&CK Courses of Action with Cortex XSOAR](https://www.paloaltonetworks.com/blog/security-operations/playbook-of-the-week-mitre-attck-courses-of-action-with-cortex-xsoar/)
- [austinsonger/Incident-Playbook](https://github.com/austinsonger/Incident-Playbook)

### 1.4 RE&CT (Response & Counter-Tactics) Framework

RE&CT is a knowledge base of **actionable Incident Response techniques**, modeled after the MITRE ATT&CK framework structure. While ATT&CK catalogs offensive techniques, RE&CT catalogs **defensive response actions**.

**Response Stages (columns in the RE&CT matrix):**

| Stage | Description | Example Response Actions |
|---|---|---|
| **Preparation** | Proactive readiness | Take trainings, Raise personnel awareness |
| **Identification** | Detecting and scoping | List victims of security alert, List host vulnerabilities |
| **Containment** | Limiting spread | Block external IP address, Block internal IP address, Delete email message |
| **Eradication** | Removing the threat | Patch vulnerability, Remove rogue network device |
| **Recovery** | Restoring operations | Restore quarantined file, Restore data from backup (14 total actions) |
| **Lessons Learned** | Post-incident improvement | Develop incident report, Conduct lessons learned exercise (2 actions) |

**Response Action Categories:** General, Network, Email, File, Process, Configuration, Identity

**Key use cases for RunbookPilot:**
- **Gap analysis** — Visualize coverage of existing IR capabilities using the RE&CT Navigator (green = available, red = unavailable)
- **Playbook construction** — Response Playbooks are composed of atomic Response Actions
- **MITRE ATT&CK linkage** — Response Actions can be linked to specific ATT&CK techniques, creating a Technique -> Detection -> Response Action chain

**Sources:**
- [RE&CT Framework Official](https://atc-project.github.io/atc-react/)
- [GitHub: atc-project/atc-react](https://github.com/atc-project/atc-react)
- [Senthorus: RE&CT Framework Blog](https://blog.senthorus.ch/posts/react_framework/)
- [IEM Labs: The Role of RE&CT Framework in Cybersecurity](https://iemlabs.com/blogs/rect/)

### 1.5 Typical Runbook Structure

Based on industry templates and standards, a well-structured runbook includes:

```
RUNBOOK: [Alert/Incident Type Name]
├── Metadata
│   ├── Author, Version, Last Updated
│   ├── MITRE ATT&CK Mapping (Tactic + Technique IDs)
│   ├── Severity Level
│   └── SLA / Expected Response Time
├── Trigger Conditions
│   ├── Alert source (SIEM rule, EDR, etc.)
│   └── Matching criteria
├── Triage / Decision Tree
│   ├── Is this a true positive? (enrichment steps)
│   ├── What is the scope/blast radius?
│   └── Escalation criteria
├── Investigation Steps
│   ├── Data collection (logs, artifacts)
│   ├── IOC extraction and lookup
│   └── Timeline reconstruction
├── Containment Actions
│   ├── Short-term (isolate host, block IP)
│   └── Long-term (firewall rules, credential reset)
├── Eradication Steps
│   ├── Remove malware/artifacts
│   └── Patch vulnerabilities
├── Recovery Steps
│   ├── Restore from backup
│   └── Monitor for reoccurrence
├── Escalation Criteria
│   ├── When to escalate to Tier 2/3
│   ├── When to engage leadership
│   └── When to contact legal/compliance
└── Post-Incident
    ├── Documentation requirements
    └── Lessons learned trigger
```

**Five principles of a trustworthy runbook (Rootly):** Actionable, Accessible, Accurate, Authoritative, Adaptable.

**Sources:**
- [Rootly: Incident Response Runbook Template 2025](https://rootly.com/blog/incident-response-runbook-template-2025-step-by-step-guide-real-world-examples)
- [Christian Emmer: An Effective Incident Runbook Template](https://emmer.dev/blog/an-effective-incident-runbook-template/)
- [Atlassian: How to Create an Incident Response Playbook](https://www.atlassian.com/incident-management/incident-response/how-to-create-an-incident-response-playbook)

---

## 2. Runbook Schema Design

### 2.1 OASIS CACAO (Collaborative Automated Course of Action Operations)

CACAO is the most comprehensive standard for machine-readable security playbooks. Version 2.0 was approved as an OASIS Committee Specification in November 2023.

**CACAO v2.0 Core Object Classes:**

| Object | Purpose |
|---|---|
| **Playbook** | Top-level container with metadata, workflow, and references |
| **Workflow Steps** | Building blocks: start, end, action, conditional, loop, parallel, switch, playbook-action |
| **Commands** | Executable instructions within steps |
| **Agents** | Entities that execute commands |
| **Targets** | Systems/resources that commands act upon |
| **Authentication** | Credential types for secure execution |
| **Extensions** | Custom objects for vendor-specific capabilities |
| **Data Markings** | TLP and access control labels |
| **Digital Signatures** | Integrity and authenticity verification |

**CACAO v2.0 Workflow Step Types:**

| Step Type | Description |
|---|---|
| `start` | Entry point of the playbook |
| `end` | Terminal step |
| `action` | Executes one or more commands |
| `conditional` | If-then-else branching based on boolean expression |
| `loop` | Repeated execution while condition is true |
| `parallel` | Concurrent execution of multiple step branches |
| `switch` | Multi-way branching (like a case/switch statement) |
| `playbook-action` | Invokes another CACAO playbook (composition) |

**CACAO Playbook JSON Structure (simplified):**

```json
{
  "type": "playbook",
  "spec_version": "cacao-2.0",
  "id": "playbook--uuid",
  "name": "Ransomware Response Playbook",
  "description": "Response procedures for ransomware incidents",
  "playbook_types": ["investigation", "remediation"],
  "created_by": "identity--uuid",
  "created": "2026-01-15T10:00:00Z",
  "modified": "2026-01-15T10:00:00Z",
  "valid_from": "2026-01-15T10:00:00Z",
  "labels": ["ransomware", "t1486"],
  "severity": 90,
  "workflow_start": "start--uuid",
  "workflow": {
    "start--uuid": {
      "type": "start",
      "on_completion": "action--uuid-1"
    },
    "action--uuid-1": {
      "type": "action",
      "name": "Isolate affected host",
      "commands": [
        {
          "type": "http-api",
          "command": "POST /api/v1/hosts/{host_id}/contain"
        }
      ],
      "on_completion": "conditional--uuid-1"
    },
    "conditional--uuid-1": {
      "type": "if-condition",
      "condition": "severity > 80",
      "on_true": "action--uuid-2",
      "on_false": "action--uuid-3"
    },
    "end--uuid": {
      "type": "end"
    }
  },
  "agent_definitions": {},
  "target_definitions": {},
  "extension_definitions": {}
}
```

**Identifiers** follow RFC 4122 UUIDs in the form `object-type--UUID`.

**CACAO Adoption Status (2025-2026):**
- Approved as OASIS Committee Specification
- JSON schemas available open-source: [oasis-open/cacao-json-schemas](https://github.com/oasis-open/cacao-json-schemas)
- MISP has CACAO integration support
- Research emerging on LLM-assisted conversion of legacy playbooks to CACAO format
- BPMN-to-CACAO and CACAO-to-BPMN mapping established in academic research

**Sources:**
- [CACAO Security Playbooks v2.0 Specification](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html)
- [CACAO JSON Schemas (GitHub)](https://github.com/cyentific-rni/cacao-json-schemas)
- [OASIS CACAO TC](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=cacao)
- [LLM-Assisted Transformation of Playbooks into CACAO Format](https://arxiv.org/html/2508.03342v1)
- [Standardized Security Orchestration with CACAO - OASIS Blog](https://www.oasis-open.org/2023/12/06/cacao-security-playbooks-v2-blog/)

### 2.2 COPS (Collaborative Open Playbook Standard)

COPS was created by Demisto (now Cortex XSOAR) as an open standard for sharing playbooks. It uses YAML v1.2 for human readability combined with complex data structure support.

**COPS YAML Schema Key Fields:**

```yaml
id: "unique-playbook-id"
version: 1
name: "Phishing Incident Response"
description: "Runbook for handling phishing alerts"
starttaskid: "task-uuid-1"
tasks:
  task-uuid-1:
    taskid: "task-uuid-1"           # Global unique ID (UUID)
    type: "title"                    # title | regular | condition
    name: "Initial Triage"
    nexttasks:
      '#default#':
        - "task-uuid-2"
  task-uuid-2:
    taskid: "task-uuid-2"
    type: "regular"                  # Script or manual task
    name: "Extract IOCs from email"
    scriptName: "ExtractIOCs"
    nexttasks:
      '#default#':
        - "task-uuid-3"
  task-uuid-3:
    taskid: "task-uuid-3"
    type: "condition"                # Decision branching
    name: "Is IOC known malicious?"
    conditions:
      - label: "yes"
        condition:
          - - operator: "isEqualString"
              left: "IOC.reputation"
              right: "malicious"
      - label: "no"
    nexttasks:
      "yes":
        - "task-uuid-4"
      "no":
        - "task-uuid-5"
```

**Task types:** `title` (section header), `regular` (script or manual task), `condition` (branching logic).

**Source:** [GitHub: demisto/COPS](https://github.com/demisto/COPS)

### 2.3 SOAR Platform Internal Formats

#### Cortex XSOAR (Palo Alto Networks)
- Uses the COPS YAML-based format internally
- Playbooks stored as Unified YAML files containing metadata, code, images
- Context system for passing data between tasks (one task stores output, next reads it)
- Exports/imports in COPS format for sharing
- Content repository: [github.com/demisto/content](https://github.com/demisto/content)

#### Tines
- **Stories** are the unit of automation (equivalent to playbooks)
- Exported as **JSON** containing schema_version, standard_lib_version, action_runtime_version, name, description
- **Action Types:**
  - `HTTP Request` — API calls to external services
  - `Event Transformation` — Data manipulation and formatting
  - `Trigger` — Conditional routing based on rules (compare incoming value against test value)
  - `Webhook` — Ingest external events into a story
  - `Send Email` — Email notifications
  - `Send to Story` — Sub-playbook invocation
- Event-based data flow: each action emits events that downstream actions consume
- No Python scripting required — connects to any API via generic HTTP request agent

**Source:** [Tines API: Story Export](https://www.tines.com/api/stories/export/)

#### Shuffle (Open Source SOAR)
- Workflows use **applications** (integrations), **triggers** (event sources), **conditions** (branching), and **variables**
- Apps auto-generated from **OpenAPI specifications** or built using Shuffle's Python SDK
- Each app creation produces: an OpenAPI spec, Python code via the App SDK, and a Docker image
- Over 11,000+ API endpoints available through OpenAPI integration
- Fully open-source: workflows, apps, and standards (OpenAPI, Swagger)

**Source:** [GitHub: Shuffle/Shuffle](https://github.com/Shuffle/Shuffle)

### 2.4 BPMN (Business Process Model and Notation)

BPMN 2.0 is a standardized graphical notation for business processes that has been applied to security playbooks:

- Provides visual representation accessible to both technical and non-technical personnel
- Research has established a **CACAO-to-BPMN mapping** allowing two-way conversion
- IACD (Integrated Adaptive Cyber Defense) publishes workflow examples as BPMN v2.0 XML files
- BPMN tools can be used for runbook visualization while CACAO handles machine execution

**Sources:**
- [Reviewing BPMN as Modeling Notation for CACAO Security Playbooks](https://arxiv.org/pdf/2305.18928)
- [GitHub: cyentific-rni/bpmn-cacao](https://github.com/cyentific-rni/bpmn-cacao)
- [IACD Playbook and Workflow Examples](https://www.iacdautomate.org/playbook-and-workflow-examples)

### 2.5 Ideal Runbook Schema for RunbookPilot

Based on the analysis of all formats above, an ideal schema should combine CACAO's rigor with YAML's readability:

```yaml
# RunbookPilot Schema v1.0 (Conceptual)
runbook:
  id: "rb-uuid"
  spec_version: "runbookpilot-1.0"
  name: "Credential Dumping Response"
  description: "Response for LSASS credential access alerts"

  # Metadata
  metadata:
    author: "SOC Team"
    version: 3
    created: "2026-01-15T10:00:00Z"
    modified: "2026-02-01T14:30:00Z"
    severity: "high"
    sla_minutes: 30
    tags: ["credential-access", "t1003", "windows"]
    mitre_attack:
      tactics: ["TA0006"]
      techniques: ["T1003", "T1003.001"]
    react_actions: ["RA2001", "RA3001", "RA3004"]
    cacao_playbook_ref: "playbook--uuid"  # Link to formal CACAO version

  # What triggers this runbook
  triggers:
    - source: "sigma"
      rule_id: "sigma-rule-uuid"
      rule_name: "LSASS Memory Access"
      confidence_threshold: 0.7
    - source: "edr"
      vendor: "crowdstrike"
      event_type: "ProcessAccess"
      target_process: "lsass.exe"

  # Input variables from alert context
  inputs:
    - name: "host_id"
      type: "string"
      required: true
      source: "alert.host.id"
    - name: "process_name"
      type: "string"
      required: true
      source: "alert.process.name"
    - name: "user_name"
      type: "string"
      required: false
      source: "alert.user.name"

  # Workflow steps
  steps:
    - id: "step-1"
      name: "Enrich Host Context"
      type: "action"
      automation_level: "full"        # full | assisted | manual
      description: "Gather host details and asset criticality"
      actions:
        - integration: "cmdb"
          command: "get_asset_details"
          params:
            host_id: "{{ inputs.host_id }}"
        - integration: "edr"
          command: "get_host_info"
          params:
            host_id: "{{ inputs.host_id }}"
      outputs:
        - name: "asset_criticality"
          path: "cmdb.response.criticality"
        - name: "host_os"
          path: "edr.response.os_version"
      on_success: "step-2"
      on_failure: "step-2"  # Continue even if enrichment partially fails

    - id: "step-2"
      name: "Validate True Positive"
      type: "decision"
      automation_level: "assisted"    # AI suggests, human confirms
      description: "Determine if this is a legitimate credential access"
      decision_criteria:
        - condition: "process_name in known_admin_tools"
          label: "Known Admin Tool"
          action: "step-fp-close"
        - condition: "asset_criticality == 'critical' AND confidence > 0.8"
          label: "High-confidence on critical asset"
          action: "step-3-escalated"
        - condition: "confidence < 0.5"
          label: "Low confidence"
          action: "step-fp-review"
      ai_guidance:
        prompt: "Analyze the process context and determine if this LSASS access is malicious or benign"
        context_needed: ["process_tree", "user_history", "host_baseline"]
        confidence_display: true
      human_approval_required: true   # HITL checkpoint
      timeout_minutes: 15
      escalation_on_timeout: "step-3-escalated"

    - id: "step-3"
      name: "Contain Affected Host"
      type: "action"
      automation_level: "assisted"
      description: "Network-isolate the host to prevent lateral movement"
      risk_assessment:
        blast_radius: "single_host"
        reversible: true
        business_impact_check: true
      actions:
        - integration: "edr"
          command: "contain_host"
          params:
            host_id: "{{ inputs.host_id }}"
            isolation_level: "network"
      human_approval_required: true   # Containment requires human approval
      approval_context:
        show: ["asset_criticality", "business_owner", "active_sessions"]
        warn_if: "asset_criticality == 'critical'"
      on_success: "step-4"

    - id: "step-4"
      name: "Investigate Lateral Movement"
      type: "parallel"
      automation_level: "full"
      branches:
        - name: "Check auth logs"
          actions:
            - integration: "siem"
              command: "search"
              query: "user={{ user_name }} event_type=authentication last_24h"
        - name: "Check network connections"
          actions:
            - integration: "ndr"
              command: "get_connections"
              params:
                host_id: "{{ inputs.host_id }}"
                timeframe: "24h"
        - name: "Check for IOCs"
          actions:
            - integration: "threat_intel"
              command: "lookup_indicators"
              params:
                indicators: "{{ extracted_iocs }}"
      on_all_complete: "step-5"

  # Escalation rules
  escalation:
    tier2_criteria:
      - "asset_criticality == 'critical'"
      - "lateral_movement_detected == true"
      - "analyst_confidence < 0.6"
    tier3_criteria:
      - "data_exfiltration_indicators == true"
      - "multiple_hosts_affected > 5"
    executive_criteria:
      - "ransomware_indicators == true"
      - "pii_exposure == true"
    notification_channels:
      - type: "slack"
        channel: "#soc-alerts"
      - type: "pagerduty"
        service: "soc-oncall"

  # Audit trail requirements
  audit:
    log_all_actions: true
    log_ai_recommendations: true
    log_human_decisions: true
    retention_days: 365
    compliance_frameworks: ["SOC2", "NIST-CSF"]
```

---

## 3. Human-in-the-Loop Decision Points

### 3.1 What MUST Involve a Human

Based on research across EC-Council, Rapid7, and multiple SOAR vendor publications:

**High-risk / irreversible actions:**
- Host isolation of production/critical systems
- Account disablement or credential resets for VIPs/service accounts
- Firewall rule changes affecting production traffic
- Data destruction or quarantine decisions
- Network segment isolation
- Communication to external parties (customers, regulators, law enforcement)

**Judgment-dependent decisions:**
- True positive vs. false positive determination (edge cases)
- Risk acceptance decisions
- Scope assessment (single host vs. enterprise-wide breach)
- Evidence handling and chain of custody decisions
- Regulatory compliance decisions (when to notify, what to report)
- Intent assessment (insider threat vs. compromised account)

**Business context decisions:**
- Response actions during maintenance windows
- Actions affecting revenue-generating systems
- Customer-facing system containment
- M&A-sensitive information handling

**Sources:**
- [EC-Council: Human in the Loop IR — Balancing AI Automation with Control and Compliance](https://www.eccouncil.org/cybersecurity-exchange/cyber-talks/human-in-the-loop-ir-balancing-ai-automation-with-control-and-compliance/)
- [Rapid7: What is Human-in-the-Loop (HITL) in Cybersecurity?](https://www.rapid7.com/fundamentals/human-in-the-loop/)

### 3.2 What Can Safely Be Automated

**Low-risk enrichment (full automation):**
- IOC lookups against threat intelligence feeds
- WHOIS / DNS / GeoIP lookups
- VirusTotal / sandbox submissions
- Asset/CMDB enrichment
- User profile and group membership lookups
- Historical alert context retrieval
- Log aggregation and timeline construction

**Notification and documentation (full automation):**
- Ticket creation in ITSM systems
- Slack/Teams alert notifications
- SLA timer initiation
- Evidence collection and preservation snapshots
- Alert deduplication and correlation

**Low-impact containment (automation with guardrails):**
- Email quarantine (reversible)
- Tagging assets as under investigation
- Adding IOCs to blocklists (with auto-expiry)
- Disabling non-privileged user accounts (with auto-re-enable timer)

**Sources:**
- [Palo Alto Networks: Automating IOC Enrichment](https://www.paloaltonetworks.com/blog/security-operations/security-orchestration-use-case-automating-ioc-enrichment/)
- [Swimlane: How to Build an Incident Response Playbook](https://swimlane.com/blog/incident-response-playbook/)

### 3.3 Confidence Scoring Models

A confidence score is a probabilistic indicator (typically 0.0 to 1.0) reflecting how certain the system is about its assessment. The scoring model should consider multiple dimensions:

**Proposed Confidence Score Framework:**

```
Final Confidence = w1(Detection_Confidence) + w2(Enrichment_Confidence)
                 + w3(Historical_Accuracy) + w4(Context_Match)

Where:
- Detection_Confidence: Sigma rule fidelity score + alert source reliability
- Enrichment_Confidence: Number of corroborating IOCs / threat intel matches
- Historical_Accuracy: Past true positive rate for this alert type
- Context_Match: How well this alert matches known attack patterns
```

**Action Thresholds:**

| Confidence Range | Action | Human Involvement |
|---|---|---|
| 0.9 - 1.0 | Auto-execute full runbook | Notify only (async review) |
| 0.7 - 0.9 | Auto-enrich, suggest containment | Human approves containment |
| 0.5 - 0.7 | Auto-enrich only | Human reviews and decides |
| 0.3 - 0.5 | Flag for manual review | Human investigates fully |
| 0.0 - 0.3 | Auto-close with documentation | Periodic batch review |

**Dynamic threshold adjustment:** Rather than static severity levels, the escalation matrix should operate on a dynamic, context-driven hierarchy that considers asset importance, user behavior, threat intelligence, and historical reliability of the detection source.

**Sources:**
- [Multimodal: Using Confidence Scoring to Reduce Risk in AI-Driven Decisions](https://www.multimodal.dev/post/using-confidence-scoring-to-reduce-risk-in-ai-driven-decisions)
- [Torq: Threat Escalation Matrix for Modern Security Challenges](https://torq.io/blog/escalation-matrix/)
- [Defy Security: AI-SOC Readiness — Preparing for Autonomous Triage](https://defysecurity.com/ai-soc-readiness-preparing-for-autonomous-triage/)

### 3.4 Risk-Based Automation

**Asset criticality scoring factors:**
- Business function dependency (revenue-generating, customer-facing)
- Data sensitivity (PII, PHI, financial data, trade secrets)
- Network position (internet-facing, domain controller, jump server)
- Compliance scope (PCI DSS, HIPAA, SOX)
- Number of dependent systems (blast radius if taken offline)

**Blast radius analysis considerations:**
- How far could an attacker move laterally from this asset?
- What systems or data could be affected?
- What operational consequences would result from containment?
- Are there dependent services that would be disrupted?

**Risk-adjusted automation decision matrix:**

```
IF asset_criticality == "low" AND confidence >= 0.8:
    -> Auto-contain (notify analyst)
IF asset_criticality == "medium" AND confidence >= 0.9:
    -> Auto-contain (notify analyst)
IF asset_criticality == "high" AND confidence >= 0.95:
    -> Recommend containment (require analyst approval)
IF asset_criticality == "critical":
    -> ALWAYS require human decision regardless of confidence
```

**Sources:**
- [VikingCloud: The Future of Risk-Based Security](https://www.vikingcloud.com/blog/the-future-of-risk-based-security-automation-ai-and-the-evolving-threat-landscape)
- [Swimlane: Risk-Based Vulnerability Management](https://swimlane.com/blog/risk-based-vulnerability-management/)

### 3.5 Automation Failures: Lessons from Real-World Incidents

**CrowdStrike Falcon Outage (July 19, 2024):**
A routine sensor configuration update pushed at 04:09 UTC triggered a logic error that blue-screened critical Windows systems worldwide, impacting airports, banks, media outlets, and hospitals. Root cause: a mismatch between IPC Template Type defining 21 input fields and sensor code providing only 20, causing an out-of-bounds memory read. This was not a malicious containment error, but it demonstrates the catastrophic blast radius when automated security tooling acts without adequate validation.

**Key patterns of automation failures in SOC context:**
- **False positive auto-containment:** Automated systems isolating server networks based on false positive detections, creating blockages preventing employees from working and causing major productivity disruptions.
- **Playbook drift:** Playbooks that fire based on stale context or outdated asset information can contain the wrong host or apply the wrong severity response.
- **Noisy detection auto-remediation:** Without guardrails, a noisy false positive can trigger production downtime.
- **Missing business context:** Automation that does not account for maintenance windows, change freezes, or business-critical periods.

**Safeguards for RunbookPilot:**
1. Always confirm sample is malicious before containment
2. Implement "dry run" mode for new playbooks
3. Track false positive rates per detection rule and adjust automation thresholds
4. Include blast radius assessment before any containment action
5. Implement auto-rollback timers for reversible actions
6. Maintain allowlists for critical assets requiring human approval
7. Regular audit of playbook accuracy and outcomes

**Sources:**
- [Splunk: SOC Automation — How to Automate Without Breaking Things](https://www.splunk.com/en_us/blog/learn/soc-automation.html)
- [CrowdStrike Outage Analysis](https://www.techtarget.com/whatis/feature/Explaining-the-largest-IT-outage-in-history-and-whats-next)
- [Dropzone AI: Complete Guide to Incident Response Automation](https://www.dropzone.ai/resource-guide/automate-incident-response-ai-soc-guide)

---

## 4. AI/LLM in Incident Response

### 4.1 Current State (2025-2026)

LLMs and autonomous AI agents have shown strong potential in SOC operations. Key developments:

**Simbian AI SOC LLM Benchmark (June 2025):**
- Industry's first comprehensive benchmark for LLM performance in SOCs
- Tested top-tier models from Anthropic, OpenAI, Google, and DeepSeek
- Results: Models completed 61%-67% of alert investigation tasks
- Key finding: **Generalist models outperform specialists** — a model good at both coding and logical reasoning (like Sonnet 3.5) outperforms a pure code specialist or pure reasoning specialist
- Specialization (SOC-specific fine-tuning or multi-model ensemble) yields highest performance

**CORTEX Multi-Agent Research (October 2025):**
- A divide-and-conquer multi-agent architecture for SOC triage
- **Orchestrator Agent** manages the pipeline and enforces coherent handoffs
- **Behavior Analysis Agent** inspects activity sequences and routes to relevant workflows
- **Evidence Acquisition Agents** query external systems to ground hypotheses
- **Reasoning Agent** synthesizes findings into auditable decisions
- Substantially reduces false positives vs. single-agent LLMs

**Industry Performance Claims:**
- SOC analysts handle ~4,484 alerts daily on average
- Up to 78% of triage decisions can be automated using LLMs
- LLMs reduce average per-alert processing time by 40%
- Investigation that takes a human analyst 20-40 minutes can be completed by AI in seconds to minutes
- AI SOC Championship 2025: AI performed better than 95% of human participants

**Sources:**
- [Simbian: AI in the SOC — Benchmarking LLMs for Autonomous Alert Triage](https://simbian.ai/blog/the-first-ai-soc-llm-benchmark)
- [CORTEX: Collaborative LLM Agents for High-Stakes Alert Triage](https://arxiv.org/html/2510.00311v1)
- [MDPI: AI-Augmented SOC — A Survey of LLMs and Agents](https://www.mdpi.com/2624-800X/5/4/95)
- [Large Language Models for Security Operations Centers — Comprehensive Survey](https://arxiv.org/abs/2509.10858)

### 4.2 Use Cases for RunbookPilot

| Use Case | Description | Maturity |
|---|---|---|
| **Alert Summarization** | Condense multi-source alert data into human-readable narrative | High — production-ready |
| **IOC Extraction** | Extract indicators from unstructured text (reports, emails, logs) | High — well-established |
| **Runbook Suggestion** | Given an alert, recommend the most appropriate runbook | Medium — needs metadata mapping |
| **Response Recommendation** | Suggest next investigation/containment steps based on context | Medium — needs guardrails |
| **Timeline Reconstruction** | Synthesize logs from multiple sources into chronological narrative | Medium — accuracy varies |
| **Report Generation** | Auto-generate incident reports from investigation data | High — strong fit for LLMs |
| **Threat Intelligence Correlation** | Match observed TTPs against known threat actor profiles | Medium — requires RAG pipeline |
| **Playbook Optimization** | Analyze historical runbook executions and suggest improvements | Low — emerging capability |

### 4.3 Limitations and Risks

**Hallucination risks in security context:**
- LLMs can generate confident but incorrect IOC attributions
- False correlation between unrelated events can lead analysts astray
- Fabricated technical details (e.g., CVE numbers that do not exist) can waste investigation time
- Particularly dangerous when LLM output directly drives automated containment actions

**Mitigation strategies for RunbookPilot:**
1. **Never use LLM output to directly trigger containment** — always route through human approval for consequential actions
2. **Ground responses in retrieved evidence** — use RAG (Retrieval-Augmented Generation) to ensure recommendations are backed by actual logs and threat intel
3. **Display confidence indicators** — show the LLM's uncertainty level alongside every recommendation
4. **Verify factual claims** — cross-reference LLM-generated IOCs, CVEs, and ATT&CK mappings against authoritative databases
5. **Audit trail everything** — log all prompts, responses, confidence scores, and human decisions

**Trust calibration:**
- Start with LLM as "advisor" mode only (no autonomous action)
- Gradually increase automation level based on measured accuracy over time
- Different trust levels per runbook type (higher for enrichment, lower for containment)
- Regular "red team" testing of LLM recommendations

### 4.4 Making LLM Suggestions Auditable

For compliance with frameworks like SOC 2, NIST CSF, ISO 27001:

**Required audit trail components:**

```
{
  "audit_record": {
    "timestamp": "2026-02-10T14:30:00Z",
    "incident_id": "INC-2026-001234",
    "runbook_id": "rb-credential-dumping-v3",
    "step_id": "step-2",
    "action_type": "ai_recommendation",
    "ai_model": {
      "provider": "anthropic",
      "model_id": "claude-sonnet-4",
      "model_version": "2025-12-01"
    },
    "input_context": {
      "alert_data": "...(sanitized)",
      "enrichment_data": "...(sanitized)",
      "prompt_template_id": "triage-assessment-v2"
    },
    "ai_output": {
      "recommendation": "This appears to be credential dumping via Mimikatz...",
      "confidence_score": 0.87,
      "suggested_actions": ["contain_host", "reset_credentials"],
      "reasoning": "Process tree shows lsass.exe accessed by unknown binary..."
    },
    "human_decision": {
      "analyst_id": "analyst-jdoe",
      "decision": "approved_containment",
      "override_reason": null,
      "decision_timestamp": "2026-02-10T14:32:15Z"
    }
  }
}
```

**Key principles:**
- Log all queries, responses, confidence scores, and escalation decisions with timestamps and unique identifiers
- Model versioning ensures traceability of system behavior to specific model iterations
- Explainability features provide transparency into decision-making processes
- Store logs securely with privacy regulation compliance
- Implement content provenance and signing for AI-generated recommendations

**Sources:**
- [Haptik: How to Address Key LLM Challenges](https://www.haptik.ai/tech/llm-challenges-hallucination-security-ethics-compliance)
- [Splunk: LLM Observability Explained](https://www.splunk.com/en_us/blog/learn/llm-observability.html)
- [FINOS AI Governance Framework](https://air-governance-framework.finos.org/)

---

## 5. Integration Points

### 5.1 SOC Tool Integration Architecture

```
                    ┌─────────────────────────────────┐
                    │         RunbookPilot             │
                    │    (Orchestration Engine)        │
                    └──────────┬──────────────────────┘
                               │
        ┌──────────┬───────────┼───────────┬──────────────┐
        │          │           │           │              │
   ┌────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼─────┐ ┌─────▼──────┐
   │  SIEM  │ │  EDR   │ │ Threat │ │Ticketing│ │  Sandbox   │
   │        │ │        │ │ Intel  │ │         │ │            │
   │Splunk  │ │CrowdSt │ │MISP   │ │Jira/SN  │ │VirusTotal │
   │Elastic │ │SentinelOne│OTXMTIP│ │PagerDuty│ │AnyRun     │
   │MS Sent.│ │Defender│ │        │ │         │ │Hybrid An. │
   └────────┘ └────────┘ └────────┘ └─────────┘ └────────────┘
```

### 5.2 Required Integration Categories

| Category | Tools | API Pattern | Data Flow |
|---|---|---|---|
| **SIEM** | Splunk, Elastic, Microsoft Sentinel | REST API, Webhooks | Alerts IN, Searches OUT |
| **EDR** | CrowdStrike, SentinelOne, Defender | REST API | Telemetry IN, Containment OUT |
| **SOAR** | XSOAR, Shuffle, Tines | REST API, Webhooks | Bidirectional orchestration |
| **Ticketing** | Jira, ServiceNow, PagerDuty | REST API, Webhooks | Ticket creation OUT, Updates IN |
| **Threat Intel** | MISP, OTX, VirusTotal, AbuseIPDB | REST API | IOC lookups OUT, Reputation IN |
| **Sandbox** | VirusTotal, Any.Run, Hybrid Analysis | REST API | Sample submission OUT, Report IN |
| **Identity** | Active Directory, Okta, Azure AD | REST API, LDAP | User lookup, Account actions |
| **Network** | Firewalls, NDR, DNS | REST API, SSH/CLI | Containment OUT, NetFlow IN |
| **Communication** | Slack, Teams, Email | REST API, Webhooks | Notifications OUT |

### 5.3 API Patterns

**Common patterns across security tools:**

1. **REST APIs** — Primary integration method. SOAR platforms use REST to pull data from and push actions to security tools. OAuth or API key authentication.

2. **Webhooks** — Real-time, event-driven automation. Instant notification when events occur, removing polling delays. Used for alert forwarding from SIEM to RunbookPilot.

3. **Streaming** — For high-volume data (SIEM log feeds, EDR telemetry). Technologies include Kafka, WebSocket, Server-Sent Events.

4. **Data normalization** — Use standard formats (CEF, ECS, OCSF) for consistent data handling across vendors. Custom parsers convert non-standard logs into structured formats.

**Source:** [TechTarget: A Leader's Guide to Integrating EDR, SIEM, and SOAR](https://www.techtarget.com/searchsecurity/tip/A-leaders-guide-to-integrating-EDR-SIEM-and-SOAR)

### 5.4 Alert-to-Runbook Mapping (DetectForge Integration)

This is a critical pipeline connecting DetectForge (detection rule generation) to RunbookPilot (response automation):

```
DetectForge Pipeline:
  Threat Report → Sigma Rule (with ATT&CK tags)

RunbookPilot Pipeline:
  Sigma Rule fires → Alert with ATT&CK context → Runbook Selection → Execution

Mapping Logic:
  1. Sigma rule includes tags: ["attack.credential_access", "attack.t1003"]
  2. Alert inherits these tags when the rule fires
  3. RunbookPilot matches tags against runbook triggers:
     - Primary match: Exact technique ID (T1003)
     - Secondary match: Tactic category (credential_access)
     - Tertiary match: Alert source type + severity
  4. If multiple runbooks match, rank by:
     - Specificity (technique > tactic > generic)
     - Asset context (different runbooks for servers vs. workstations)
     - Historical effectiveness (past resolution rate)
```

**Sigma rule tag structure for mapping:**
- Tags follow format: `attack.tactic_name` and `attack.tXXXX`
- Over 3,000 Sigma rules in the SigmaHQ repository with ATT&CK mappings
- Tools like S2AN can map Sigma rules to ATT&CK Navigator for coverage visualization

**Sources:**
- [SigmaHQ: Rules Documentation](https://sigmahq.io/docs/basics/rules.html)
- [Graylog: Threat Detection and Incident Response with MITRE ATT&CK and Sigma Rules](https://graylog.org/post/tdir-mitre-attck-and-sigma-rules/)
- [GitHub: 3CORESec/S2AN](https://github.com/3CORESec/S2AN)

---

## 6. Open Source Runbook Resources

### 6.1 Major Open Source Collections

#### Incident Response Consortium (IRC)
- **URL:** [incidentresponse.com](https://www.incidentresponse.com/)
- **Status:** Relaunching in 2025 — "bigger, better, and stronger than ever"
- **Content:** Open-source playbooks, runbooks, and response plans
- **Format:** Downloadable templates for common incident types

#### SOCFortress Playbooks
- **URL:** [github.com/socfortress/Playbooks](https://github.com/socfortress/Playbooks)
- **Content:** Playbooks targeting SOC analysts, structured per NIST 800-61 phases
- **Strengths:** Practical, operator-focused, integrates with Wazuh/Shuffle stack

#### austinsonger Incident-Playbook
- **URL:** [github.com/austinsonger/Incident-Playbook](https://github.com/austinsonger/Incident-Playbook)
- **Content:** Incident response playbooks mapped to MITRE ATT&CK tactics and techniques
- **Goal:** A playbook for every MITRE ATT&CK technique
- **Structure:** Modified SANS/NIST hybrid process with preparation phase
- **Includes:** Playbook templates, exercise scenarios, tool references, checklists, battle cards

#### Demisto/XSOAR Content Repository
- **URL:** [github.com/demisto/content](https://github.com/demisto/content)
- **Content:** Hundreds of playbooks in COPS YAML format
- **Strengths:** Production-tested, integration-rich, community-maintained

#### counteractive Incident Response Plan Template
- **URL:** [github.com/counteractive/incident-response-plan-template](https://github.com/counteractive/incident-response-plan-template)
- **Content:** Complete IR plan template with playbooks for phishing, ransomware, supply chain
- **Format:** Markdown with structured sections

#### CISA Cybersecurity Incident & Vulnerability Response Playbooks
- **URL:** [CISA Playbooks (PDF)](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- **Content:** Federal government incident and vulnerability response procedures
- **Authority:** Official US government guidance, referenced by NIST SP 800-61r3

#### Microsoft Incident Response Playbooks
- **URL:** [Microsoft Learn: Incident Response Playbooks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks)
- **Content:** Playbooks for phishing, password spray, app consent grant, OAuth token theft
- **Strengths:** Microsoft-ecosystem specific, detailed Azure AD/Entra ID procedures

#### MISP Playbooks
- **URL:** [github.com/MISP/misp-playbooks](https://github.com/MISP/misp-playbooks)
- **Content:** Playbooks with CACAO format integration
- **Strengths:** Threat intelligence platform integration

### 6.2 Gap Analysis: What Is Missing from Open Source

| Gap Area | Current State | What's Needed |
|---|---|---|
| **Cloud-native IR** | Few playbooks for AWS/Azure/GCP-specific incidents | Playbooks for cloud IAM compromise, S3 bucket exposure, Lambda abuse, cloud trail tampering |
| **Container/K8s** | Nearly absent — ephemeral containers make traditional playbooks ineffective | Kubernetes pod compromise, container escape, image supply chain attack playbooks |
| **Supply chain** | Templates exist but contain TODO placeholders | Mature playbooks for dependency confusion, CI/CD pipeline compromise, SaaS vendor breach |
| **AI/ML-specific** | Virtually nonexistent | Playbooks for model poisoning, prompt injection on production systems, training data exposure |
| **OT/ICS** | Limited to CISA guidance | Sector-specific playbooks for manufacturing, energy, healthcare OT environments |
| **SaaS application** | Scattered across vendor docs | Unified playbooks for OAuth token abuse, API key compromise, SaaS data exfiltration |
| **Identity-focused** | Basic credential compromise only | Advanced identity attack playbooks: Kerberoasting, Golden Ticket, MFA bypass, directory sync abuse |
| **Machine-readable** | Most are Markdown/PDF (human-only) | CACAO-formatted versions of existing playbooks for automated execution |
| **Runbook-to-detection linkage** | Manual/ad-hoc at best | Systematic mapping between detection rules (Sigma) and response playbooks |
| **Decision tree formalization** | Narrative text descriptions | Structured, machine-parseable decision trees with confidence thresholds |

**Sources:**
- [Wiz: Kubernetes Incident Response Security Playbook](https://www.wiz.io/academy/container-security/kubernetes-incident-response)
- [Sygnia: Incident Response to Cloud Security Incidents](https://www.sygnia.co/blog/incident-response-to-cloud-security-incidents-aws-azure-and-gcp-best-practices/)
- [50 Essential Incident Response Playbooks for Next-Gen SOC Operations](https://undercodetesting.com/50-essential-incident-response-playbooks-for-next-gen-soc-operations-2025-edition/)

---

## 7. Design Implications for RunbookPilot

### 7.1 Architecture Recommendations

Based on all research findings, RunbookPilot should:

1. **Use CACAO v2.0 as the internal schema foundation** — it is the only OASIS-approved standard with workflow step types (conditional, parallel, loop), digital signatures, and extension support. Augment with custom properties for AI guidance, confidence scoring, and HITL checkpoints.

2. **Provide YAML as the user-facing authoring format** — following COPS precedent, YAML is preferred for human readability. Auto-convert YAML to CACAO JSON internally.

3. **Implement a three-tier automation model:**
   - `full` — Automated with async notification
   - `assisted` — AI recommends, human approves
   - `manual` — Human drives, tool assists

4. **Build on the RE&CT framework for response action taxonomy** — use RE&CT's categorized response actions (Network, Email, File, Process, Configuration, Identity) as the vocabulary for runbook steps.

5. **Integrate DetectForge via ATT&CK tags** — Sigma rule tags provide the mapping key from detection to response. This is the core value proposition linking the two tools.

6. **Adopt the CORTEX multi-agent pattern** for AI assistance — separate agents for behavior analysis, evidence gathering, reasoning, and orchestration produce more reliable results than a single monolithic LLM.

### 7.2 Key Differentiators

| Feature | Current Market | RunbookPilot Advantage |
|---|---|---|
| Detection-to-response pipeline | Manual mapping | Auto-links DetectForge Sigma rules to runbooks via ATT&CK tags |
| Schema standard | Proprietary per vendor | CACAO v2.0 based (open standard, portable) |
| AI integration | Vendor-locked LLM | Model-agnostic via OpenRouter, auditable recommendations |
| Human-in-the-loop | Binary (on/off) | Confidence-scored, risk-adjusted, with graduated autonomy |
| Cost | $50K-$500K/yr for SOAR platforms | Open-source core, self-hostable |

### 7.3 Critical Success Factors

1. **Trust calibration** — Start in advisor-only mode. Let analysts build confidence in AI recommendations before enabling any automation. Track accuracy metrics per runbook type.

2. **Blast radius awareness** — Every containment action must include asset criticality check, dependency mapping, and reversibility assessment.

3. **Audit-first design** — Log everything from day one. Every AI recommendation, human decision, and automated action must have a traceable audit record for compliance.

4. **Gradual automation** — Follow Splunk's guidance: automate enrichment first, then low-risk containment, then higher-risk actions only after proven accuracy.

5. **Open source runbook seeding** — Bootstrap the runbook library by converting existing open-source playbooks (austinsonger, SOCFortress, CISA) into the RunbookPilot CACAO-based format.

---

## Appendix A: Key URLs and Resources

### Standards and Specifications
- NIST SP 800-61r3: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- CACAO v2.0 Spec: https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
- CACAO JSON Schemas: https://github.com/oasis-open/cacao-json-schemas
- COPS Standard: https://github.com/demisto/COPS
- RE&CT Framework: https://atc-project.github.io/atc-react/
- BPMN-CACAO Mapping: https://github.com/cyentific-rni/bpmn-cacao

### Open Source Playbook Collections
- Incident Response Consortium: https://www.incidentresponse.com/
- SOCFortress Playbooks: https://github.com/socfortress/Playbooks
- austinsonger Incident-Playbook: https://github.com/austinsonger/Incident-Playbook
- Demisto/XSOAR Content: https://github.com/demisto/content
- counteractive IR Plan Template: https://github.com/counteractive/incident-response-plan-template
- CISA Playbooks: https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
- Microsoft IR Playbooks: https://learn.microsoft.com/en-us/security/operations/incident-response-playbooks

### SOAR Platforms
- Shuffle (Open Source): https://github.com/Shuffle/Shuffle
- Cortex XSOAR: https://xsoar.pan.dev/
- Tines: https://www.tines.com/

### Research Papers
- CORTEX Multi-Agent SOC Triage: https://arxiv.org/html/2510.00311v1
- AI-Augmented SOC Survey: https://www.mdpi.com/2624-800X/5/4/95
- LLMs for SOC Survey: https://arxiv.org/abs/2509.10858
- LLM-Assisted CACAO Transformation: https://arxiv.org/html/2508.03342v1
- BPMN as CACAO Modeling Notation: https://arxiv.org/pdf/2305.18928
- Simbian AI SOC Benchmark: https://simbian.ai/blog/the-first-ai-soc-llm-benchmark

### MITRE Resources
- ATT&CK Framework: https://attack.mitre.org/
- RE&CT GitHub: https://github.com/atc-project/atc-react
- Sigma Rules: https://github.com/SigmaHQ/sigma
- S2AN (Sigma-to-ATT&CK Navigator): https://github.com/3CORESec/S2AN
