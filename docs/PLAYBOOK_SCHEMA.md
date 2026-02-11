# RunbookPilot Playbook Schema Reference

**Schema Version:** 1.0
**Last Updated:** 2026-02-11
**Status:** Specification Document
**Ticket:** S0-004

---

## Table of Contents

1. [Overview](#1-overview)
2. [Schema Version](#2-schema-version)
3. [Complete Field Reference](#3-complete-field-reference)
   - [Root Object](#31-root-object-runbook)
   - [Metadata](#32-metadata)
   - [Triggers](#33-triggers)
   - [Config](#34-config)
   - [Steps](#35-steps)
   - [Rollback Definition](#36-rollback-definition)
4. [Template Syntax](#4-template-syntax)
5. [Validation Rules](#5-validation-rules)
6. [Error Handling Modes](#6-error-handling-modes)
7. [Automation Levels](#7-automation-levels)
8. [StepAction Reference](#8-stepaction-reference)

---

## 1. Overview

RunbookPilot playbooks are YAML-defined incident response workflows. Each playbook specifies metadata, trigger conditions, execution configuration, and an ordered sequence of steps. The schema is designed to be human-readable, machine-validatable, and compatible with the deterministic state machine execution engine.

Playbooks live in the `playbooks/` directory and are validated against this schema at load time using Zod validators. Invalid playbooks are rejected before execution with descriptive error messages.

### Minimal Example

```yaml
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  metadata:
    name: "Minimal Playbook"
    created: "2026-02-11T00:00:00Z"
    updated: "2026-02-11T00:00:00Z"
    tags:
      - "example"
  triggers:
    detection_sources:
      - "manual"
    mitre_techniques:
      - "T1566"
    platforms:
      - "windows"
  config:
    automation_level: "L0"
    max_execution_time: 300
    requires_approval: false
  steps:
    - id: "step-01"
      name: "Collect Logs"
      action: "collect_logs"
      executor: "mock"
      parameters:
        target: "{{ alert.host.hostname }}"
      on_error: "halt"
      timeout: 30
```

---

## 2. Schema Version

**Current Version:** `1.0`

Schema versioning follows semantic versioning:

| Component | Meaning |
|-----------|---------|
| **Major** | Breaking changes to schema structure (fields removed, types changed) |
| **Minor** | Backwards-compatible additions (new optional fields, new enum values) |
| **Patch** | Documentation or validation rule clarifications |

The `version` field in each playbook declares which schema version it targets. The execution engine validates playbooks against the declared version and rejects mismatches.

---

## 3. Complete Field Reference

### 3.1 Root Object: `runbook`

All playbook content is nested under a single `runbook` key at the document root.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `string` (UUID v4) | Yes | Unique identifier for this playbook. Must be a valid UUID v4. |
| `version` | `string` | Yes | Schema version this playbook targets. Currently `"1.0"`. |
| `metadata` | `object` | Yes | Descriptive metadata about the playbook. See [3.2](#32-metadata). |
| `triggers` | `object` | Yes | Conditions under which this playbook should be invoked. See [3.3](#33-triggers). |
| `config` | `object` | Yes | Execution configuration and policy settings. See [3.4](#34-config). |
| `steps` | `array` | Yes | Ordered sequence of execution steps. Min: 1, Max: 50. See [3.5](#35-steps). |

---

### 3.2 Metadata

Descriptive information about the playbook used for indexing, searching, and audit trails.

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `name` | `string` | Yes | 3-100 characters, no leading/trailing whitespace | Human-readable playbook name. Convention: `"TXXXX - Description"`. |
| `description` | `string` | No | No length limit | Detailed description of the playbook's purpose and scope. |
| `author` | `string` | No | No constraints | Author name or email address. |
| `created` | `string` | Yes | ISO 8601 format (e.g., `"2026-01-15T10:00:00Z"`) | Timestamp when the playbook was first created. |
| `updated` | `string` | Yes | ISO 8601 format (e.g., `"2026-01-15T10:00:00Z"`) | Timestamp of the most recent modification. |
| `tags` | `string[]` | Yes | 1-20 tags, each 2-50 characters | Searchable classification tags for filtering and discovery. |
| `references` | `string[]` | No | Valid HTTP/HTTPS URLs | Links to external documentation, threat reports, ATT&CK pages, etc. |

**Example:**

```yaml
metadata:
  name: "T1566.001 - Phishing Email Investigation"
  description: "Initial triage for suspected phishing emails with attachment analysis"
  author: "security-team@example.com"
  created: "2026-01-15T10:00:00Z"
  updated: "2026-02-10T14:30:00Z"
  tags:
    - "phishing"
    - "email"
    - "initial-access"
    - "triage"
  references:
    - "https://attack.mitre.org/techniques/T1566/001/"
    - "https://www.cisa.gov/phishing"
```

---

### 3.3 Triggers

Defines the conditions under which this playbook should be invoked. Used by the matching engine to associate incoming alerts with the correct playbook.

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `detection_sources` | `DetectionSource[]` | Yes | Min: 1 | Alert sources that can trigger this playbook. |
| `mitre_techniques` | `string[]` | Yes | Min: 1, pattern: `^T\d{4}(\.\d{3})?$` | MITRE ATT&CK technique IDs this playbook responds to. |
| `platforms` | `Platform[]` | Yes | Min: 1 | Target platforms where this playbook applies. |
| `severity` | `Severity[]` | No | Valid values only | Optional severity filter. If omitted, matches all severities. |

**DetectionSource enum values:**

| Value | Description |
|-------|-------------|
| `sigma` | Sigma rule detection |
| `edr_alert` | EDR/XDR platform alert |
| `siem_correlation` | SIEM correlation rule match |
| `webhook` | External system webhook |
| `manual` | Manual analyst invocation |
| `detectforge` | DetectForge-generated detection |

**Platform enum values:**

| Value | Description |
|-------|-------------|
| `windows` | Windows endpoints and servers |
| `linux` | Linux endpoints and servers |
| `macos` | macOS endpoints |
| `cloud` | Cloud infrastructure (AWS, Azure, GCP) |
| `network` | Network devices (firewalls, routers, switches) |
| `saas` | SaaS applications (email, identity, collaboration) |

**Severity enum values:**

| Value | Description |
|-------|-------------|
| `low` | Low severity, informational |
| `medium` | Medium severity, warrants investigation |
| `high` | High severity, requires prompt response |
| `critical` | Critical severity, immediate action required |

**Example:**

```yaml
triggers:
  detection_sources:
    - "siem_correlation"
    - "manual"
  mitre_techniques:
    - "T1566.001"
  platforms:
    - "saas"
  severity:
    - "medium"
    - "high"
    - "critical"
```

---

### 3.4 Config

Execution-level configuration controlling automation behavior, timeouts, and approval policies.

| Field | Type | Required | Constraints | Default | Description |
|-------|------|----------|-------------|---------|-------------|
| `automation_level` | `AutomationLevel` | Yes | `L0`, `L1`, or `L2` | N/A | The autonomy level for this playbook. See [Section 7](#7-automation-levels). |
| `max_execution_time` | `number` | Yes | 60-3600 (seconds) | N/A | Maximum wall-clock time for the entire playbook execution. |
| `requires_approval` | `boolean` | Yes | L2 must be `true` | N/A | Whether the playbook requires approval before execution begins. |
| `approval_timeout` | `number` | No | 300-7200 (seconds) | `3600` | Time to wait for approval before auto-escalation. |
| `parallel_execution` | `boolean` | No | N/A | `false` | Whether steps without dependency relationships can execute in parallel. |
| `rollback_on_failure` | `boolean` | No | N/A | `true` | Whether to automatically rollback completed steps on failure. |

**Notes:**
- L2 runbooks **must** have `requires_approval: true`. This is enforced at validation time.
- L0 playbooks typically set `requires_approval: false` since they are recommendation-only.
- When `parallel_execution` is `true`, steps that share no `depends_on` relationships may run concurrently.
- When `rollback_on_failure` is `true`, the engine executes rollback definitions for all completed steps in reverse order upon failure.

**Example:**

```yaml
config:
  automation_level: "L1"
  max_execution_time: 600
  requires_approval: false
  approval_timeout: 1800
  parallel_execution: true
  rollback_on_failure: true
```

---

### 3.5 Steps

Ordered sequence of actions to execute. Each step defines a single action with its executor, parameters, error handling, and optional dependencies.

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `id` | `string` | Yes | Unique within runbook. Recommended pattern: `^step-\d{2}$` | Step identifier used for dependency references and output lookups. |
| `name` | `string` | Yes | 3-100 characters | Human-readable step name displayed in logs and the approval queue. |
| `description` | `string` | No | No length limit | Detailed description of what this step does and why. |
| `action` | `StepAction` | Yes | Must be a valid StepAction value | The action type to execute. See [Section 8](#8-stepaction-reference). |
| `executor` | `string` | Yes | Must be a registered adapter name | The adapter that executes this action (e.g., `"siem"`, `"edr"`, `"threat_intel"`, `"mock"`). |
| `parameters` | `object` | Yes | Supports `{{ template }}` syntax | Action-specific parameters passed to the executor. See [Section 4](#4-template-syntax). |
| `approval_required` | `boolean` | No | N/A | Override the config-level `requires_approval` for this specific step. |
| `rollback` | `object` | No | See [3.6](#36-rollback-definition) | Defines how to undo this step if rollback is triggered. |
| `on_error` | `OnError` | Yes | `halt`, `continue`, or `skip` | Error handling strategy when this step fails. See [Section 6](#6-error-handling-modes). |
| `timeout` | `number` | Yes | 5-600 (seconds) | Maximum execution time for this individual step. |
| `depends_on` | `string[]` | No | All IDs must reference existing steps | Step IDs that must complete successfully before this step can begin. |
| `condition` | `string` | No | Valid JavaScript expression | Guard condition evaluated at runtime. Step is skipped if expression evaluates to `false`. |

**Example:**

```yaml
steps:
  - id: "step-01"
    name: "Query Authentication Logs"
    description: "Pull last 7 days of auth events for the affected user"
    action: "query_siem"
    executor: "splunk"
    parameters:
      query: 'index=authentication user="{{ alert.user.name }}"'
      earliest: "-7d"
      latest: "now"
    on_error: "halt"
    timeout: 60

  - id: "step-02"
    name: "Enrich Source IP"
    action: "enrich_ioc"
    executor: "threat_intel"
    parameters:
      indicator_type: "ip"
      indicator_value: "{{ alert.source.ip }}"
    depends_on:
      - "step-01"
    on_error: "continue"
    timeout: 30
    condition: "steps['step-01'].output.source_ips.length > 0"
```

---

### 3.6 Rollback Definition

Defines how to undo a step's action when rollback is triggered (either by a subsequent step failure or manual cancellation). Rollback is a core safety mechanism in RunbookPilot -- if a write action cannot define a rollback, it should not be auto-executed.

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `action` | `StepAction` | Yes | Must be a valid StepAction value | The rollback action to execute (typically the inverse of the parent step). |
| `executor` | `string` | No | Must be a registered adapter | Adapter to use for rollback. Defaults to the parent step's executor. |
| `parameters` | `object` | Yes | Supports `{{ template }}` syntax | Parameters for the rollback action. |
| `timeout` | `number` | Yes | 5-600 (seconds) | Maximum execution time for the rollback operation. |
| `on_error` | `OnError` | No | `halt`, `continue`, or `skip` | What to do if the rollback itself fails. |

**Example:**

```yaml
- id: "step-03"
  name: "Isolate Host"
  action: "isolate_host"
  executor: "crowdstrike"
  parameters:
    host_id: "{{ alert.host.id }}"
    reason: "Automated containment - {{ alert.rule.name }}"
  rollback:
    action: "restore_connectivity"
    parameters:
      host_id: "{{ alert.host.id }}"
      reason: "Rollback - isolation reversed"
    timeout: 60
    on_error: "halt"
  approval_required: true
  on_error: "halt"
  timeout: 45
```

---

## 4. Template Syntax

RunbookPilot supports Mustache-style template interpolation in step `parameters` fields. Templates are resolved at runtime immediately before each step executes, allowing dynamic values derived from the triggering alert, previous step outputs, execution context, and environment variables.

### 4.1 Template Namespaces

Templates use the `{{ namespace.path }}` syntax with four available namespaces:

#### `alert` -- Triggering Alert Fields

References fields from the ECS-formatted alert that triggered the playbook.

```yaml
parameters:
  hostname: "{{ alert.host.hostname }}"
  username: "{{ alert.user.name }}"
  source_ip: "{{ alert.source.ip }}"
  message_id: "{{ alert.email.message_id }}"
  severity: "{{ alert.event.severity }}"
  rule_name: "{{ alert.rule.name }}"
```

#### `steps` -- Previous Step Outputs

References output data from previously completed steps. The step must be in the `depends_on` chain or must have completed prior to the current step.

```yaml
parameters:
  threat_score: "{{ steps.step-01.output.score }}"
  sender_domain: "{{ steps.step-01.output.sender.domain }}"
  file_count: "{{ steps.step-03.output.file_count }}"
```

#### `context` -- Execution Context Variables

References runtime context variables set by the execution engine or the analyst.

```yaml
parameters:
  analyst_email: "{{ context.analyst_email }}"
  execution_id: "{{ context.execution_id }}"
  ticket_id: "{{ context.ticket_id }}"
```

#### `env` -- Environment Variables

References environment variables from the host system. Used for API keys and secrets that should not be stored in playbook files.

```yaml
parameters:
  api_key: "{{ env.VIRUSTOTAL_API_KEY }}"
  auth_token: "{{ env.IDP_API_TOKEN }}"
  webhook_url: "{{ env.SLACK_WEBHOOK_URL }}"
```

### 4.2 Filters and Expressions

#### Default Values

Use the `| default:` filter to provide a fallback when a template variable is unresolvable:

```yaml
parameters:
  timeout: "{{ alert.timeout | default: 300 }}"
  priority: "{{ alert.event.severity | default: medium }}"
  analyst: "{{ context.analyst_email | default: unassigned@example.com }}"
```

#### Conditional (Ternary) Expressions

Use the ternary operator for inline conditional logic:

```yaml
parameters:
  priority: "{{ alert.event.severity > 80 ? 'critical' : 'high' }}"
  action: "{{ steps.step-02.output.risk_score > 70 ? 'Escalate to L2' : 'Monitor' }}"
  notify: "{{ alert.event.severity > 90 ? 'oncall-page' : 'slack-channel' }}"
```

### 4.3 Template Evaluation Rules

1. Templates are evaluated **at runtime**, immediately before each step executes.
2. Template resolution happens **after** dependency checks and **before** executor invocation.
3. Unresolvable templates without a `| default:` filter cause step failure with error code `RBP-2007`.
4. Templates in `rollback.parameters` are evaluated at rollback time, not at step execution time.
5. Nested template references (templates within templates) are **not supported**.
6. Template values are always resolved to strings. Type coercion to the expected parameter type is handled by the executor.

### 4.4 Template Syntax Summary

| Syntax | Description | Example |
|--------|-------------|---------|
| `{{ alert.field.path }}` | Alert field reference | `{{ alert.host.hostname }}` |
| `{{ steps.ID.output.path }}` | Step output reference | `{{ steps.step-01.output.score }}` |
| `{{ context.variable }}` | Context variable | `{{ context.analyst_email }}` |
| `{{ env.VARIABLE }}` | Environment variable | `{{ env.API_KEY }}` |
| `{{ value \| default: fallback }}` | Default value filter | `{{ alert.timeout \| default: 300 }}` |
| `{{ expr ? 'a' : 'b' }}` | Ternary conditional | `{{ alert.event.severity > 80 ? 'critical' : 'high' }}` |

---

## 5. Validation Rules

The playbook validator enforces these rules at load time. Playbooks that fail validation are rejected before any execution attempt.

### 5.1 Global Rules

| Rule | Description |
|------|-------------|
| All required fields must be present | Missing required fields produce error code `RBP-1001` |
| Timestamps must be valid ISO 8601 | Format: `YYYY-MM-DDTHH:mm:ssZ` or with timezone offset. Invalid timestamps produce `RBP-1002` |
| UUIDs must be valid UUID v4 | Invalid UUIDs produce `RBP-1003` |
| MITRE technique IDs must match pattern | Pattern: `^T\d{4}(\.\d{3})?$` (e.g., `T1566`, `T1566.001`). Invalid IDs produce `RBP-1004` |

### 5.2 Metadata Rules

| Rule | Constraint | Error Code |
|------|-----------|------------|
| `name` length | 3-100 characters | `RBP-1005` |
| `name` whitespace | No leading or trailing whitespace | `RBP-1005` |
| `tags` count | 1-20 tags | `RBP-1006` |
| `tags` length | Each tag 2-50 characters | `RBP-1006` |
| `references` format | Valid HTTP or HTTPS URLs only | `RBP-1007` |

### 5.3 Triggers Rules

| Rule | Constraint | Error Code |
|------|-----------|------------|
| `detection_sources` | At least one source required | `RBP-1008` |
| `detection_sources` values | Must be valid DetectionSource enum values | `RBP-1008` |
| `mitre_techniques` | At least one technique required | `RBP-1009` |
| `mitre_techniques` format | Must match `^T\d{4}(\.\d{3})?$` | `RBP-1009` |
| `platforms` | At least one platform required | `RBP-1008` |
| `platforms` values | Must be valid Platform enum values | `RBP-1008` |
| `severity` values | Must be valid Severity enum values if present | `RBP-1008` |

### 5.4 Config Rules

| Rule | Constraint | Error Code |
|------|-----------|------------|
| `automation_level` | Must be `L0`, `L1`, or `L2` | `RBP-1010` |
| `max_execution_time` | 60-3600 seconds | `RBP-1011` |
| `approval_timeout` | 300-7200 seconds (if provided) | `RBP-1011` |
| L2 approval enforcement | L2 runbooks must have `requires_approval: true` | `RBP-1012` |

### 5.5 Steps Rules

| Rule | Constraint | Error Code |
|------|-----------|------------|
| Step count | At least 1 step, maximum 50 steps | `RBP-1013` |
| `id` uniqueness | All step IDs must be unique within the runbook | `RBP-1014` |
| `id` pattern | Recommended: `^step-\d{2}$` | N/A (warning) |
| `name` length | 3-100 characters | `RBP-1005` |
| `timeout` range | 5-600 seconds | `RBP-1015` |
| `action` value | Must be a valid StepAction enum value | `RBP-1016` |
| `on_error` value | Must be `halt`, `continue`, or `skip` | `RBP-1017` |
| `depends_on` references | All referenced step IDs must exist in the playbook | `RBP-1018` |
| No circular dependencies | Dependency graph must be a DAG (directed acyclic graph) | `RBP-1019` |
| `condition` syntax | Must be a valid JavaScript expression (if provided) | `RBP-1020` |
| Template syntax | All `{{ }}` templates must use valid syntax | `RBP-1010` |

### 5.6 Rollback Rules

| Rule | Constraint | Error Code |
|------|-----------|------------|
| `action` value | Must be a valid StepAction enum value | `RBP-1016` |
| `timeout` range | 5-600 seconds | `RBP-1015` |
| `parameters` required | Rollback parameters must be provided | `RBP-1001` |

---

## 6. Error Handling Modes

Each step declares an `on_error` strategy that determines execution behavior when the step fails.

### `halt`

**Behavior:** Immediately stop playbook execution. No subsequent steps are executed.

**When to use:**
- Critical data collection steps where all downstream steps depend on the output.
- Steps whose failure indicates a fundamental problem (e.g., cannot reach target host).
- First steps in a playbook where failure means the investigation cannot proceed.

**Rollback:** If `rollback_on_failure` is `true` in config, all previously completed steps with rollback definitions are rolled back in reverse order.

```yaml
- id: "step-01"
  name: "Collect Email Metadata"
  action: "collect_logs"
  executor: "email_gateway"
  parameters:
    message_id: "{{ alert.email.message_id }}"
  on_error: "halt"    # Stop everything if we can't get the email
  timeout: 30
```

### `continue`

**Behavior:** Log the error and proceed to the next eligible step. The failed step's output is marked as unavailable.

**When to use:**
- Enrichment steps where partial data is acceptable.
- Non-critical steps whose output enhances but is not required for the investigation.
- Steps with alternative data sources (e.g., multiple threat intel feeds).

**Rollback:** The failed step is skipped during rollback (no action to undo). Previously completed steps are still eligible for rollback.

```yaml
- id: "step-02"
  name: "Enrich Sender Domain"
  action: "check_reputation"
  executor: "threat_intel"
  parameters:
    indicator_value: "{{ steps.step-01.output.sender.domain }}"
  on_error: "continue"    # Enrichment failure is non-fatal
  timeout: 45
```

### `skip`

**Behavior:** Silently skip this step and all steps that depend on it. No error is logged. The step and its dependents are marked as `skipped` in the execution result.

**When to use:**
- Optional enhancement steps that may not apply to all alert types.
- Steps guarded by conditions where the condition evaluation itself may fail.
- Steps targeting optional integrations that may not be configured.

**Rollback:** Skipped steps and their dependents are excluded from rollback.

```yaml
- id: "step-03"
  name: "Check Sandbox Results"
  action: "enrich_ioc"
  executor: "sandbox"
  parameters:
    files: "{{ steps.step-01.output.attachments }}"
  on_error: "skip"    # No sandbox? Just skip attachment analysis
  timeout: 60
```

### Error Handling Flow

```
Step fails
  |
  +-- on_error: "halt"
  |     +-- Stop execution
  |     +-- Trigger rollback (if rollback_on_failure: true)
  |     +-- Set execution state to "failed"
  |
  +-- on_error: "continue"
  |     +-- Log error
  |     +-- Mark step output as unavailable
  |     +-- Proceed to next eligible step
  |
  +-- on_error: "skip"
        +-- Mark step as skipped (no error logged)
        +-- Mark all dependent steps as skipped
        +-- Proceed to next eligible step
```

---

## 7. Automation Levels

RunbookPilot supports three automation levels, each providing a different degree of human-in-the-loop control. The automation level is set at the playbook level via `config.automation_level`.

### L0 -- Manual (Recommendation Only)

**Behavior:** The engine generates a step-by-step checklist for the analyst. No actions are executed automatically. Each step presents the analyst with the action to perform, the parameters to use, and relevant context.

**Use cases:**
- New runbooks being validated before promotion to L1.
- Sensitive investigations requiring full analyst control.
- Training scenarios for junior analysts.
- Organizations with strict change control policies.

**Execution model:**
1. Engine validates and loads the playbook.
2. Each step is presented as a recommendation with pre-populated parameters.
3. Analyst manually performs each action and confirms completion.
4. Engine records analyst actions and timing for audit.

```yaml
config:
  automation_level: "L0"
  max_execution_time: 300
  requires_approval: false    # No approval needed -- nothing is auto-executed
```

### L1 -- Semi-Automatic (Read-Only Automation)

**Behavior:** The engine automatically executes read-only operations (queries, enrichment, data collection) but requires analyst approval for any write operations (isolation, blocking, account changes). This is the recommended starting level for most production deployments.

**Use cases:**
- Enrichment-heavy investigation playbooks.
- Playbooks where data collection is the bottleneck.
- Teams transitioning from fully manual to assisted operations.

**Execution model:**
1. Engine validates and loads the playbook.
2. Read-only steps (queries, enrichment) execute automatically.
3. Write steps pause and enter the approval queue.
4. Analyst reviews context and approves/denies each write step.
5. Approved steps execute; denied steps are skipped or halt execution.

```yaml
config:
  automation_level: "L1"
  max_execution_time: 600
  requires_approval: false     # Config-level approval not required
  parallel_execution: true     # Read-only steps can run in parallel
```

### L2 -- Simulation (Full Automation, Dry-Run in v1)

**Behavior:** The engine generates a complete action plan including all write operations, but executes everything in simulation mode. Actions are logged as structured JSON describing what would happen, without affecting production systems. Analysts review the simulated plan and can approve it for future one-click execution.

**Important:** In RunbookPilot v1, L2 never auto-executes write operations against real systems. All L2 execution is dry-run simulation only.

**Use cases:**
- Building confidence in automation through simulation accuracy tracking.
- Demonstrating containment capabilities without risk.
- Collecting data on response time improvements for automation justification.
- Preparing for future auto-execution (v2+).

**Execution model:**
1. Engine validates and loads the playbook.
2. All steps (read and write) are simulated.
3. Write actions generate structured simulation records instead of executing.
4. Complete action plan presented for analyst review.
5. Analyst can approve the plan (logged for future reference) or modify it.

```yaml
config:
  automation_level: "L2"
  max_execution_time: 900
  requires_approval: true      # Mandatory for L2
  approval_timeout: 3600
  rollback_on_failure: true
```

### Automation Level Comparison

| Capability | L0 | L1 | L2 |
|-----------|----|----|-----|
| Read-only actions | Manual | Auto | Simulated |
| Write actions | Manual | Approval-gated | Simulated |
| Approval required | No | Per-step | Yes (plan-level) |
| Rollback available | N/A | Yes | Simulated |
| Production impact | None | Read-only | None (dry-run) |
| Recommended for | New playbooks, training | Production enrichment | Automation validation |

---

## 8. StepAction Reference

All valid values for the `action` field in step definitions. Actions are organized by category.

### Network Isolation

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `isolate_host` | Network-isolate a host from the environment | `edr`, `nac` |
| `restore_connectivity` | Restore network access to an isolated host | `edr`, `nac` |
| `block_ip` | Block an IP address at the firewall | `firewall` |
| `unblock_ip` | Remove an IP block rule | `firewall` |
| `block_domain` | Block a domain via DNS or proxy | `dns`, `proxy` |
| `unblock_domain` | Remove a domain block | `dns`, `proxy` |

### Data Collection

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `collect_logs` | Collect logs from a specified source | `siem`, `email_gateway` |
| `query_siem` | Execute a SIEM search query | `splunk`, `elastic` |
| `collect_network_traffic` | Capture network traffic for analysis | `ndr`, `pcap` |
| `snapshot_memory` | Capture a memory snapshot of a host | `edr` |
| `collect_file_metadata` | Collect file metadata (hashes, timestamps) | `edr`, `filesystem` |

### Threat Intelligence

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `enrich_ioc` | Enrich an indicator of compromise with context | `threat_intel`, `sandbox` |
| `check_reputation` | Check reputation score for an indicator | `threat_intel` |
| `query_threat_feed` | Query a specific threat intelligence feed | `threat_intel` |

### Ticketing and Notifications

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `create_ticket` | Create a new ticket in the ticketing system | `jira`, `servicenow` |
| `update_ticket` | Update an existing ticket with findings | `jira`, `servicenow` |
| `notify_analyst` | Send a notification to the assigned analyst | `slack`, `email` |
| `notify_oncall` | Page the on-call responder | `pagerduty`, `opsgenie` |
| `send_email` | Send an email notification | `smtp` |

### Account Management

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `disable_account` | Disable a user account | `active_directory`, `okta` |
| `enable_account` | Re-enable a disabled account | `active_directory`, `okta` |
| `reset_password` | Force a password reset | `active_directory`, `okta` |
| `revoke_session` | Revoke all active sessions for a user | `identity_provider` |

### File Operations

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `quarantine_file` | Move a file to quarantine | `edr` |
| `restore_file` | Restore a quarantined file | `edr` |
| `delete_file` | Permanently delete a file | `edr`, `filesystem` |
| `calculate_hash` | Calculate file hash (MD5, SHA256) | `edr`, `filesystem` |

### EDR/XDR Actions

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `kill_process` | Terminate a running process | `edr` |
| `start_edr_scan` | Initiate an on-demand EDR scan | `edr` |
| `retrieve_edr_data` | Retrieve telemetry data from EDR | `crowdstrike`, `sentinelone` |

### Custom and Utility Actions

| Action | Description | Typical Executor |
|--------|-------------|-----------------|
| `execute_script` | Execute a custom script | `script` |
| `http_request` | Make an HTTP request to an API | `http` |
| `wait` | Pause execution for a specified duration | `engine` |
