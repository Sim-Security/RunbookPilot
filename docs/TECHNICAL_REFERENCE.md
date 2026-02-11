# RunbookPilot Technical Reference

**Version:** 1.0.0
**Last Updated:** 2026-02-10
**Status:** Specification Document

## Overview

RunbookPilot is an open-source, AI-assisted SOC runbook automation tool that bridges detection engineering and incident response. Built with Bun + TypeScript + Vitest, it provides three levels of autonomy (L0/L1/L2) with human-in-the-loop controls for safe, auditable security automation.

This document serves as the definitive technical reference for implementing RunbookPilot from scratch.

---

## Table of Contents

1. [TypeScript Type Definitions](#1-typescript-type-definitions)
2. [YAML Playbook Schema Specification](#2-yaml-playbook-schema-specification)
3. [ECS Alert Event Schema](#3-ecs-alert-event-schema)
4. [State Machine Specification](#4-state-machine-specification)
5. [Adapter Interface Contract](#5-adapter-interface-contract)
6. [SQLite Schema](#6-sqlite-schema)
7. [CLI Command Reference](#7-cli-command-reference)
8. [LLM Integration Specification](#8-llm-integration-specification)
9. [DetectForge Integration Protocol](#9-detectforge-integration-protocol)
10. [Error Codes and Handling](#10-error-codes-and-handling)

---

## 1. TypeScript Type Definitions

### 1.1 Core Enums and Types

```typescript
/**
 * Automation levels defining human-in-the-loop requirements
 * L0: Recommend only (no execution)
 * L1: Auto-execute safe actions (e.g., enrichment, queries)
 * L2: Auto-execute impactful actions (requires approval in simulation mode)
 */
type AutomationLevel = 'L0' | 'L1' | 'L2';

/**
 * Execution modes
 * production: Execute actions against real systems
 * simulation: Simulate actions, log what would happen
 * dry-run: Validate runbook without execution or simulation
 */
type ExecutionMode = 'production' | 'simulation' | 'dry-run';

/**
 * Available step actions (extensible via adapters)
 */
type StepAction =
  // Network isolation
  | 'isolate_host'
  | 'restore_connectivity'
  | 'block_ip'
  | 'unblock_ip'
  | 'block_domain'
  | 'unblock_domain'

  // Data collection
  | 'collect_logs'
  | 'query_siem'
  | 'collect_network_traffic'
  | 'snapshot_memory'
  | 'collect_file_metadata'

  // Threat intelligence
  | 'enrich_ioc'
  | 'check_reputation'
  | 'query_threat_feed'

  // Ticketing and notifications
  | 'create_ticket'
  | 'update_ticket'
  | 'notify_analyst'
  | 'notify_oncall'
  | 'send_email'

  // Account management
  | 'disable_account'
  | 'enable_account'
  | 'reset_password'
  | 'revoke_session'

  // File operations
  | 'quarantine_file'
  | 'restore_file'
  | 'delete_file'
  | 'calculate_hash'

  // EDR/XDR actions
  | 'kill_process'
  | 'start_edr_scan'
  | 'retrieve_edr_data'

  // Custom actions
  | 'execute_script'
  | 'http_request'
  | 'wait';

/**
 * Error handling strategies for failed steps
 */
type OnError = 'halt' | 'continue' | 'skip';

/**
 * Detection sources that can trigger runbooks
 */
type DetectionSource =
  | 'sigma'
  | 'edr_alert'
  | 'siem_correlation'
  | 'webhook'
  | 'manual'
  | 'detectforge';

/**
 * Supported platforms
 */
type Platform = 'windows' | 'linux' | 'macos' | 'cloud' | 'network' | 'saas';

/**
 * Execution states
 */
type ExecutionState =
  | 'idle'
  | 'validating'
  | 'planning'
  | 'awaiting_approval'
  | 'executing'
  | 'rolling_back'
  | 'completed'
  | 'failed'
  | 'cancelled';

/**
 * Approval status
 */
type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

/**
 * Adapter health status
 */
type AdapterHealth = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
```

### 1.2 Core Interfaces

```typescript
/**
 * Complete runbook definition
 */
interface Runbook {
  id: string;
  version: string;
  metadata: RunbookMetadata;
  triggers: RunbookTrigger;
  config: RunbookConfig;
  steps: RunbookStep[];
}

/**
 * Runbook metadata
 */
interface RunbookMetadata {
  name: string;
  description?: string;
  author?: string;
  created: string; // ISO8601
  updated: string; // ISO8601
  tags: string[];
  references?: string[]; // URLs to documentation, threat reports, etc.
}

/**
 * Trigger conditions for runbook execution
 */
interface RunbookTrigger {
  detection_sources: DetectionSource[];
  mitre_techniques: string[]; // Format: TXXXX or TXXXX.XXX
  platforms: Platform[];
  severity?: ('low' | 'medium' | 'high' | 'critical')[]; // Optional severity filter
}

/**
 * Runbook configuration
 */
interface RunbookConfig {
  automation_level: AutomationLevel;
  max_execution_time: number; // seconds
  requires_approval: boolean; // Override for L1/L2
  approval_timeout?: number; // seconds, default 3600
  parallel_execution?: boolean; // Allow parallel steps, default false
  rollback_on_failure?: boolean; // Auto-rollback on error, default true
}

/**
 * Individual runbook step
 */
interface RunbookStep {
  id: string; // Unique within runbook (e.g., step-01)
  name: string;
  description?: string;
  action: StepAction;
  executor: string; // Adapter name (e.g., 'edr', 'siem', 'mock')
  parameters: Record<string, any>; // Action-specific parameters
  approval_required?: boolean; // Override config-level setting
  rollback?: RollbackDefinition;
  on_error: OnError;
  timeout: number; // seconds
  depends_on?: string[]; // Step IDs that must complete first
  condition?: string; // JavaScript expression (optional guard)
}

/**
 * Rollback definition for a step
 */
interface RollbackDefinition {
  action: StepAction;
  executor?: string; // Defaults to parent step executor
  parameters: Record<string, any>;
  timeout: number; // seconds
  on_error?: OnError; // What to do if rollback fails
}

/**
 * Execution context passed between steps
 */
interface ExecutionContext {
  execution_id: string;
  runbook_id: string;
  runbook_version: string;
  mode: ExecutionMode;
  alert?: AlertEvent; // Triggering alert
  started_at: string; // ISO8601
  current_step?: string; // Current step ID
  completed_steps: string[]; // Step IDs
  variables: Record<string, any>; // Accumulated variables from steps
  state: ExecutionState;
  error?: ExecutionError;
}

/**
 * Result of runbook execution
 */
interface ExecutionResult {
  execution_id: string;
  runbook_id: string;
  success: boolean;
  state: ExecutionState;
  started_at: string; // ISO8601
  completed_at: string; // ISO8601
  duration_ms: number;
  steps_executed: StepResult[];
  error?: ExecutionError;
  metrics: ExecutionMetrics;
}

/**
 * Result of individual step execution
 */
interface StepResult {
  step_id: string;
  step_name: string;
  action: StepAction;
  success: boolean;
  started_at: string; // ISO8601
  completed_at: string; // ISO8601
  duration_ms: number;
  output?: any; // Action-specific output
  error?: ExecutionError;
  rolled_back?: boolean;
}

/**
 * Simulation-specific result (extends ExecutionResult)
 */
interface SimulationResult extends ExecutionResult {
  simulated_actions: SimulatedAction[];
  risk_score: number; // 0-100
  affected_assets: string[];
  rollback_available: boolean;
}

/**
 * Simulated action details
 */
interface SimulatedAction {
  step_id: string;
  action: StepAction;
  executor: string;
  parameters: Record<string, any>;
  expected_outcome: string;
  risk_level: 'low' | 'medium' | 'high';
  affected_assets: string[];
}

/**
 * Approval request for L2 actions
 */
interface ApprovalRequest {
  request_id: string;
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  step_id: string;
  step_name: string;
  action: StepAction;
  parameters: Record<string, any>;
  simulation_result: SimulationResult;
  requested_at: string; // ISO8601
  expires_at: string; // ISO8601
  status: ApprovalStatus;
  approved_by?: string;
  approved_at?: string; // ISO8601
  denial_reason?: string;
}

/**
 * Audit log entry
 */
interface AuditLogEntry {
  id: string;
  timestamp: string; // ISO8601
  execution_id: string;
  runbook_id: string;
  event_type: 'execution_started' | 'execution_completed' | 'execution_failed'
    | 'step_executed' | 'step_failed' | 'approval_requested'
    | 'approval_granted' | 'approval_denied' | 'rollback_triggered';
  actor: string; // 'system' or user identifier
  details: Record<string, any>;
  success: boolean;
}

/**
 * Incoming alert event (ECS-normalized)
 */
interface AlertEvent {
  '@timestamp': string; // ISO8601
  event: EventFields;
  host?: HostFields;
  source?: NetworkFields;
  destination?: NetworkFields;
  process?: ProcessFields;
  file?: FileFields;
  user?: UserFields;
  threat?: ThreatFields;
  tags?: string[];
  'x-detectforge'?: DetectForgeMetadata;
}

/**
 * ECS event fields
 */
interface EventFields {
  kind: 'alert' | 'event' | 'metric';
  category: string[];
  type: string[];
  action?: string;
  outcome?: 'success' | 'failure' | 'unknown';
  severity: number; // 0-100
  risk_score?: number; // 0-100
  dataset?: string;
  module?: string;
}

/**
 * ECS host fields
 */
interface HostFields {
  hostname?: string;
  name?: string;
  id?: string;
  ip?: string[];
  mac?: string[];
  os?: {
    family?: string;
    name?: string;
    platform?: string;
    version?: string;
  };
}

/**
 * ECS network fields
 */
interface NetworkFields {
  ip?: string;
  port?: number;
  domain?: string;
  geo?: {
    country_iso_code?: string;
    city_name?: string;
  };
}

/**
 * ECS process fields
 */
interface ProcessFields {
  pid?: number;
  name?: string;
  executable?: string;
  command_line?: string;
  parent?: {
    pid?: number;
    name?: string;
  };
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

/**
 * ECS file fields
 */
interface FileFields {
  path?: string;
  name?: string;
  extension?: string;
  size?: number;
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

/**
 * ECS user fields
 */
interface UserFields {
  id?: string;
  name?: string;
  email?: string;
  domain?: string;
  roles?: string[];
}

/**
 * ECS threat fields
 */
interface ThreatFields {
  framework: 'MITRE ATT&CK';
  technique?: {
    id: string[];
    name: string[];
  };
  tactic?: {
    id: string[];
    name: string[];
  };
  indicator?: {
    type?: string;
    value?: string;
  };
}

/**
 * DetectForge metadata (handoff from DetectForge)
 */
interface DetectForgeMetadata {
  rule_id: string;
  rule_name: string;
  rule_version: string;
  generated_at: string; // ISO8601
  intel_source?: string;
  intel_url?: string;
  confidence: 'low' | 'medium' | 'high';
  suggested_runbook?: string; // Runbook ID
}

/**
 * Adapter configuration
 */
interface AdapterConfig {
  name: string;
  type: string; // 'edr', 'siem', 'firewall', 'iam', 'ticketing', 'mock'
  enabled: boolean;
  config: Record<string, any>; // Adapter-specific config
  credentials?: AdapterCredentials;
  timeout?: number; // Default timeout in seconds
  retry?: RetryConfig;
}

/**
 * Adapter credentials (stored encrypted)
 */
interface AdapterCredentials {
  type: 'api_key' | 'oauth2' | 'basic_auth' | 'certificate';
  credentials: Record<string, string>; // Type-specific fields
}

/**
 * Retry configuration
 */
interface RetryConfig {
  max_attempts: number;
  backoff_ms: number;
  exponential: boolean;
}

/**
 * Adapter execution result
 */
interface AdapterResult {
  success: boolean;
  action: StepAction;
  executor: string;
  duration_ms: number;
  output?: any; // Action-specific output
  error?: AdapterError;
  metadata?: Record<string, any>;
}

/**
 * Execution error details
 */
interface ExecutionError {
  code: string; // Error code (see section 10)
  message: string;
  step_id?: string;
  details?: Record<string, any>;
  stack?: string;
}

/**
 * Adapter-specific error
 */
interface AdapterError extends ExecutionError {
  adapter: string;
  action: StepAction;
  retryable: boolean;
}

/**
 * Execution metrics
 */
interface ExecutionMetrics {
  total_steps: number;
  successful_steps: number;
  failed_steps: number;
  skipped_steps: number;
  rollbacks_triggered: number;
  duration_ms: number;
  mttd?: number; // Mean time to detect (ms)
  mttr?: number; // Mean time to respond (ms)
}

/**
 * Metrics snapshot for dashboard
 */
interface MetricsSnapshot {
  period_start: string; // ISO8601
  period_end: string; // ISO8601
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  avg_execution_time_ms: number;
  avg_mttd_ms: number;
  avg_mttr_ms: number;
  executions_by_level: Record<AutomationLevel, number>;
  executions_by_technique: Record<string, number>; // MITRE technique -> count
  top_runbooks: Array<{ runbook_id: string; count: number }>;
  adapter_health: Record<string, AdapterHealth>;
}
```

---

## 2. YAML Playbook Schema Specification

### 2.1 Schema Version

**Current Version:** `1.0`

Schema versioning follows semantic versioning:
- **Major version:** Breaking changes to schema structure
- **Minor version:** Backwards-compatible additions
- **Patch version:** Documentation or validation rule clarifications

### 2.2 Complete Schema Definition

```yaml
runbook:
  # Required: Unique identifier (UUID v4)
  id: string

  # Required: Schema version (default: "1.0")
  version: string

  # Required: Runbook metadata
  metadata:
    # Required: Human-readable name
    name: string

    # Optional: Description of runbook purpose
    description: string

    # Optional: Author name or email
    author: string

    # Required: ISO8601 creation timestamp
    created: string

    # Required: ISO8601 last update timestamp
    updated: string

    # Required: Searchable tags (min: 1)
    tags: string[]

    # Optional: Reference URLs (threat reports, documentation)
    references: string[]

  # Required: Trigger conditions
  triggers:
    # Required: Detection sources (min: 1)
    detection_sources:
      - sigma
      - edr_alert
      - siem_correlation
      - webhook
      - manual
      - detectforge

    # Required: MITRE ATT&CK techniques (format: TXXXX or TXXXX.XXX)
    mitre_techniques: string[]

    # Required: Target platforms (min: 1)
    platforms:
      - windows
      - linux
      - macos
      - cloud
      - network
      - saas

    # Optional: Severity filter
    severity:
      - low
      - medium
      - high
      - critical

  # Required: Execution configuration
  config:
    # Required: Automation level
    automation_level: L0 | L1 | L2

    # Required: Maximum execution time (seconds, min: 60, max: 3600)
    max_execution_time: number

    # Required: Whether approval is required (L2 default: true)
    requires_approval: boolean

    # Optional: Approval timeout (seconds, default: 3600)
    approval_timeout: number

    # Optional: Allow parallel step execution (default: false)
    parallel_execution: boolean

    # Optional: Auto-rollback on failure (default: true)
    rollback_on_failure: boolean

  # Required: Execution steps (min: 1)
  steps:
    - # Required: Unique step identifier (within runbook)
      id: string

      # Required: Human-readable step name
      name: string

      # Optional: Step description
      description: string

      # Required: Action to execute
      action: StepAction

      # Required: Adapter name (must be registered)
      executor: string

      # Required: Action-specific parameters (supports {{ template }} syntax)
      parameters:
        key: value

      # Optional: Override config-level approval requirement
      approval_required: boolean

      # Optional: Rollback definition
      rollback:
        # Required: Rollback action
        action: StepAction

        # Optional: Rollback executor (defaults to step executor)
        executor: string

        # Required: Rollback parameters
        parameters:
          key: value

        # Required: Rollback timeout (seconds)
        timeout: number

        # Optional: Error handling for rollback failure
        on_error: halt | continue | skip

      # Required: Error handling strategy
      on_error: halt | continue | skip

      # Required: Step timeout (seconds, min: 5, max: 600)
      timeout: number

      # Optional: Dependencies (step IDs that must complete first)
      depends_on: string[]

      # Optional: Guard condition (JavaScript expression)
      condition: string
```

### 2.3 Field Validation Rules

#### Global Rules
- All required fields must be present
- All timestamps must be valid ISO8601 format
- All UUIDs must be valid UUID v4 format
- All MITRE technique IDs must match pattern: `^T\d{4}(\.\d{3})?$`

#### Metadata Rules
- `name`: 3-100 characters, no leading/trailing whitespace
- `tags`: 1-20 tags, each 2-50 characters
- `references`: Valid URLs (http/https only)

#### Triggers Rules
- `detection_sources`: At least one source required
- `mitre_techniques`: At least one technique required
- `platforms`: At least one platform required

#### Config Rules
- `max_execution_time`: 60-3600 seconds
- `approval_timeout`: 300-7200 seconds
- L2 runbooks must have `requires_approval: true` (enforced at runtime)

#### Steps Rules
- `steps`: At least one step required, max 50 steps
- `id`: Unique within runbook, pattern: `^step-\d{2}$` recommended
- `timeout`: 5-600 seconds
- `depends_on`: All referenced step IDs must exist
- `condition`: Must be valid JavaScript expression
- Circular dependencies are forbidden

### 2.4 Template Syntax

RunbookPilot supports Mustache-style template interpolation in `parameters` fields:

```yaml
parameters:
  # Alert field reference
  hostname: "{{ alert.host.hostname }}"

  # Previous step output reference
  threat_score: "{{ steps.step-01.output.score }}"

  # Context variable reference
  analyst_email: "{{ context.analyst_email }}"

  # Environment variable reference
  api_key: "{{ env.VIRUSTOTAL_API_KEY }}"

  # Default values
  timeout: "{{ alert.timeout | default: 300 }}"

  # Conditional rendering
  severity: "{{ alert.event.severity > 80 ? 'critical' : 'high' }}"
```

Template evaluation happens at runtime before step execution.

### 2.5 Example Playbooks

#### Example 1: L0 Runbook (Recommendation Only)

```yaml
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  metadata:
    name: "T1566.001 - Phishing Email Investigation"
    description: "Initial triage for suspected phishing emails"
    author: "security-team@example.com"
    created: "2026-01-15T10:00:00Z"
    updated: "2026-01-15T10:00:00Z"
    tags:
      - "phishing"
      - "email"
      - "initial-access"
    references:
      - "https://attack.mitre.org/techniques/T1566/001/"

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

  config:
    automation_level: "L0"
    max_execution_time: 300
    requires_approval: false

  steps:
    - id: "step-01"
      name: "Collect Email Metadata"
      action: "collect_logs"
      executor: "email_gateway"
      parameters:
        message_id: "{{ alert.email.message_id }}"
        fields:
          - "sender"
          - "recipients"
          - "subject"
          - "headers"
          - "attachments"
      on_error: "halt"
      timeout: 30

    - id: "step-02"
      name: "Enrich Sender Domain"
      action: "check_reputation"
      executor: "threat_intel"
      parameters:
        indicator_type: "domain"
        indicator_value: "{{ steps.step-01.output.sender.domain }}"
        sources:
          - "virustotal"
          - "abuseipdb"
      depends_on:
        - "step-01"
      on_error: "continue"
      timeout: 45

    - id: "step-03"
      name: "Analyze Attachments"
      action: "enrich_ioc"
      executor: "sandbox"
      parameters:
        files: "{{ steps.step-01.output.attachments }}"
        analysis_type: "static"
      depends_on:
        - "step-01"
      on_error: "continue"
      timeout: 60

    - id: "step-04"
      name: "Create Investigation Ticket"
      action: "create_ticket"
      executor: "jira"
      parameters:
        project: "SOC"
        issue_type: "Investigation"
        summary: "Phishing Email: {{ alert.email.subject }}"
        description: |
          Automated analysis completed:
          - Sender: {{ steps.step-01.output.sender.address }}
          - Reputation: {{ steps.step-02.output.risk_score }}/100
          - Attachments: {{ steps.step-03.output.file_count }}

          Manual review required.
        priority: "{{ alert.event.severity > 80 ? 'High' : 'Medium' }}"
        labels:
          - "phishing"
          - "automated-triage"
      depends_on:
        - "step-02"
        - "step-03"
      on_error: "continue"
      timeout: 30
```

#### Example 2: L1 Runbook (Auto-Execute Safe Actions)

```yaml
runbook:
  id: "660e8400-e29b-41d4-a716-446655440001"
  version: "1.0"
  metadata:
    name: "T1078 - Suspicious Login Enrichment"
    description: "Automated enrichment for suspicious authentication events"
    author: "security-team@example.com"
    created: "2026-01-20T14:00:00Z"
    updated: "2026-01-20T14:00:00Z"
    tags:
      - "authentication"
      - "credential-access"
      - "auto-enrich"

  triggers:
    detection_sources:
      - "siem_correlation"
      - "edr_alert"
    mitre_techniques:
      - "T1078"
    platforms:
      - "windows"
      - "linux"
      - "saas"

  config:
    automation_level: "L1"
    max_execution_time: 600
    requires_approval: false
    parallel_execution: true

  steps:
    - id: "step-01"
      name: "Query User Login History"
      action: "query_siem"
      executor: "splunk"
      parameters:
        query: |
          index=authentication user="{{ alert.user.name }}"
          | stats count by src_ip, user_agent, authentication_method
          | where _time > relative_time(now(), "-7d")
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
        enrichment:
          - "geolocation"
          - "reputation"
          - "asn"
          - "threat_feeds"
      on_error: "continue"
      timeout: 30

    - id: "step-03"
      name: "Check User Risk Score"
      action: "http_request"
      executor: "http"
      parameters:
        method: "GET"
        url: "https://identity-platform.example.com/api/v1/users/{{ alert.user.id }}/risk"
        headers:
          Authorization: "Bearer {{ env.IDP_API_TOKEN }}"
        timeout: 15
      on_error: "continue"
      timeout: 20

    - id: "step-04"
      name: "Correlate with EDR Events"
      action: "retrieve_edr_data"
      executor: "crowdstrike"
      parameters:
        host_id: "{{ alert.host.id }}"
        timeframe: "24h"
        event_types:
          - "ProcessRollup2"
          - "NetworkConnect4"
          - "DnsRequest"
      depends_on:
        - "step-01"
      on_error: "continue"
      timeout: 45

    - id: "step-05"
      name: "Update Ticket with Findings"
      action: "update_ticket"
      executor: "jira"
      parameters:
        ticket_id: "{{ alert.x-detectforge.ticket_id }}"
        comment: |
          Automated enrichment completed:

          IP Analysis:
          - Location: {{ steps.step-02.output.geo.country }} / {{ steps.step-02.output.geo.city }}
          - Reputation: {{ steps.step-02.output.reputation }}
          - ASN: {{ steps.step-02.output.asn.organization }}

          User Context:
          - Risk Score: {{ steps.step-03.output.risk_score }}/100
          - Recent Logins: {{ steps.step-01.output.count }}

          EDR Activity:
          - Process Events: {{ steps.step-04.output.process_count }}
          - Network Connections: {{ steps.step-04.output.network_count }}

          Recommend: {{ steps.step-03.output.risk_score > 70 ? 'Escalate to L2' : 'Monitor' }}
      depends_on:
        - "step-02"
        - "step-03"
        - "step-04"
      on_error: "continue"
      timeout: 30
```

#### Example 3: L2 Runbook (Auto-Execute with Approval)

```yaml
runbook:
  id: "770e8400-e29b-41d4-a716-446655440002"
  version: "1.0"
  metadata:
    name: "T1486 - Ransomware Containment"
    description: "Automated containment for suspected ransomware activity"
    author: "security-team@example.com"
    created: "2026-02-01T09:00:00Z"
    updated: "2026-02-05T16:30:00Z"
    tags:
      - "ransomware"
      - "impact"
      - "containment"
      - "critical"
    references:
      - "https://attack.mitre.org/techniques/T1486/"

  triggers:
    detection_sources:
      - "edr_alert"
      - "detectforge"
    mitre_techniques:
      - "T1486"
      - "T1490"
    platforms:
      - "windows"
    severity:
      - "critical"

  config:
    automation_level: "L2"
    max_execution_time: 900
    requires_approval: true
    approval_timeout: 600
    rollback_on_failure: true

  steps:
    - id: "step-01"
      name: "Snapshot Memory"
      action: "snapshot_memory"
      executor: "edr"
      parameters:
        host_id: "{{ alert.host.id }}"
        include_processes: true
      on_error: "continue"
      timeout: 120

    - id: "step-02"
      name: "Collect File Hashes"
      action: "collect_file_metadata"
      executor: "edr"
      parameters:
        host_id: "{{ alert.host.id }}"
        file_paths: "{{ alert.file.path }}"
        compute_hashes:
          - "md5"
          - "sha256"
      on_error: "continue"
      timeout: 60

    - id: "step-03"
      name: "Isolate Host"
      action: "isolate_host"
      executor: "edr"
      parameters:
        host_id: "{{ alert.host.id }}"
        isolation_type: "network"
        allow_list:
          - "edr-management.example.com"
      approval_required: true
      rollback:
        action: "restore_connectivity"
        parameters:
          host_id: "{{ alert.host.id }}"
        timeout: 60
        on_error: "continue"
      depends_on:
        - "step-01"
        - "step-02"
      on_error: "halt"
      timeout: 90

    - id: "step-04"
      name: "Disable User Account"
      action: "disable_account"
      executor: "active_directory"
      parameters:
        username: "{{ alert.user.name }}"
        domain: "{{ alert.user.domain }}"
        reason: "Automated containment - T1486 ransomware"
      approval_required: true
      rollback:
        action: "enable_account"
        parameters:
          username: "{{ alert.user.name }}"
          domain: "{{ alert.user.domain }}"
        timeout: 30
        on_error: "continue"
      depends_on:
        - "step-03"
      on_error: "continue"
      timeout: 45

    - id: "step-05"
      name: "Block C2 IPs"
      action: "block_ip"
      executor: "firewall"
      parameters:
        ip_addresses: "{{ alert.destination.ip }}"
        direction: "egress"
        rule_name: "AUTO-BLOCK-T1486-{{ execution_id }}"
        expiry: "24h"
      approval_required: true
      rollback:
        action: "unblock_ip"
        parameters:
          ip_addresses: "{{ alert.destination.ip }}"
          direction: "egress"
        timeout: 60
        on_error: "continue"
      depends_on:
        - "step-03"
      on_error: "continue"
      timeout: 90

    - id: "step-06"
      name: "Notify Incident Response"
      action: "notify_oncall"
      executor: "pagerduty"
      parameters:
        service: "incident-response"
        severity: "critical"
        title: "CRITICAL: Ransomware Containment Active - {{ alert.host.hostname }}"
        description: |
          Automated L2 containment executed:

          Host: {{ alert.host.hostname }} ({{ alert.host.ip }})
          User: {{ alert.user.name }}
          Detection: {{ alert.x-detectforge.rule_name }}

          Actions Taken:
          ✓ Memory snapshot captured
          ✓ Host isolated from network
          ✓ User account disabled
          ✓ C2 IP blocked: {{ alert.destination.ip }}

          IMMEDIATE MANUAL INVESTIGATION REQUIRED
        urgency: "high"
      depends_on:
        - "step-03"
        - "step-04"
        - "step-05"
      on_error: "continue"
      timeout: 30

    - id: "step-07"
      name: "Create Critical Incident"
      action: "create_ticket"
      executor: "jira"
      parameters:
        project: "INCIDENT"
        issue_type: "Incident"
        summary: "CRITICAL: T1486 Ransomware - {{ alert.host.hostname }}"
        description: |
          Automated L2 containment executed by RunbookPilot.

          Execution ID: {{ execution_id }}
          Runbook: {{ runbook.metadata.name }}

          Evidence Collected:
          - Memory Snapshot: {{ steps.step-01.output.snapshot_id }}
          - File Hashes: {{ steps.step-02.output.sha256 }}

          Containment Actions:
          - Host Isolation: {{ steps.step-03.success ? 'SUCCESS' : 'FAILED' }}
          - Account Disable: {{ steps.step-04.success ? 'SUCCESS' : 'FAILED' }}
          - IP Block: {{ steps.step-05.success ? 'SUCCESS' : 'FAILED' }}

          Next Steps:
          1. Review memory snapshot for additional IOCs
          2. Identify patient zero
          3. Check backup integrity
          4. Coordinate with management on recovery strategy
        priority: "Highest"
        labels:
          - "ransomware"
          - "automated-response"
          - "t1486"
        assignee: "ir-lead"
      depends_on:
        - "step-06"
      on_error: "continue"
      timeout: 45
```

### 2.6 Schema Versioning Strategy

When schema changes occur:

1. **Minor version bump (1.0 → 1.1)**: New optional fields added
   - Old runbooks remain valid without modification
   - New fields have sensible defaults
   - Example: Adding `parallel_execution` field

2. **Major version bump (1.0 → 2.0)**: Breaking changes
   - Field renamed, removed, or type changed
   - Required field added
   - Validation rules tightened
   - Migration tool provided

**Version compatibility matrix:**
- RunbookPilot 1.x supports schema 1.x runbooks
- Schema version must match major version of RunbookPilot

---

## 3. ECS Alert Event Schema

### 3.1 Overview

RunbookPilot ingests alerts normalized to the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) format. This ensures consistent alert processing regardless of source (SIEM, EDR, DetectForge, etc.).

### 3.2 Base Alert Structure

All alerts must contain:

```json
{
  "@timestamp": "2026-02-10T14:32:15.123Z",
  "event": {
    "kind": "alert",
    "category": ["intrusion_detection"],
    "type": ["info"],
    "action": "suspicious-activity-detected",
    "outcome": "success",
    "severity": 75,
    "risk_score": 80,
    "dataset": "edr.alerts",
    "module": "crowdstrike"
  }
}
```

### 3.3 Entity Fields

#### Host Fields

```json
{
  "host": {
    "hostname": "workstation-042",
    "name": "WORKSTATION-042.corp.example.com",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "ip": ["10.20.30.40", "fe80::1"],
    "mac": ["00:1B:44:11:3A:B7"],
    "os": {
      "family": "windows",
      "name": "Windows 10 Pro",
      "platform": "windows",
      "version": "10.0.19044"
    }
  }
}
```

#### Network Fields (Source/Destination)

```json
{
  "source": {
    "ip": "192.168.1.100",
    "port": 49152,
    "domain": "workstation.corp.example.com"
  },
  "destination": {
    "ip": "185.220.101.5",
    "port": 443,
    "domain": "malicious-c2.example",
    "geo": {
      "country_iso_code": "RU",
      "city_name": "Moscow"
    }
  }
}
```

#### Process Fields

```json
{
  "process": {
    "pid": 4532,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcA...",
    "parent": {
      "pid": 2048,
      "name": "explorer.exe"
    },
    "hash": {
      "md5": "5d5b09f6dcb2d53a5fffc60c4ac0d55f",
      "sha1": "7697d3b1f6c74e0c3e6c6f3f3f3f3f3f3f3f3f3f",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
}
```

#### File Fields

```json
{
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\invoice.pdf.exe",
    "name": "invoice.pdf.exe",
    "extension": "exe",
    "size": 2048576,
    "hash": {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
}
```

#### User Fields

```json
{
  "user": {
    "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
    "name": "jdoe",
    "email": "jdoe@example.com",
    "domain": "CORP",
    "roles": ["user", "remote-desktop-users"]
  }
}
```

#### Threat Fields (MITRE ATT&CK)

```json
{
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {
      "id": ["T1059.001", "T1055"],
      "name": ["PowerShell", "Process Injection"]
    },
    "tactic": {
      "id": ["TA0002", "TA0005"],
      "name": ["Execution", "Defense Evasion"]
    },
    "indicator": {
      "type": "ipv4-addr",
      "value": "185.220.101.5"
    }
  }
}
```

### 3.4 DetectForge Extension Fields

When alerts originate from DetectForge, additional metadata is included:

```json
{
  "x-detectforge": {
    "rule_id": "df-sigma-001",
    "rule_name": "Suspicious PowerShell Encoded Command",
    "rule_version": "1.2.0",
    "generated_at": "2026-02-08T10:15:00Z",
    "intel_source": "Threat Report #2026-045",
    "intel_url": "https://threat-intel.example.com/reports/2026-045",
    "confidence": "high",
    "suggested_runbook": "770e8400-e29b-41d4-a716-446655440002"
  }
}
```

### 3.5 Complete Alert Example

```json
{
  "@timestamp": "2026-02-10T14:32:15.123Z",
  "event": {
    "kind": "alert",
    "category": ["malware", "intrusion_detection"],
    "type": ["info"],
    "action": "ransomware-detected",
    "outcome": "success",
    "severity": 95,
    "risk_score": 98,
    "dataset": "edr.alerts",
    "module": "crowdstrike"
  },
  "host": {
    "hostname": "workstation-042",
    "name": "WORKSTATION-042.corp.example.com",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "ip": ["10.20.30.40"],
    "mac": ["00:1B:44:11:3A:B7"],
    "os": {
      "family": "windows",
      "name": "Windows 10 Pro",
      "platform": "windows",
      "version": "10.0.19044"
    }
  },
  "source": {
    "ip": "10.20.30.40",
    "port": 49152
  },
  "destination": {
    "ip": "185.220.101.5",
    "port": 443,
    "domain": "c2-server.malicious.net",
    "geo": {
      "country_iso_code": "RU",
      "city_name": "Moscow"
    }
  },
  "process": {
    "pid": 4532,
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -EncodedCommand JABzAD0ATgBlAHcA...",
    "parent": {
      "pid": 2048,
      "name": "explorer.exe"
    },
    "hash": {
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  },
  "file": {
    "path": "C:\\Users\\jdoe\\Documents\\invoice.pdf.exe",
    "name": "invoice.pdf.exe",
    "extension": "exe",
    "size": 2048576,
    "hash": {
      "sha256": "44d88612fea8a8f36de82e1278abb02f"
    }
  },
  "user": {
    "id": "S-1-5-21-3623811015-3361044348-30300820-1013",
    "name": "jdoe",
    "email": "jdoe@example.com",
    "domain": "CORP"
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {
      "id": ["T1486", "T1490"],
      "name": ["Data Encrypted for Impact", "Inhibit System Recovery"]
    },
    "tactic": {
      "id": ["TA0040"],
      "name": ["Impact"]
    },
    "indicator": {
      "type": "ipv4-addr",
      "value": "185.220.101.5"
    }
  },
  "tags": ["ransomware", "critical", "containment-required"],
  "x-detectforge": {
    "rule_id": "df-sigma-ransomware-001",
    "rule_name": "Ransomware File Encryption Activity",
    "rule_version": "2.1.0",
    "generated_at": "2026-02-09T08:00:00Z",
    "intel_source": "CISA Alert AA26-040A",
    "intel_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-040a",
    "confidence": "high",
    "suggested_runbook": "770e8400-e29b-41d4-a716-446655440002"
  }
}
```

### 3.6 Alert Ingestion

RunbookPilot accepts alerts via:

1. **File input**: JSON files in ECS format
2. **HTTP webhook**: POST to `/api/v1/alerts/ingest`
3. **Queue consumer**: RabbitMQ, Kafka, etc.
4. **DetectForge integration**: Automatic handoff from detection pipeline

All alerts are validated against ECS schema before processing.

---

## 4. State Machine Specification

### 4.1 Execution States

```
┌────────┐
│  idle  │ (Initial state, no active execution)
└───┬────┘
    │ trigger(runbook, alert)
    ▼
┌────────────┐
│ validating │ (Schema validation, adapter checks)
└─────┬──────┘
      │ validation_success
      ▼
┌──────────┐
│ planning │ (Resolve dependencies, build execution plan)
└─────┬────┘
      │ plan_ready
      │
      ▼
 ┌─────────────────┐
 │ requires_approval? │
 └─────┬─────┬──────┘
       │     │
   Yes │     │ No
       │     │
       ▼     ▼
┌──────────────────┐    ┌──────────┐
│ awaiting_approval│    │executing │
└────────┬─────────┘    └────┬─────┘
         │                    │
         │ approved           │ step_success (loop)
         ▼                    │
     ┌──────────┐             │
     │executing │◄────────────┘
     └────┬─────┘
          │
          │ error + rollback_enabled
          ▼
     ┌─────────────┐
     │rolling_back │
     └──────┬──────┘
            │
   ┌────────┼────────┐
   │        │        │
   │success │rollback│cancel
   │        │failed  │requested
   ▼        ▼        ▼
┌───────┐ ┌──────┐ ┌──────────┐
│completed│ │failed│ │cancelled │
└────────┘ └──────┘ └──────────┘
  (Final)   (Final)   (Final)
```

### 4.2 State Descriptions

| State | Description | Entry Actions | Exit Actions |
|-------|-------------|---------------|--------------|
| `idle` | No active execution. System ready. | None | None |
| `validating` | Validating runbook schema, checking adapter availability | Load runbook, validate YAML, check adapters | Log validation result |
| `planning` | Building execution plan, resolving dependencies | Resolve step dependencies, build DAG, identify approval points | Create execution context |
| `awaiting_approval` | L2 runbook waiting for human approval | Create approval request, simulate actions, notify approvers | Log approval decision |
| `executing` | Actively executing steps | Initialize execution context, start step execution loop | Log execution metrics |
| `rolling_back` | Executing rollback steps after failure | Identify completed steps with rollback, execute in reverse | Log rollback result |
| `completed` | Execution finished successfully | Calculate metrics, write audit log | None |
| `failed` | Execution failed, rollback attempted (if enabled) | Log error, write audit log | None |
| `cancelled` | Execution cancelled by user | Write audit log | None |

### 4.3 State Transitions

#### Transition: idle → validating

**Trigger:** `runbook.execute(runbook, alert, mode)`

**Guards:**
- Runbook file exists and is readable
- Alert matches ECS schema

**Actions:**
1. Generate execution ID
2. Load runbook YAML
3. Parse and validate schema
4. Check all referenced adapters are registered
5. Check automation level compatibility

#### Transition: validating → planning

**Trigger:** `validation_success`

**Guards:**
- Schema validation passed
- All adapters available
- No circular dependencies

**Actions:**
1. Build step dependency graph (DAG)
2. Identify execution order
3. Identify approval checkpoints (L2 + `approval_required: true` steps)
4. Create execution context
5. Substitute template variables

#### Transition: planning → awaiting_approval

**Trigger:** `plan_ready` AND `requires_approval == true`

**Guards:**
- Automation level is L2
- At least one step requires approval

**Actions:**
1. Run simulation of all steps
2. Calculate risk score
3. Identify affected assets
4. Create approval request
5. Notify approvers (Slack, PagerDuty, email)
6. Start approval timeout timer

#### Transition: awaiting_approval → executing

**Trigger:** `approval_granted`

**Guards:**
- Approval request not expired
- Approved by authorized user

**Actions:**
1. Log approval in audit log
2. Update execution context with approver details
3. Switch to production mode

#### Transition: awaiting_approval → cancelled

**Trigger:** `approval_denied` OR `approval_timeout`

**Guards:** None

**Actions:**
1. Log denial/timeout in audit log
2. Notify submitter of denial
3. Mark execution as cancelled

#### Transition: planning → executing

**Trigger:** `plan_ready` AND `requires_approval == false`

**Guards:**
- Automation level is L0 or L1

**Actions:**
1. Initialize step execution loop
2. Execute steps in dependency order

#### Transition: executing → executing (loop)

**Trigger:** `step_completed`

**Guards:**
- More steps remaining
- Current step succeeded OR `on_error: continue`

**Actions:**
1. Store step output in context variables
2. Update execution metrics
3. Execute next step

#### Transition: executing → rolling_back

**Trigger:** `step_failed` AND `rollback_on_failure == true`

**Guards:**
- At least one completed step has rollback definition

**Actions:**
1. Identify steps to rollback (completed steps with rollback, in reverse order)
2. Execute rollback actions
3. Log rollback attempts

#### Transition: executing → completed

**Trigger:** `all_steps_completed`

**Guards:**
- All required steps executed successfully

**Actions:**
1. Calculate final metrics (duration, success rate, MTTR)
2. Write execution result to database
3. Write audit log entries
4. Notify on completion (if configured)

#### Transition: executing → failed

**Trigger:** `step_failed` AND `on_error: halt`

**Guards:** None

**Actions:**
1. Log failure details
2. Calculate partial metrics
3. Write execution result to database
4. Write audit log entries
5. Notify on failure

#### Transition: rolling_back → completed

**Trigger:** `rollback_completed`

**Guards:**
- All rollback steps succeeded

**Actions:**
1. Mark execution as completed with rollback
2. Write audit log
3. Notify on completion

#### Transition: rolling_back → failed

**Trigger:** `rollback_failed`

**Guards:** None

**Actions:**
1. Log rollback failure (critical)
2. Write audit log
3. Escalate to on-call (manual intervention required)

#### Transition: * → cancelled

**Trigger:** `cancel_execution(execution_id)`

**Guards:**
- Execution is in progress (not in terminal state)

**Actions:**
1. Stop current step execution (if possible)
2. Execute rollback for completed steps
3. Write audit log
4. Mark as cancelled

### 4.4 State Persistence

Execution state is persisted in SQLite after every transition:

```sql
UPDATE executions
SET state = :new_state,
    state_data = :state_data_json,
    updated_at = CURRENT_TIMESTAMP
WHERE execution_id = :execution_id;
```

This enables:
- Crash recovery (resume from last known state)
- Execution status queries
- Audit trail

---

## 5. Adapter Interface Contract

### 5.1 Adapter Pattern Overview

Adapters abstract vendor-specific integrations, allowing RunbookPilot to execute actions against diverse security tools through a unified interface.

### 5.2 Core Interface

```typescript
/**
 * ActionAdapter interface
 * All adapters must implement this interface
 */
interface ActionAdapter {
  /**
   * Unique adapter name (lowercase, no spaces)
   */
  readonly name: string;

  /**
   * Adapter version (semantic versioning)
   */
  readonly version: string;

  /**
   * List of actions this adapter can execute
   */
  readonly supportedActions: StepAction[];

  /**
   * Initialize adapter with configuration
   * Called once when adapter is registered
   */
  initialize(config: AdapterConfig): Promise<void>;

  /**
   * Execute an action
   * @param action - Action to execute
   * @param params - Action-specific parameters
   * @param mode - Execution mode (production/simulation/dry-run)
   * @returns Result of execution
   */
  execute(
    action: StepAction,
    params: Record<string, any>,
    mode: ExecutionMode
  ): Promise<AdapterResult>;

  /**
   * Rollback a previously executed action
   * @param action - Original action that was executed
   * @param params - Original parameters (may include step output)
   * @returns Result of rollback
   */
  rollback(
    action: StepAction,
    params: Record<string, any>
  ): Promise<AdapterResult>;

  /**
   * Check adapter health
   * @returns true if adapter is operational
   */
  healthCheck(): Promise<boolean>;

  /**
   * Gracefully shutdown adapter
   * Called when adapter is unregistered or system shutdown
   */
  shutdown?(): Promise<void>;

  /**
   * Validate parameters for an action (optional)
   * Called before execution to catch parameter errors early
   */
  validateParameters?(
    action: StepAction,
    params: Record<string, any>
  ): Promise<ValidationResult>;
}
```

### 5.3 Adapter Configuration

```typescript
interface AdapterConfig {
  name: string; // Must match adapter.name
  type: string; // Category: 'edr', 'siem', 'firewall', etc.
  enabled: boolean;
  config: Record<string, any>; // Adapter-specific config
  credentials?: AdapterCredentials;
  timeout?: number; // Default timeout (seconds)
  retry?: RetryConfig;
}

interface AdapterCredentials {
  type: 'api_key' | 'oauth2' | 'basic_auth' | 'certificate';
  credentials: Record<string, string>;
}

interface RetryConfig {
  max_attempts: number; // Default: 3
  backoff_ms: number; // Default: 1000
  exponential: boolean; // Default: true
}
```

### 5.4 Execution Modes

Adapters must handle all three execution modes:

1. **Production Mode**: Execute real actions against live systems
2. **Simulation Mode**: Return simulated outcomes without execution
3. **Dry-Run Mode**: Validate parameters only, no execution or simulation

```typescript
async execute(action: StepAction, params: any, mode: ExecutionMode): Promise<AdapterResult> {
  switch (mode) {
    case 'production':
      return await this.executeProduction(action, params);

    case 'simulation':
      return await this.executeSimulation(action, params);

    case 'dry-run':
      return await this.executeDryRun(action, params);
  }
}
```

### 5.5 Mock Adapter (Reference Implementation)

```typescript
/**
 * Mock adapter for testing and development
 * Simulates all actions without external dependencies
 */
class MockAdapter implements ActionAdapter {
  readonly name = 'mock';
  readonly version = '1.0.0';
  readonly supportedActions: StepAction[] = [
    'isolate_host',
    'restore_connectivity',
    'block_ip',
    'unblock_ip',
    'collect_logs',
    'query_siem',
    'enrich_ioc',
    'check_reputation',
    'create_ticket',
    'notify_analyst',
    'disable_account',
    'enable_account',
    'quarantine_file',
    'snapshot_memory'
  ];

  private config?: AdapterConfig;
  private simulatedLatency = 100; // ms

  async initialize(config: AdapterConfig): Promise<void> {
    this.config = config;
    this.simulatedLatency = config.config.latency || 100;
  }

  async execute(
    action: StepAction,
    params: Record<string, any>,
    mode: ExecutionMode
  ): Promise<AdapterResult> {
    const startTime = Date.now();

    // Simulate network latency
    await this.sleep(this.simulatedLatency);

    if (mode === 'dry-run') {
      return {
        success: true,
        action,
        executor: this.name,
        duration_ms: Date.now() - startTime,
        output: { validated: true }
      };
    }

    // Simulate action execution
    const result = this.simulateAction(action, params, mode);

    return {
      success: true,
      action,
      executor: this.name,
      duration_ms: Date.now() - startTime,
      output: result
    };
  }

  async rollback(
    action: StepAction,
    params: Record<string, any>
  ): Promise<AdapterResult> {
    const startTime = Date.now();
    await this.sleep(this.simulatedLatency);

    return {
      success: true,
      action,
      executor: this.name,
      duration_ms: Date.now() - startTime,
      output: { rolled_back: true }
    };
  }

  async healthCheck(): Promise<boolean> {
    return true;
  }

  private simulateAction(
    action: StepAction,
    params: any,
    mode: ExecutionMode
  ): any {
    switch (action) {
      case 'isolate_host':
        return {
          host_id: params.host_id,
          isolated: mode === 'production',
          simulated: mode === 'simulation'
        };

      case 'enrich_ioc':
        return {
          indicator: params.indicator_value,
          reputation: 'malicious',
          score: 85,
          sources: ['virustotal', 'abuseipdb']
        };

      case 'create_ticket':
        return {
          ticket_id: `MOCK-${Date.now()}`,
          url: 'https://jira.example.com/browse/MOCK-123'
        };

      default:
        return { action, params };
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### 5.6 Adapter Registry

Adapters are registered at system startup:

```typescript
class AdapterRegistry {
  private adapters: Map<string, ActionAdapter> = new Map();

  /**
   * Register an adapter
   */
  async register(adapter: ActionAdapter, config: AdapterConfig): Promise<void> {
    await adapter.initialize(config);
    this.adapters.set(adapter.name, adapter);
  }

  /**
   * Get adapter by name
   */
  get(name: string): ActionAdapter | undefined {
    return this.adapters.get(name);
  }

  /**
   * Get adapter for action
   */
  getForAction(action: StepAction): ActionAdapter[] {
    return Array.from(this.adapters.values())
      .filter(adapter => adapter.supportedActions.includes(action));
  }

  /**
   * Health check all adapters
   */
  async healthCheckAll(): Promise<Record<string, AdapterHealth>> {
    const results: Record<string, AdapterHealth> = {};

    for (const [name, adapter] of this.adapters) {
      try {
        const healthy = await adapter.healthCheck();
        results[name] = healthy ? 'healthy' : 'unhealthy';
      } catch (error) {
        results[name] = 'unhealthy';
      }
    }

    return results;
  }
}
```

### 5.7 Creating Custom Adapters

To create a new adapter:

1. **Implement the interface**:
   ```typescript
   class CrowdStrikeAdapter implements ActionAdapter {
     readonly name = 'crowdstrike';
     readonly version = '1.0.0';
     readonly supportedActions = ['isolate_host', 'restore_connectivity', 'kill_process'];

     // Implement required methods...
   }
   ```

2. **Add configuration schema**:
   ```yaml
   adapters:
     - name: crowdstrike
       type: edr
       enabled: true
       config:
         api_url: https://api.crowdstrike.com
         client_id: ${CROWDSTRIKE_CLIENT_ID}
         client_secret: ${CROWDSTRIKE_CLIENT_SECRET}
       timeout: 60
       retry:
         max_attempts: 3
         backoff_ms: 1000
         exponential: true
   ```

3. **Register at startup**:
   ```typescript
   const adapter = new CrowdStrikeAdapter();
   await registry.register(adapter, config);
   ```

4. **Reference in runbooks**:
   ```yaml
   steps:
     - id: step-01
       name: Isolate Host
       action: isolate_host
       executor: crowdstrike  # References registered adapter
       parameters:
         host_id: "{{ alert.host.id }}"
   ```

### 5.8 Built-in Adapters

RunbookPilot ships with these adapters:

| Adapter | Type | Actions |
|---------|------|---------|
| `mock` | Testing | All actions (simulated) |
| `http` | Integration | `http_request` |
| `shell` | System | `execute_script` |
| `email` | Notification | `send_email` |

Additional adapters (EDR, SIEM, firewall, IAM) are community-contributed plugins.

---

## 6. SQLite Schema

### 6.1 Database Location

Default: `~/.runbookpilot/runbookpilot.db`

Override with `RUNBOOKPILOT_DB_PATH` environment variable.

### 6.2 Schema Definition

```sql
-- Schema version tracking
CREATE TABLE schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_version (version) VALUES (1);

-- Runbook definitions (cached from YAML files)
CREATE TABLE runbooks (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  content TEXT NOT NULL, -- Full YAML content
  automation_level TEXT NOT NULL CHECK(automation_level IN ('L0', 'L1', 'L2')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  loaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(id, version)
);

CREATE INDEX idx_runbooks_name ON runbooks(name);
CREATE INDEX idx_runbooks_level ON runbooks(automation_level);

-- Execution history
CREATE TABLE executions (
  execution_id TEXT PRIMARY KEY,
  runbook_id TEXT NOT NULL,
  runbook_version TEXT NOT NULL,
  runbook_name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN (
    'idle', 'validating', 'planning', 'awaiting_approval',
    'executing', 'rolling_back', 'completed', 'failed', 'cancelled'
  )),
  mode TEXT NOT NULL CHECK(mode IN ('production', 'simulation', 'dry-run')),
  success BOOLEAN,
  alert_data TEXT, -- JSON: AlertEvent
  context_data TEXT, -- JSON: ExecutionContext
  result_data TEXT, -- JSON: ExecutionResult
  started_at TEXT NOT NULL,
  completed_at TEXT,
  duration_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (runbook_id, runbook_version) REFERENCES runbooks(id, version)
);

CREATE INDEX idx_executions_runbook ON executions(runbook_id);
CREATE INDEX idx_executions_state ON executions(state);
CREATE INDEX idx_executions_started ON executions(started_at DESC);
CREATE INDEX idx_executions_success ON executions(success);

-- Step execution results
CREATE TABLE step_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL,
  step_id TEXT NOT NULL,
  step_name TEXT NOT NULL,
  action TEXT NOT NULL,
  executor TEXT NOT NULL,
  success BOOLEAN NOT NULL,
  output_data TEXT, -- JSON: step output
  error_data TEXT, -- JSON: error details
  rolled_back BOOLEAN DEFAULT FALSE,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX idx_step_results_execution ON step_results(execution_id);
CREATE INDEX idx_step_results_action ON step_results(action);
CREATE INDEX idx_step_results_success ON step_results(success);

-- Approval queue (L2 actions pending approval)
CREATE TABLE approval_queue (
  request_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  runbook_name TEXT NOT NULL,
  step_id TEXT NOT NULL,
  step_name TEXT NOT NULL,
  action TEXT NOT NULL,
  parameters TEXT NOT NULL, -- JSON
  simulation_result TEXT NOT NULL, -- JSON: SimulationResult
  status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'denied', 'expired')),
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  denial_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX idx_approval_status ON approval_queue(status);
CREATE INDEX idx_approval_requested ON approval_queue(requested_at DESC);
CREATE INDEX idx_approval_expires ON approval_queue(expires_at);

-- Audit log (immutable record of all actions)
CREATE TABLE audit_log (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  execution_id TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  details TEXT NOT NULL, -- JSON
  success BOOLEAN NOT NULL,
  FOREIGN KEY (execution_id) REFERENCES executions(execution_id) ON DELETE CASCADE
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_execution ON audit_log(execution_id);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_actor ON audit_log(actor);

-- Metrics (aggregated performance data)
CREATE TABLE metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  dimensions TEXT, -- JSON: additional dimensions (runbook_id, technique, etc.)
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(period_start, period_end, metric_name, dimensions)
);

CREATE INDEX idx_metrics_period ON metrics(period_start, period_end);
CREATE INDEX idx_metrics_name ON metrics(metric_name);

-- Registered adapters
CREATE TABLE adapters (
  name TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  config TEXT NOT NULL, -- JSON: AdapterConfig
  health_status TEXT CHECK(health_status IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
  last_health_check TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_adapters_enabled ON adapters(enabled);
CREATE INDEX idx_adapters_type ON adapters(type);

-- DetectForge integration (runbook suggestions by MITRE technique)
CREATE TABLE detectforge_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mitre_technique TEXT NOT NULL,
  runbook_id TEXT NOT NULL,
  confidence TEXT CHECK(confidence IN ('low', 'medium', 'high')),
  source TEXT, -- 'manual' or 'detectforge'
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (runbook_id) REFERENCES runbooks(id)
);

CREATE INDEX idx_detectforge_technique ON detectforge_mappings(mitre_technique);
CREATE INDEX idx_detectforge_runbook ON detectforge_mappings(runbook_id);
```

### 6.3 Database Migrations

Migrations are applied automatically on startup:

```typescript
async function runMigrations(db: Database): Promise<void> {
  const currentVersion = await db.get(
    'SELECT MAX(version) as version FROM schema_version'
  );

  const migrations = [
    { version: 2, up: migration_002_add_parallel_execution },
    { version: 3, up: migration_003_add_llm_cache },
    // ... more migrations
  ];

  for (const migration of migrations) {
    if (migration.version > currentVersion.version) {
      await migration.up(db);
      await db.run(
        'INSERT INTO schema_version (version) VALUES (?)',
        migration.version
      );
    }
  }
}
```

### 6.4 Backup and Recovery

**Automated backups:**
- Daily backup to `~/.runbookpilot/backups/runbookpilot-YYYY-MM-DD.db`
- Keep last 30 days
- Pre-migration backup

**Manual backup:**
```bash
runbookpilot db backup --output /path/to/backup.db
```

**Restore:**
```bash
runbookpilot db restore --input /path/to/backup.db
```

---

## 7. CLI Command Reference

### 7.1 Installation

```bash
# Install via npm
npm install -g runbookpilot

# Or via Bun
bun install -g runbookpilot

# Verify installation
runbookpilot --version
```

### 7.2 Global Options

All commands support these flags:

```
--config, -c <path>    Path to config file (default: ~/.runbookpilot/config.yml)
--db <path>            Path to database (default: ~/.runbookpilot/runbookpilot.db)
--log-level <level>    Log level: debug, info, warn, error (default: info)
--no-color             Disable colored output
--help, -h             Show help
--version, -v          Show version
```

### 7.3 Commands

#### `runbookpilot run`

Execute a runbook.

```bash
runbookpilot run <playbook.yml> [options]
```

**Options:**
```
--alert <file>         Alert event JSON file (ECS format)
--mode <mode>          Execution mode: production, simulation, dry-run (default: production)
--var <key>=<value>    Set context variable (can be repeated)
--wait                 Wait for execution to complete
--timeout <seconds>    Override runbook max_execution_time
--no-rollback          Disable automatic rollback on failure
```

**Examples:**
```bash
# Execute with alert
runbookpilot run playbooks/ransomware-containment.yml --alert alert.json

# Simulate execution
runbookpilot run playbooks/phishing-triage.yml --mode simulation --wait

# Dry-run validation
runbookpilot run playbooks/suspicious-login.yml --mode dry-run

# Override variables
runbookpilot run playbooks/test.yml \
  --var analyst_email=jdoe@example.com \
  --var severity=high
```

**Output:**
```
✓ Runbook validated: T1486 - Ransomware Containment
✓ Execution started: exec-550e8400-e29b-41d4-a716-446655440000

Step 1/7: Snapshot Memory.......................... ✓ (2.3s)
Step 2/7: Collect File Hashes...................... ✓ (1.1s)
Step 3/7: Isolate Host............................. ⏳ Awaiting approval

Approval required for step-03:
  Action: isolate_host
  Host: workstation-042 (10.20.30.40)
  Risk: HIGH

Approve with:
  runbookpilot approve exec-550e8400-e29b-41d4-a716-446655440000
```

#### `runbookpilot validate`

Validate runbook schema without execution.

```bash
runbookpilot validate <playbook.yml>
```

**Options:**
```
--strict              Enable strict validation (fail on warnings)
--schema <version>    Validate against specific schema version (default: latest)
```

**Examples:**
```bash
runbookpilot validate playbooks/ransomware-containment.yml
```

**Output:**
```
✓ Schema version: 1.0
✓ Metadata valid
✓ Triggers valid: 2 sources, 2 techniques, 1 platform
✓ Config valid: L2 automation
✓ Steps valid: 7 steps, 0 circular dependencies
✓ Adapters available: edr, active_directory, firewall, pagerduty, jira
✓ Template variables: 12 found, 12 resolvable

Runbook is valid.
```

#### `runbookpilot simulate`

Run runbook in simulation mode (alias for `run --mode simulation`).

```bash
runbookpilot simulate <playbook.yml> [options]
```

**Options:**
Same as `run` command.

**Output:**
```
Simulation Report:
------------------
Runbook: T1486 - Ransomware Containment
Mode: Simulation
Duration: 4.2s

Simulated Actions:
  ✓ step-01: snapshot_memory (2.1s)
    → Memory snapshot captured: 2.3 GB
  ✓ step-02: collect_file_metadata (1.1s)
    → SHA256: 44d88612fea8a8f36de82e1278abb02f
  ⚠ step-03: isolate_host (0.5s)
    → Would isolate workstation-042 from network
    → Risk: HIGH
  ⚠ step-04: disable_account (0.3s)
    → Would disable CORP\jdoe
    → Risk: MEDIUM

Risk Score: 85/100
Affected Assets:
  - workstation-042 (10.20.30.40)
  - CORP\jdoe

Simulation complete. No actions executed.
```

#### `runbookpilot approve`

Approve pending L2 action.

```bash
runbookpilot approve <execution-id> [options]
```

**Options:**
```
--step <step-id>       Approve specific step (default: all pending)
--comment <text>       Approval comment
--timeout <seconds>    Extended timeout after approval (default: runbook max)
```

**Examples:**
```bash
# Approve all pending steps
runbookpilot approve exec-550e8400-e29b-41d4-a716-446655440000

# Approve specific step with comment
runbookpilot approve exec-550e8400 \
  --step step-03 \
  --comment "Confirmed with IT manager, safe to isolate"
```

**Output:**
```
✓ Approval granted for execution exec-550e8400

Resuming execution...

Step 3/7: Isolate Host............................. ✓ (3.2s)
Step 4/7: Disable User Account..................... ✓ (1.5s)
Step 5/7: Block C2 IPs............................. ✓ (2.8s)
Step 6/7: Notify Incident Response................. ✓ (0.9s)
Step 7/7: Create Critical Incident................. ✓ (1.2s)

✓ Execution completed successfully (15.3s)
  Ticket: INCIDENT-12345
  Audit Log: /var/log/runbookpilot/exec-550e8400.log
```

#### `runbookpilot deny`

Deny pending L2 action.

```bash
runbookpilot deny <execution-id> [options]
```

**Options:**
```
--reason <text>        Denial reason (required)
--step <step-id>       Deny specific step (default: all pending)
```

**Examples:**
```bash
runbookpilot deny exec-550e8400 \
  --reason "False positive, benign activity confirmed"
```

#### `runbookpilot status`

Check execution status.

```bash
runbookpilot status [execution-id]
```

**Options:**
```
--watch, -w            Watch for updates (refresh every 2s)
--format <fmt>         Output format: text, json, table (default: text)
```

**Examples:**
```bash
# Show all recent executions
runbookpilot status

# Show specific execution
runbookpilot status exec-550e8400

# Watch execution progress
runbookpilot status exec-550e8400 --watch
```

**Output:**
```
Execution: exec-550e8400-e29b-41d4-a716-446655440000
Runbook: T1486 - Ransomware Containment (v1.0)
State: executing
Mode: production
Started: 2026-02-10 14:32:15 (2m ago)

Progress: 4/7 steps completed (57%)

✓ step-01: Snapshot Memory (2.3s)
✓ step-02: Collect File Hashes (1.1s)
✓ step-03: Isolate Host (3.2s)
✓ step-04: Disable User Account (1.5s)
⏳ step-05: Block C2 IPs (in progress, 2.1s elapsed)
⏸ step-06: Notify Incident Response (waiting)
⏸ step-07: Create Critical Incident (waiting)
```

#### `runbookpilot cancel`

Cancel running execution.

```bash
runbookpilot cancel <execution-id> [options]
```

**Options:**
```
--force                Skip rollback and cancel immediately
--reason <text>        Cancellation reason
```

**Examples:**
```bash
runbookpilot cancel exec-550e8400 --reason "Duplicate execution"
```

#### `runbookpilot metrics`

Display metrics dashboard.

```bash
runbookpilot metrics [options]
```

**Options:**
```
--period <period>      Time period: 1h, 24h, 7d, 30d (default: 24h)
--format <fmt>         Output format: text, json (default: text)
--export <file>        Export metrics to CSV/JSON
```

**Examples:**
```bash
# Last 24 hours
runbookpilot metrics

# Last 7 days
runbookpilot metrics --period 7d

# Export to CSV
runbookpilot metrics --period 30d --export metrics.csv
```

**Output:**
```
RunbookPilot Metrics (Last 24h)
===============================

Executions:
  Total: 42
  Successful: 38 (90.5%)
  Failed: 4 (9.5%)

Performance:
  Avg Execution Time: 12.4s
  Avg MTTD: 3.2s
  Avg MTTR: 45.6s

By Automation Level:
  L0: 15 (35.7%)
  L1: 20 (47.6%)
  L2: 7 (16.7%)

Top MITRE Techniques:
  T1078 (Valid Accounts): 12
  T1566 (Phishing): 8
  T1486 (Ransomware): 5
  T1059 (Command Execution): 4

Top Runbooks:
  1. Suspicious Login Enrichment: 12 runs
  2. Phishing Email Triage: 8 runs
  3. Ransomware Containment: 5 runs

Adapter Health:
  ✓ mock: healthy
  ✓ http: healthy
  ✓ email: healthy
```

#### `runbookpilot adapters`

Manage adapters.

```bash
runbookpilot adapters <subcommand>
```

**Subcommands:**

```bash
# List registered adapters
runbookpilot adapters list

# Show adapter details
runbookpilot adapters show <name>

# Health check
runbookpilot adapters health [name]

# Enable/disable adapter
runbookpilot adapters enable <name>
runbookpilot adapters disable <name>

# Test adapter
runbookpilot adapters test <name> --action <action> --params <json>
```

**Examples:**
```bash
# List all adapters
runbookpilot adapters list

# Check EDR adapter health
runbookpilot adapters health crowdstrike

# Test adapter action
runbookpilot adapters test mock \
  --action isolate_host \
  --params '{"host_id": "test-123"}'
```

#### `runbookpilot init`

Initialize new runbook from template.

```bash
runbookpilot init [options]
```

**Options:**
```
--name <name>          Runbook name
--level <L0|L1|L2>     Automation level (default: L0)
--technique <id>       MITRE technique ID
--template <name>      Use named template
--output <file>        Output file path
--interactive, -i      Interactive mode (default)
```

**Examples:**
```bash
# Interactive mode
runbookpilot init

# Quick init
runbookpilot init \
  --name "Account Lockout Response" \
  --level L1 \
  --technique T1110 \
  --output playbooks/account-lockout.yml
```

**Interactive prompts:**
```
RunbookPilot Runbook Generator
==============================

Runbook name: Account Lockout Response
Automation level (L0/L1/L2): L1
MITRE technique: T1110
Platform (windows/linux/macos/cloud/network/saas): windows
Detection source (sigma/edr_alert/siem_correlation/webhook/manual): siem_correlation

Add steps:
1. Enter step name (or 'done' to finish): Query Failed Login Attempts
   Action: query_siem
   Executor: splunk
   Timeout (seconds, default 60): 30

2. Enter step name (or 'done' to finish): Check Account Status
   Action: http_request
   Executor: http
   Timeout (seconds, default 60): 20

3. Enter step name (or 'done' to finish): done

✓ Runbook created: playbooks/account-lockout.yml
```

#### `runbookpilot config`

Manage configuration.

```bash
runbookpilot config <subcommand>
```

**Subcommands:**
```bash
# Show current config
runbookpilot config show

# Set config value
runbookpilot config set <key> <value>

# Edit config in editor
runbookpilot config edit

# Validate config
runbookpilot config validate
```

#### `runbookpilot db`

Database management.

```bash
runbookpilot db <subcommand>
```

**Subcommands:**
```bash
# Backup database
runbookpilot db backup --output <file>

# Restore database
runbookpilot db restore --input <file>

# Vacuum database (reclaim space)
runbookpilot db vacuum

# Run migrations
runbookpilot db migrate

# Show database info
runbookpilot db info
```

#### `runbookpilot logs`

View audit logs.

```bash
runbookpilot logs [options]
```

**Options:**
```
--execution <id>       Filter by execution ID
--runbook <id>         Filter by runbook ID
--event <type>         Filter by event type
--actor <name>         Filter by actor
--since <time>         Show logs since time (e.g., "1h ago", "2026-02-10")
--follow, -f           Follow log output
--limit <n>            Limit number of entries (default: 100)
```

**Examples:**
```bash
# Last 100 log entries
runbookpilot logs

# Follow logs in real-time
runbookpilot logs --follow

# Execution-specific logs
runbookpilot logs --execution exec-550e8400

# Approval events only
runbookpilot logs --event approval_granted --event approval_denied
```

---

## 8. LLM Integration Specification

### 8.1 LLM Usage Philosophy

**Where LLM IS used:**
- Generate enrichment summaries (synthesize threat intel data)
- Suggest runbook improvements (based on execution history)
- Generate investigation notes (analyst-friendly summaries)
- Explain runbook behavior (what will this runbook do?)

**Where LLM IS BANNED:**
- Execution decisions (which steps to run, whether to approve)
- Approval overrides (cannot approve L2 actions)
- Runtime playbook modification (cannot add/remove/modify steps)
- Parameter injection (cannot modify step parameters)
- State transitions (cannot change execution state)

**Principle:** LLM is a **read-only augmentation layer** that enhances human understanding. It never makes autonomous execution decisions.

### 8.2 OpenRouter Integration

RunbookPilot uses [OpenRouter](https://openrouter.ai/) for LLM access, enabling model flexibility and cost optimization.

**Configuration:**
```yaml
llm:
  enabled: true
  provider: openrouter
  api_key: ${OPENROUTER_API_KEY}
  models:
    default: anthropic/claude-3.5-sonnet  # General tasks
    fast: openai/gpt-4o-mini              # Quick summaries
    reasoning: openai/o1                  # Complex analysis
  timeout: 30000  # ms
  max_tokens: 4096
  temperature: 0.3  # Low temperature for deterministic output
  cache_ttl: 3600  # Cache responses for 1 hour
```

### 8.3 LLM Use Cases

#### Use Case 1: Enrichment Summary

**When:** After L1 enrichment runbook completes
**Model:** `fast` (gpt-4o-mini)
**Prompt:**

```typescript
const prompt = `
You are a security analyst assistant. Summarize the following threat intelligence enrichment data into a concise, actionable summary for a SOC analyst.

Alert Context:
- Source IP: ${alert.source.ip}
- User: ${alert.user.name}
- Action: ${alert.event.action}

Enrichment Data:
${JSON.stringify(enrichmentData, null, 2)}

Provide:
1. Risk assessment (Low/Medium/High/Critical)
2. Key findings (2-3 bullet points)
3. Recommended action (Escalate / Monitor / Close)

Format as markdown.
`;
```

**Output:**
```markdown
## Risk Assessment: HIGH

## Key Findings:
- Source IP (185.220.101.5) flagged by 3/5 threat feeds as C2 infrastructure
- User account (jdoe) shows anomalous login pattern: first login from Russia
- Process execution indicates PowerShell obfuscation techniques

## Recommended Action:
**ESCALATE** - Initiate L2 containment runbook immediately.
```

#### Use Case 2: Runbook Suggestion

**When:** Alert received with no matching runbook
**Model:** `default` (claude-3.5-sonnet)
**Prompt:**

```typescript
const prompt = `
You are a detection engineering expert. Based on the following alert, suggest which existing runbook best matches this scenario, or explain why no runbook exists.

Alert:
${JSON.stringify(alert, null, 2)}

Available Runbooks:
${runbooks.map(r => `- ${r.metadata.name} (${r.triggers.mitre_techniques.join(', ')})`).join('\n')}

Respond in JSON format:
{
  "suggested_runbook_id": "uuid or null",
  "confidence": "low|medium|high",
  "reasoning": "explanation"
}
`;
```

**Output:**
```json
{
  "suggested_runbook_id": "770e8400-e29b-41d4-a716-446655440002",
  "confidence": "high",
  "reasoning": "Alert matches T1486 (ransomware) technique with high severity. The 'Ransomware Containment' runbook is specifically designed for this scenario and includes network isolation, account disabling, and incident notification."
}
```

#### Use Case 3: Investigation Notes

**When:** Execution completes (any level)
**Model:** `default` (claude-3.5-sonnet)
**Prompt:**

```typescript
const prompt = `
You are a SOC documentation assistant. Generate investigation notes for the following runbook execution. Include what was done, key findings, and next steps.

Execution Summary:
- Runbook: ${execution.runbook_name}
- Duration: ${execution.duration_ms}ms
- Success: ${execution.success}
- Steps Executed: ${execution.steps_executed.length}

Step Results:
${execution.steps_executed.map(step => `
- ${step.step_name}: ${step.success ? 'SUCCESS' : 'FAILED'}
  Output: ${JSON.stringify(step.output)}
`).join('\n')}

Generate investigation notes in markdown format suitable for a JIRA ticket.
`;
```

**Output:**
```markdown
## Investigation Summary

**Incident:** T1486 Ransomware Detection on workstation-042
**Runbook:** Ransomware Containment (L2)
**Duration:** 15.3 seconds
**Outcome:** Successful containment

## Actions Taken

1. **Memory Snapshot Captured** (2.3s)
   - Snapshot ID: mem-snapshot-20260210-143215
   - Size: 2.3 GB
   - Preserved for forensic analysis

2. **File Hashes Collected** (1.1s)
   - Malicious executable: `invoice.pdf.exe`
   - SHA256: `44d88612fea8a8f36de82e1278abb02f`
   - Confirmed malicious by VirusTotal (58/70 detections)

3. **Host Isolated** (3.2s)
   - workstation-042 (10.20.30.40) isolated from corporate network
   - EDR management channel maintained for remote access

4. **Account Disabled** (1.5s)
   - User: CORP\jdoe
   - Reason: Automated containment - T1486 ransomware

5. **C2 IP Blocked** (2.8s)
   - Blocked egress to 185.220.101.5 (Russia)
   - Firewall rule: AUTO-BLOCK-T1486-exec-550e8400
   - Expiry: 24 hours

## Next Steps

1. **Immediate:**
   - [ ] Forensic analysis of memory snapshot
   - [ ] Identify patient zero (initial infection vector)
   - [ ] Check backup integrity

2. **Short-term:**
   - [ ] Scan all endpoints for IOCs (hash, C2 IP)
   - [ ] Review email gateway for phishing campaign
   - [ ] Interview user (jdoe) about suspicious activity

3. **Recovery:**
   - [ ] Coordinate with management on recovery strategy
   - [ ] Plan host reimaging
   - [ ] Restore user access after validation
```

#### Use Case 4: Runbook Explanation

**When:** User runs `runbookpilot explain <runbook.yml>`
**Model:** `default` (claude-3.5-sonnet)
**Prompt:**

```typescript
const prompt = `
You are a security automation expert. Explain what this runbook does in plain English, suitable for a junior SOC analyst.

Runbook:
${runbookYaml}

Provide:
1. Purpose (1-2 sentences)
2. When it runs (triggers)
3. What it does (step-by-step)
4. Impact assessment (what changes it makes)
5. Human interaction required (approval points)

Use simple language, avoid jargon.
`;
```

### 8.4 Graceful Degradation

If LLM is unavailable (API down, rate limit, network error):

1. **Log warning** (not error)
2. **Continue execution** (LLM is optional)
3. **Fallback behavior:**
   - Enrichment summary: Return raw JSON
   - Runbook suggestion: Use technique-based matching
   - Investigation notes: Use template-based generation
   - Explanation: Return runbook YAML as-is

```typescript
async function generateEnrichmentSummary(data: any): Promise<string> {
  try {
    const summary = await llm.generate(enrichmentPrompt(data));
    return summary;
  } catch (error) {
    logger.warn('LLM unavailable, using fallback', { error });
    return formatEnrichmentFallback(data);
  }
}
```

### 8.5 LLM Response Caching

To reduce cost and latency, responses are cached:

```typescript
interface LLMCache {
  key: string;      // Hash of (prompt + model)
  response: string;
  created_at: string;
  expires_at: string;
}
```

**Cache strategy:**
- Enrichment summaries: 1 hour TTL
- Runbook suggestions: 24 hour TTL
- Investigation notes: No cache (unique per execution)
- Explanations: 7 day TTL (rarely changes)

### 8.6 Prompt Templates

All prompts are stored in `src/llm/prompts/`:

```
src/llm/prompts/
├── enrichment-summary.ts
├── runbook-suggestion.ts
├── investigation-notes.ts
└── runbook-explanation.ts
```

Each template is a function that returns a structured prompt with clear instructions, examples, and output format specification.

---

## 9. DetectForge Integration Protocol

### 9.1 Integration Overview

DetectForge generates detection rules (Sigma/YARA/Suricata) from threat intelligence. RunbookPilot operationalizes response when those detections fire.

**Handoff Flow:**
```
Threat Report → DetectForge → Detection Rule → SIEM/EDR → Alert → RunbookPilot → Response
```

### 9.2 DetectForge Metadata Format

DetectForge enriches alerts with `x-detectforge` metadata:

```typescript
interface DetectForgeMetadata {
  rule_id: string;           // DetectForge rule ID
  rule_name: string;         // Human-readable rule name
  rule_version: string;      // Rule version (semver)
  generated_at: string;      // ISO8601 timestamp
  intel_source?: string;     // Source report name
  intel_url?: string;        // URL to source report
  confidence: 'low' | 'medium' | 'high';
  suggested_runbook?: string; // Recommended runbook ID
}
```

**Example:**
```json
{
  "x-detectforge": {
    "rule_id": "df-sigma-ransomware-001",
    "rule_name": "Ransomware File Encryption Activity",
    "rule_version": "2.1.0",
    "generated_at": "2026-02-09T08:00:00Z",
    "intel_source": "CISA Alert AA26-040A",
    "intel_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-040a",
    "confidence": "high",
    "suggested_runbook": "770e8400-e29b-41d4-a716-446655440002"
  }
}
```

### 9.3 Technique-Based Runbook Matching

When alert arrives, RunbookPilot selects runbook based on:

1. **Explicit suggestion**: Use `x-detectforge.suggested_runbook` if present
2. **Technique matching**: Match `threat.technique.id` to `runbook.triggers.mitre_techniques`
3. **Platform filtering**: Filter by `runbook.triggers.platforms`
4. **Severity filtering**: Filter by `runbook.triggers.severity`
5. **LLM suggestion**: Use LLM to suggest best match (fallback)

**Matching algorithm:**
```typescript
function selectRunbook(alert: AlertEvent): Runbook | null {
  const runbooks = loadAllRunbooks();

  // 1. Explicit suggestion from DetectForge
  if (alert['x-detectforge']?.suggested_runbook) {
    const suggested = runbooks.find(r => r.id === alert['x-detectforge'].suggested_runbook);
    if (suggested) return suggested;
  }

  // 2. Technique-based matching
  const techniques = alert.threat?.technique?.id || [];
  const candidates = runbooks.filter(runbook => {
    const matchesTechnique = runbook.triggers.mitre_techniques.some(t =>
      techniques.includes(t)
    );
    const matchesPlatform = runbook.triggers.platforms.includes(
      alert.host?.os?.platform || 'unknown'
    );
    const matchesSeverity = !runbook.triggers.severity ||
      runbook.triggers.severity.includes(severityFromScore(alert.event.severity));

    return matchesTechnique && matchesPlatform && matchesSeverity;
  });

  // 3. Rank by confidence
  const ranked = candidates.sort((a, b) => {
    const aScore = calculateMatchScore(a, alert);
    const bScore = calculateMatchScore(b, alert);
    return bScore - aScore;
  });

  // 4. Return best match
  return ranked[0] || null;
}
```

### 9.4 File-Based Integration

**Export from DetectForge:**
```bash
# DetectForge exports alerts in ECS format
detectforge export --format ecs --output alert.json
```

**Import to RunbookPilot:**
```bash
# RunbookPilot ingests and executes
runbookpilot run <runbook.yml> --alert alert.json
```

### 9.5 Webhook Integration

RunbookPilot can receive alerts via HTTP webhook:

**Endpoint:** `POST /api/v1/alerts/ingest`

**Request:**
```json
{
  "alert": {
    /* ECS-formatted alert */
  },
  "options": {
    "mode": "production",
    "auto_execute": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "execution_id": "exec-550e8400-e29b-41d4-a716-446655440000",
  "runbook_id": "770e8400-e29b-41d4-a716-446655440002",
  "runbook_name": "T1486 - Ransomware Containment",
  "state": "executing"
}
```

**DetectForge webhook configuration:**
```yaml
# DetectForge config
outputs:
  - type: webhook
    url: https://runbookpilot.example.com/api/v1/alerts/ingest
    method: POST
    headers:
      Authorization: "Bearer ${RUNBOOKPILOT_API_KEY}"
    format: ecs
```

### 9.6 Docker Compose Integration

Run both systems together:

```yaml
version: '3.8'

services:
  detectforge:
    image: detectforge/detectforge:latest
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
    volumes:
      - ./intel:/app/intel
      - ./rules:/app/rules
    ports:
      - "3000:3000"

  runbookpilot:
    image: runbookpilot/runbookpilot:latest
    environment:
      - OPENROUTER_API_KEY=${OPENROUTER_API_KEY}
      - DETECTFORGE_WEBHOOK_URL=http://detectforge:3000/api/v1/alerts/export
    volumes:
      - ./playbooks:/app/playbooks
      - ./data:/app/data
    ports:
      - "3001:3001"
    depends_on:
      - detectforge

  # Shared SIEM connector (optional)
  siem-connector:
    image: logstash:latest
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    environment:
      - XPACK_MONITORING_ENABLED=false
```

### 9.7 Standalone Operation

RunbookPilot can operate without DetectForge:

- Ingest alerts from SIEM directly (Splunk, Elastic, etc.)
- Manual execution via CLI
- Webhook from any source (EDR, firewall, etc.)

DetectForge integration is **optional but recommended** for the complete detection-to-response pipeline.

### 9.8 Bidirectional Feedback

RunbookPilot can send execution results back to DetectForge for rule quality feedback:

**Feedback payload:**
```json
{
  "rule_id": "df-sigma-ransomware-001",
  "execution_id": "exec-550e8400",
  "outcome": "true_positive",
  "effectiveness_score": 95,
  "notes": "Containment successful, no lateral movement detected"
}
```

This feedback loop improves DetectForge's rule confidence scoring over time.

---

## 10. Error Codes and Handling

### 10.1 Error Code Taxonomy

All errors follow the format: `RBP-XXXX`

| Code Range | Category |
|------------|----------|
| RBP-1000 to RBP-1999 | Schema/Validation Errors |
| RBP-2000 to RBP-2999 | Execution Errors |
| RBP-3000 to RBP-3999 | Approval Errors |
| RBP-4000 to RBP-4999 | Integration Errors |
| RBP-5000 to RBP-5999 | System Errors |

### 10.2 Schema Errors (RBP-1XXX)

| Code | Error | Description | Resolution |
|------|-------|-------------|------------|
| RBP-1001 | INVALID_YAML | YAML syntax error | Fix YAML syntax |
| RBP-1002 | MISSING_REQUIRED_FIELD | Required field missing | Add missing field |
| RBP-1003 | INVALID_FIELD_TYPE | Field has wrong type | Correct field type |
| RBP-1004 | INVALID_FIELD_VALUE | Field value out of range/enum | Use valid value |
| RBP-1005 | INVALID_RUNBOOK_ID | Runbook ID not valid UUID | Use UUID v4 |
| RBP-1006 | INVALID_MITRE_TECHNIQUE | Technique ID format invalid | Use TXXXX.XXX format |
| RBP-1007 | CIRCULAR_DEPENDENCY | Steps have circular dependencies | Remove circular depends_on |
| RBP-1008 | INVALID_STEP_REFERENCE | depends_on references non-existent step | Reference existing step |
| RBP-1009 | UNSUPPORTED_SCHEMA_VERSION | Schema version not supported | Upgrade RunbookPilot or downgrade schema |
| RBP-1010 | INVALID_TEMPLATE_SYNTAX | Template variable syntax error | Fix {{ template }} syntax |

### 10.3 Execution Errors (RBP-2XXX)

| Code | Error | Description | Resolution |
|------|-------|-------------|------------|
| RBP-2001 | ADAPTER_NOT_FOUND | Referenced adapter not registered | Register adapter or change executor |
| RBP-2002 | ADAPTER_INITIALIZATION_FAILED | Adapter failed to initialize | Check adapter config/credentials |
| RBP-2003 | ADAPTER_EXECUTION_FAILED | Adapter execution error | Check adapter logs |
| RBP-2004 | ADAPTER_TIMEOUT | Adapter exceeded timeout | Increase timeout or check adapter health |
| RBP-2005 | STEP_TIMEOUT | Step exceeded timeout | Increase step timeout |
| RBP-2006 | ROLLBACK_FAILED | Rollback execution failed | Manual intervention required |
| RBP-2007 | PARAMETER_RESOLUTION_FAILED | Template variable unresolvable | Check alert data/context variables |
| RBP-2008 | CONDITION_EVALUATION_FAILED | Guard condition threw error | Fix condition expression |
| RBP-2009 | EXECUTION_CANCELLED | Execution cancelled by user | N/A |
| RBP-2010 | MAX_EXECUTION_TIME_EXCEEDED | Runbook exceeded max_execution_time | Increase max_execution_time or optimize runbook |

### 10.4 Approval Errors (RBP-3XXX)

| Code | Error | Description | Resolution |
|------|-------|-------------|------------|
| RBP-3001 | APPROVAL_TIMEOUT | Approval request expired | Re-run with fresh approval |
| RBP-3002 | APPROVAL_DENIED | Approval explicitly denied | Review denial reason |
| RBP-3003 | APPROVAL_REQUEST_NOT_FOUND | Approval request ID invalid | Check execution ID |
| RBP-3004 | ALREADY_APPROVED | Approval already granted | N/A |
| RBP-3005 | UNAUTHORIZED_APPROVER | User not authorized to approve | Use authorized account |
| RBP-3006 | SIMULATION_FAILED | Pre-approval simulation failed | Check simulation logs |

### 10.5 Integration Errors (RBP-4XXX)

| Code | Error | Description | Resolution |
|------|-------|-------------|------------|
| RBP-4001 | INVALID_ALERT_FORMAT | Alert not valid ECS format | Validate alert schema |
| RBP-4002 | DETECTFORGE_HANDOFF_FAILED | DetectForge metadata invalid | Check x-detectforge fields |
| RBP-4003 | WEBHOOK_AUTH_FAILED | Webhook authentication failed | Check API key |
| RBP-4004 | WEBHOOK_TIMEOUT | Webhook request timed out | Increase timeout or check network |
| RBP-4005 | SIEM_CONNECTION_FAILED | Cannot connect to SIEM | Check SIEM connectivity |
| RBP-4006 | EDR_CONNECTION_FAILED | Cannot connect to EDR | Check EDR API credentials |
| RBP-4007 | LLM_API_FAILED | LLM API request failed | Check API key/quota |

### 10.6 System Errors (RBP-5XXX)

| Code | Error | Description | Resolution |
|------|-------|-------------|------------|
| RBP-5001 | DATABASE_ERROR | SQLite error | Check database file permissions |
| RBP-5002 | FILE_NOT_FOUND | Runbook file not found | Check file path |
| RBP-5003 | FILE_READ_ERROR | Cannot read runbook file | Check file permissions |
| RBP-5004 | CONFIGURATION_ERROR | Invalid system configuration | Check config.yml |
| RBP-5005 | NETWORK_ERROR | Network request failed | Check network connectivity |
| RBP-5006 | UNKNOWN_ERROR | Unhandled exception | Report bug with stack trace |

### 10.7 Error Response Format

All errors follow this structure:

```typescript
interface ExecutionError {
  code: string;           // Error code (RBP-XXXX)
  message: string;        // Human-readable message
  step_id?: string;       // Step where error occurred
  details?: Record<string, any>; // Additional context
  stack?: string;         // Stack trace (debug mode only)
  retryable: boolean;     // Whether retry might succeed
  resolution?: string;    // Suggested resolution
}
```

**Example:**
```json
{
  "code": "RBP-2002",
  "message": "Adapter initialization failed",
  "step_id": "step-03",
  "details": {
    "adapter": "crowdstrike",
    "error": "Invalid API credentials"
  },
  "retryable": false,
  "resolution": "Check CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET environment variables"
}
```

### 10.8 Error Handling Best Practices

1. **Graceful degradation**: Non-critical errors (LLM, notifications) shouldn't halt execution
2. **Clear error messages**: Include actionable resolution steps
3. **Retry logic**: Implement exponential backoff for retryable errors
4. **Audit logging**: All errors logged to audit_log table
5. **Alerting**: Critical errors (rollback failure) trigger alerts

```typescript
async function executeStepWithRetry(step: RunbookStep, ctx: ExecutionContext): Promise<StepResult> {
  const maxAttempts = step.retry?.max_attempts || 1;
  let lastError: ExecutionError | undefined;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await executeStep(step, ctx);
    } catch (error) {
      lastError = normalizeError(error);

      if (!lastError.retryable || attempt === maxAttempts) {
        throw lastError;
      }

      const backoff = calculateBackoff(attempt, step.retry);
      await sleep(backoff);
    }
  }

  throw lastError;
}
```

---

## Appendix A: Schema Validation

RunbookPilot uses [Zod](https://zod.dev/) for runtime schema validation:

```typescript
import { z } from 'zod';

const AutomationLevelSchema = z.enum(['L0', 'L1', 'L2']);
const ExecutionModeSchema = z.enum(['production', 'simulation', 'dry-run']);
const StepActionSchema = z.enum([
  'isolate_host', 'restore_connectivity', 'block_ip', /* ... */
]);

const RunbookSchema = z.object({
  id: z.string().uuid(),
  version: z.string().regex(/^\d+\.\d+$/),
  metadata: z.object({
    name: z.string().min(3).max(100),
    description: z.string().optional(),
    author: z.string().optional(),
    created: z.string().datetime(),
    updated: z.string().datetime(),
    tags: z.array(z.string()).min(1).max(20),
    references: z.array(z.string().url()).optional(),
  }),
  triggers: z.object({
    detection_sources: z.array(z.string()).min(1),
    mitre_techniques: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).min(1),
    platforms: z.array(z.string()).min(1),
    severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
  }),
  config: z.object({
    automation_level: AutomationLevelSchema,
    max_execution_time: z.number().int().min(60).max(3600),
    requires_approval: z.boolean(),
    approval_timeout: z.number().int().min(300).max(7200).optional(),
    parallel_execution: z.boolean().optional(),
    rollback_on_failure: z.boolean().optional(),
  }),
  steps: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string().optional(),
    action: StepActionSchema,
    executor: z.string(),
    parameters: z.record(z.any()),
    approval_required: z.boolean().optional(),
    rollback: z.object({
      action: StepActionSchema,
      executor: z.string().optional(),
      parameters: z.record(z.any()),
      timeout: z.number().int().min(5),
      on_error: z.enum(['halt', 'continue', 'skip']).optional(),
    }).optional(),
    on_error: z.enum(['halt', 'continue', 'skip']),
    timeout: z.number().int().min(5).max(600),
    depends_on: z.array(z.string()).optional(),
    condition: z.string().optional(),
  })).min(1).max(50),
});

// Validate runbook
function validateRunbook(yaml: string): Runbook {
  const parsed = YAML.parse(yaml);
  return RunbookSchema.parse(parsed.runbook);
}
```

---

## Appendix B: Reference Implementations

### Reference Playbooks
- **L0 Runbook:** Phishing Email Investigation
- **L1 Runbook:** Suspicious Login Enrichment
- **L2 Runbook:** Ransomware Containment

See [Section 2.5](#25-example-playbooks) for full YAML.

### Reference Adapters
- **Mock Adapter:** Testing and development (see [Section 5.5](#55-mock-adapter-reference-implementation))
- **HTTP Adapter:** REST API integration
- **Shell Adapter:** Script execution

---

## Appendix C: Security Considerations

### Authentication
- CLI commands authenticate via API key or OAuth2
- Webhook endpoints require Bearer token authentication
- Adapter credentials stored encrypted in SQLite

### Authorization
- Approval actions require authorized user role
- L2 runbooks require approval by default
- Audit log tracks all actions by actor

### Secrets Management
- Environment variables for sensitive config
- Integration with HashiCorp Vault (optional)
- Adapter credentials encrypted at rest

### Network Security
- HTTPS required for all webhook/API communication
- Certificate pinning for critical integrations
- Firewall allowlist for outbound adapter connections

---

## Appendix D: Performance Optimization

### Database Optimization
- Indexes on frequent query columns
- Periodic VACUUM to reclaim space
- Connection pooling for concurrent access

### Adapter Optimization
- Connection pooling per adapter
- Request batching where possible
- Circuit breaker pattern for failing adapters

### LLM Optimization
- Response caching (see [Section 8.5](#85-llm-response-caching))
- Model selection based on task complexity
- Streaming responses for long outputs

---

## Appendix E: Testing Strategy

### Unit Tests
- All TypeScript types validated
- Schema validation rules tested
- State machine transitions tested
- Adapter interface compliance tested

### Integration Tests
- End-to-end runbook execution (mock adapters)
- Webhook ingestion
- Approval flow
- Rollback behavior

### Simulation Tests
- L2 runbook simulation accuracy
- Risk score calculation
- Affected assets identification

### Load Tests
- Concurrent execution handling
- Database performance under load
- Adapter timeout behavior

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-02-10 | Initial release |

---

**End of Technical Reference**

For implementation questions, see the [RunbookPilot GitHub repository](https://github.com/Sim-Security/RunbookPilot) or contact the maintainers.
