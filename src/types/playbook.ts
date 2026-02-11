/**
 * RunbookPilot Core Playbook Types
 *
 * All types derived from TECHNICAL_REFERENCE.md Section 1.
 * Deterministic state machine types for SOC runbook automation
 * with graduated autonomy (L0/L1/L2).
 *
 * ECS types (AlertEvent, EventFields, etc.) live in ./ecs.ts and are
 * imported here where needed. This file owns everything else from Section 1.
 *
 * @module types/playbook
 */

import type { AlertEvent } from './ecs.ts';

// ---------------------------------------------------------------------------
// 1.1 Core Enums and Type Aliases
// ---------------------------------------------------------------------------

/**
 * Automation levels defining human-in-the-loop requirements.
 * L0: Recommend only (no execution)
 * L1: Auto-execute safe actions (e.g., enrichment, queries)
 * L2: Auto-execute impactful actions (requires approval in simulation mode)
 */
export type AutomationLevel = 'L0' | 'L1' | 'L2';

/**
 * Execution modes.
 * production: Execute actions against real systems
 * simulation: Simulate actions, log what would happen
 * dry-run: Validate runbook without execution or simulation
 */
export type ExecutionMode = 'production' | 'simulation' | 'dry-run';

/**
 * Available step actions (extensible via adapters).
 */
export type StepAction =
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
 * Error handling strategies for failed steps.
 */
export type OnError = 'halt' | 'continue' | 'skip';

/**
 * Detection sources that can trigger runbooks.
 */
export type DetectionSource =
  | 'sigma'
  | 'edr_alert'
  | 'siem_correlation'
  | 'webhook'
  | 'manual'
  | 'detectforge';

/**
 * Supported platforms.
 */
export type Platform = 'windows' | 'linux' | 'macos' | 'cloud' | 'network' | 'saas';

/**
 * Execution states for the deterministic state machine.
 */
export type ExecutionState =
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
 * Approval status for L2 actions.
 */
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

/**
 * Adapter health status.
 */
export type AdapterHealth = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

/**
 * Severity levels for alerts and triggers.
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Runbook Definition
// ---------------------------------------------------------------------------

/**
 * Complete runbook definition.
 */
export interface Runbook {
  id: string;
  version: string;
  metadata: RunbookMetadata;
  triggers: RunbookTrigger;
  config: RunbookConfig;
  steps: RunbookStep[];
}

/**
 * Runbook metadata.
 */
export interface RunbookMetadata {
  name: string;
  description?: string;
  author?: string;
  created: string; // ISO8601
  updated: string; // ISO8601
  tags: string[];
  references?: string[]; // URLs to documentation, threat reports, etc.
}

/**
 * Trigger conditions for runbook execution.
 */
export interface RunbookTrigger {
  detection_sources: DetectionSource[];
  mitre_techniques: string[]; // Format: TXXXX or TXXXX.XXX
  platforms: Platform[];
  severity?: Severity[]; // Optional severity filter
}

/**
 * Runbook configuration.
 */
export interface RunbookConfig {
  automation_level: AutomationLevel;
  max_execution_time: number; // seconds
  requires_approval: boolean; // Override for L1/L2
  approval_timeout?: number; // seconds, default 3600
  parallel_execution?: boolean; // Allow parallel steps, default false
  rollback_on_failure?: boolean; // Auto-rollback on error, default true
}

/**
 * Individual runbook step.
 */
export interface RunbookStep {
  id: string; // Unique within runbook (e.g., step-01)
  name: string;
  description?: string;
  action: StepAction;
  executor: string; // Adapter name (e.g., 'edr', 'siem', 'mock')
  parameters: Record<string, unknown>;
  approval_required?: boolean; // Override config-level setting
  rollback?: RollbackDefinition;
  on_error: OnError;
  timeout: number; // seconds
  depends_on?: string[]; // Step IDs that must complete first
  condition?: string; // JavaScript expression (optional guard)
}

/**
 * Rollback definition for a step.
 */
export interface RollbackDefinition {
  action: StepAction;
  executor?: string; // Defaults to parent step executor
  parameters: Record<string, unknown>;
  timeout: number; // seconds
  on_error?: OnError; // What to do if rollback fails
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Execution
// ---------------------------------------------------------------------------

/**
 * Execution context passed between steps.
 */
export interface ExecutionContext {
  execution_id: string;
  runbook_id: string;
  runbook_version: string;
  mode: ExecutionMode;
  alert?: AlertEvent; // Triggering alert (ECS-normalized)
  started_at: string; // ISO8601
  current_step?: string; // Current step ID
  completed_steps: string[]; // Step IDs
  variables: Record<string, unknown>; // Accumulated variables from steps
  state: ExecutionState;
  error?: ExecutionError;
}

/**
 * Result of runbook execution.
 */
export interface ExecutionResult {
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
 * Result of individual step execution.
 */
export interface StepResult {
  step_id: string;
  step_name: string;
  action: StepAction;
  success: boolean;
  started_at: string; // ISO8601
  completed_at: string; // ISO8601
  duration_ms: number;
  output?: unknown; // Action-specific output
  error?: ExecutionError;
  rolled_back?: boolean;
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Simulation
// ---------------------------------------------------------------------------

/**
 * Simulation-specific result (extends ExecutionResult).
 */
export interface SimulationResult extends ExecutionResult {
  simulated_actions: SimulatedAction[];
  risk_score: number; // 0-100
  affected_assets: string[];
  rollback_available: boolean;
}

/**
 * Simulated action details.
 */
export interface SimulatedAction {
  step_id: string;
  action: StepAction;
  executor: string;
  parameters: Record<string, unknown>;
  expected_outcome: string;
  risk_level: 'low' | 'medium' | 'high';
  affected_assets: string[];
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Approval & Audit
// ---------------------------------------------------------------------------

/**
 * Approval request for L2 actions.
 */
export interface ApprovalRequest {
  request_id: string;
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  step_id: string;
  step_name: string;
  action: StepAction;
  parameters: Record<string, unknown>;
  simulation_result: SimulationResult;
  requested_at: string; // ISO8601
  expires_at: string; // ISO8601
  status: ApprovalStatus;
  approved_by?: string;
  approved_at?: string; // ISO8601
  denial_reason?: string;
}

/**
 * Audit log entry.
 */
export interface AuditLogEntry {
  id: string;
  timestamp: string; // ISO8601
  execution_id: string;
  runbook_id: string;
  event_type:
    | 'execution_started'
    | 'execution_completed'
    | 'execution_failed'
    | 'step_executed'
    | 'step_failed'
    | 'approval_requested'
    | 'approval_granted'
    | 'approval_denied'
    | 'rollback_triggered';
  actor: string; // 'system' or user identifier
  details: Record<string, unknown>;
  success: boolean;
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Errors
// ---------------------------------------------------------------------------

/**
 * Execution error details.
 */
export interface ExecutionError {
  code: string; // Error code (see section 10 of TECHNICAL_REFERENCE)
  message: string;
  step_id?: string;
  details?: Record<string, unknown>;
  stack?: string;
}

/**
 * Adapter-specific error.
 */
export interface AdapterError extends ExecutionError {
  adapter: string;
  action: StepAction;
  retryable: boolean;
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Adapters
// ---------------------------------------------------------------------------

/**
 * Adapter configuration.
 */
export interface AdapterConfig {
  name: string;
  type: string; // 'edr', 'siem', 'firewall', 'iam', 'ticketing', 'mock'
  enabled: boolean;
  config: Record<string, unknown>; // Adapter-specific config
  credentials?: AdapterCredentials;
  timeout?: number; // Default timeout in seconds
  retry?: RetryConfig;
}

/**
 * Adapter credentials (stored encrypted).
 */
export interface AdapterCredentials {
  type: 'api_key' | 'oauth2' | 'basic_auth' | 'certificate';
  credentials: Record<string, string>; // Type-specific fields
}

/**
 * Retry configuration for adapter calls.
 */
export interface RetryConfig {
  max_attempts: number;
  backoff_ms: number;
  exponential: boolean;
}

/**
 * Adapter execution result.
 */
export interface AdapterResult {
  success: boolean;
  action: StepAction;
  executor: string;
  duration_ms: number;
  output?: unknown; // Action-specific output
  error?: AdapterError;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 1.2 Core Interfaces -- Metrics
// ---------------------------------------------------------------------------

/**
 * Execution metrics collected during a runbook run.
 */
export interface ExecutionMetrics {
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
 * Metrics snapshot for dashboard display.
 */
export interface MetricsSnapshot {
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
