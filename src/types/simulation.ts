/**
 * RunbookPilot L2 Simulation Types
 *
 * Detailed types for the L2 simulation engine, approval queue,
 * impact assessment, confidence scoring, and accuracy tracking.
 * The basic SimulationResult/SimulatedAction types live in playbook.ts;
 * this module adds the richer internal types used by the simulation engine.
 *
 * @module types/simulation
 */

import type {
  StepAction,
  ExecutionMode,
  AutomationLevel,
  ApprovalStatus,
} from './playbook.ts';

// ---------------------------------------------------------------------------
// Simulation Context
// ---------------------------------------------------------------------------

/**
 * Context for an L2 simulation execution.
 * Extends the normal execution context concept with simulation-specific state.
 */
export interface SimulationContext {
  simulation_id: string;
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  mode: ExecutionMode; // always 'simulation' for L2
  started_at: string; // ISO8601
  completed_at?: string; // ISO8601
  is_dry_run: boolean;
  enable_l2: boolean;
  approval_timeout: number; // seconds
  variables: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Simulated Step (detailed per-step result)
// ---------------------------------------------------------------------------

/**
 * Detailed result for a single simulated step.
 * More detailed than SimulatedAction in playbook.ts.
 */
export interface SimulatedStep {
  step_id: string;
  step_name: string;
  action: StepAction;
  executor: string;
  parameters: Record<string, unknown>;
  predicted_result: unknown;
  confidence: number; // 0.0 – 1.0
  side_effects: string[];
  rollback_action?: string;
  rollback_parameters?: Record<string, unknown>;
  validations_passed: boolean;
  validation_errors: string[];
  is_write_action: boolean;
  duration_ms: number; // how long the simulation took
  impact?: ImpactAssessment;
}

// ---------------------------------------------------------------------------
// Impact Assessment
// ---------------------------------------------------------------------------

/** Risk level for an assessed action. */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Impact assessment for a single simulated action.
 */
export interface ImpactAssessment {
  action: StepAction;
  risk_score: number; // 1–10
  risk_level: RiskLevel;
  blast_radius: BlastRadius;
  dependencies: string[]; // affected services / systems
  summary: string; // human-readable impact summary
  reversible: boolean;
  rollback_available: boolean;
}

/**
 * Blast radius: how many hosts/users/services are affected.
 */
export interface BlastRadius {
  hosts_affected: number;
  users_affected: number;
  services_affected: number;
  affected_assets: string[]; // list of asset identifiers
}

// ---------------------------------------------------------------------------
// Simulation Report
// ---------------------------------------------------------------------------

/**
 * Full simulation report generated after L2 dry-run.
 */
export interface SimulationReport {
  simulation_id: string;
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  timestamp: string; // ISO8601
  steps: SimulatedStep[];
  predicted_outcome: 'SUCCESS' | 'PARTIAL' | 'FAILURE';
  overall_confidence: number; // 0.0 – 1.0
  overall_risk_score: number; // 1–10
  overall_risk_level: RiskLevel;
  estimated_duration_ms: number;
  risks_identified: string[];
  affected_assets: string[];
  rollback_plan: RollbackPlan;
  detectforge_confidence?: number; // from x-detectforge.confidence, if available
  detectforge_rule_id?: string;
}

/**
 * Rollback plan for the entire simulation.
 */
export interface RollbackPlan {
  available: boolean;
  steps: RollbackStep[];
  estimated_duration_ms: number;
}

/**
 * Single rollback step.
 */
export interface RollbackStep {
  step_id: string;
  original_action: StepAction;
  rollback_action: StepAction;
  executor: string;
  parameters: Record<string, unknown>;
  timeout: number; // seconds
}

// ---------------------------------------------------------------------------
// Confidence Scoring
// ---------------------------------------------------------------------------

/**
 * Breakdown of how confidence was calculated for a step.
 */
export interface ConfidenceBreakdown {
  parameter_validation: number; // 0.0 – 1.0
  adapter_health: number; // 0.0 – 1.0
  rollback_available: number; // 0.0 or 1.0
  historical_success_rate?: number; // 0.0 – 1.0
  detectforge_confidence?: number; // 0.0 – 1.0
  overall: number; // weighted average
}

/**
 * Confidence display for CLI output.
 */
export interface ConfidenceDisplay {
  score: number; // 0.0 – 1.0
  label: 'high' | 'medium' | 'low';
  color: 'green' | 'yellow' | 'red';
  source: string; // e.g. 'detectforge', 'parameter_validation', 'combined'
  rule_id?: string; // detection rule that triggered
}

// ---------------------------------------------------------------------------
// Approval Queue
// ---------------------------------------------------------------------------

/**
 * Row in the approval_queue table.
 */
export interface ApprovalQueueEntry {
  request_id: string;
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  step_id: string;
  step_name: string;
  action: StepAction;
  parameters: string; // JSON serialized
  simulation_result: string; // JSON serialized SimulationReport
  status: ApprovalStatus;
  requested_at: string; // ISO8601
  expires_at: string; // ISO8601
  approved_by?: string;
  approved_at?: string; // ISO8601
  denial_reason?: string;
  created_at: string; // ISO8601
  updated_at: string; // ISO8601
}

/**
 * Options for creating an approval request.
 */
export interface CreateApprovalOptions {
  execution_id: string;
  runbook_id: string;
  runbook_name: string;
  step_id: string;
  step_name: string;
  action: StepAction;
  parameters: Record<string, unknown>;
  simulation_report: SimulationReport;
  ttl_seconds: number; // time-to-live before auto-expire
}

/**
 * Options for listing approval queue entries.
 */
export interface ListApprovalOptions {
  status?: ApprovalStatus;
  execution_id?: string;
  runbook_id?: string;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// Accuracy Report (comparing simulation to actual execution)
// ---------------------------------------------------------------------------

/**
 * Compares predicted simulation results to actual execution results.
 */
export interface AccuracyReport {
  simulation_id: string;
  execution_id: string;
  overall_accuracy: number; // 0.0 – 1.0
  correct_predictions: number;
  incorrect_predictions: number;
  total_steps: number;
  step_differences: StepDifference[];
  generated_at: string; // ISO8601
}

/**
 * Difference between predicted and actual result for a single step.
 */
export interface StepDifference {
  step_id: string;
  action: StepAction;
  predicted_success: boolean;
  actual_success: boolean;
  predicted_output: unknown;
  actual_output: unknown;
  match: boolean;
}

// ---------------------------------------------------------------------------
// Simulation Metrics
// ---------------------------------------------------------------------------

/**
 * Aggregate simulation metrics stored in SQLite.
 */
export interface SimulationMetricsRecord {
  id: string;
  period_start: string; // ISO8601
  period_end: string; // ISO8601
  total_simulations: number;
  total_approvals: number;
  total_denials: number;
  total_expirations: number;
  total_executions_from_queue: number;
  approval_rate: number; // 0.0 – 1.0
  avg_approval_latency_ms: number;
  action_distribution: Record<string, number>; // action -> count
  avg_risk_score: number;
  avg_confidence: number;
  accuracy_rate?: number; // 0.0 – 1.0, simulation prediction accuracy
}

// ---------------------------------------------------------------------------
// Policy Enforcement
// ---------------------------------------------------------------------------

/**
 * Automation policy that governs what actions can run at which levels.
 */
export interface AutomationPolicy {
  name: string;
  description?: string;
  rules: PolicyRule[];
}

/**
 * Individual policy rule.
 */
export interface PolicyRule {
  action: StepAction | '*'; // '*' matches all actions
  min_level: AutomationLevel; // minimum level required
  requires_approval: boolean;
  max_risk_score?: number; // block if risk exceeds this
  allowed_modes: ExecutionMode[];
  admin_override: boolean; // allow admin to bypass
}

/**
 * Result of a policy check.
 */
export interface PolicyCheckResult {
  allowed: boolean;
  action: StepAction;
  requested_level: AutomationLevel;
  required_level: AutomationLevel;
  requires_approval: boolean;
  violations: PolicyViolation[];
}

/**
 * Policy violation detail.
 */
export interface PolicyViolation {
  rule: string;
  message: string;
  severity: 'warning' | 'error';
}
