/**
 * RunbookPilot Type Definitions -- Barrel Export
 *
 * Re-exports all types from the types module. Uses `export type` syntax
 * because verbatimModuleSyntax is enabled in tsconfig.json.
 *
 * @module types
 */

export type {
  // Core type aliases
  AutomationLevel,
  ExecutionMode,
  StepAction,
  OnError,
  DetectionSource,
  Platform,
  ExecutionState,
  ApprovalStatus,
  AdapterHealth,
  Severity,

  // Runbook definition interfaces
  Runbook,
  RunbookMetadata,
  RunbookTrigger,
  RunbookConfig,
  RunbookStep,
  RollbackDefinition,

  // Execution interfaces
  ExecutionContext,
  ExecutionResult,
  StepResult,

  // Simulation interfaces
  SimulationResult,
  SimulatedAction,

  // Approval & audit interfaces
  ApprovalRequest,
  AuditLogEntry,

  // Error interfaces
  ExecutionError,
  AdapterError,

  // Adapter interfaces
  AdapterConfig,
  AdapterCredentials,
  RetryConfig,
  AdapterResult,

  // Metrics interfaces
  ExecutionMetrics,
  MetricsSnapshot,
} from './playbook.ts';

export type {
  // ECS field interfaces
  EventFields,
  HostFields,
  NetworkFields,
  ProcessFields,
  FileFields,
  UserFields,
  ThreatFields,

  // DetectForge handoff
  DetectForgeMetadata,

  // Top-level alert event
  AlertEvent,
} from './ecs.ts';

export type {
  // Simulation context & steps
  SimulationContext,
  SimulatedStep,

  // Impact assessment
  RiskLevel,
  ImpactAssessment,
  BlastRadius,

  // Simulation report
  SimulationReport,
  RollbackPlan,
  RollbackStep,

  // Confidence scoring
  ConfidenceBreakdown,
  ConfidenceDisplay,

  // Approval queue
  ApprovalQueueEntry,
  CreateApprovalOptions,
  ListApprovalOptions,

  // Accuracy
  AccuracyReport,
  StepDifference,

  // Simulation metrics
  SimulationMetricsRecord,

  // Policy enforcement
  AutomationPolicy,
  PolicyRule,
  PolicyCheckResult,
  PolicyViolation,
} from './simulation.ts';
