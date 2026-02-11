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
