/**
 * Adapter Interface Definition
 *
 * Defines the contract all vendor adapters must implement.
 * Extends the minimal StepAdapter from S1 with lifecycle management,
 * health checking, rollback support, and parameter validation.
 *
 * @module adapters/adapter-interface
 */

import type {
  StepAction,
  ExecutionMode,
  AdapterResult,
  AdapterConfig,
} from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Validation Result
// ---------------------------------------------------------------------------

/**
 * Result of parameter validation before execution.
 */
export interface ValidationResult {
  valid: boolean;
  errors?: string[];
}

// ---------------------------------------------------------------------------
// Simulation Result
// ---------------------------------------------------------------------------

/**
 * Result returned when executing in simulation mode.
 */
export interface SimulationResult {
  wouldSucceed: boolean;
  predictedOutput: unknown;
  confidence?: number;
  validationErrors?: string[];
  rollbackPlan: string;
}

// ---------------------------------------------------------------------------
// Adapter Capabilities
// ---------------------------------------------------------------------------

/**
 * Describes what an adapter can do. Returned by getCapabilities().
 */
export interface AdapterCapabilities {
  /** Actions this adapter handles. */
  supportedActions: readonly StepAction[];
  /** Whether the adapter supports simulation mode. */
  supportsSimulation: boolean;
  /** Whether the adapter supports rollback. */
  supportsRollback: boolean;
  /** Whether the adapter supports parameter validation. */
  supportsValidation: boolean;
  /** Maximum concurrent executions (0 = unlimited). */
  maxConcurrency: number;
}

// ---------------------------------------------------------------------------
// Adapter Health
// ---------------------------------------------------------------------------

export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

export interface HealthCheckResult {
  status: HealthStatus;
  message?: string;
  latencyMs?: number;
  checkedAt: string; // ISO 8601
}

// ---------------------------------------------------------------------------
// ActionAdapter Interface (Full Contract)
// ---------------------------------------------------------------------------

/**
 * Full adapter interface that all vendor adapters must implement.
 *
 * Lifecycle:
 *   1. `initialize(config)` — called once when adapter is registered
 *   2. `execute()` / `rollback()` — called per step during execution
 *   3. `healthCheck()` — called periodically and on demand
 *   4. `shutdown()` — called when adapter is unregistered or system shuts down
 */
export interface ActionAdapter {
  /** Unique adapter name (lowercase, no spaces). */
  readonly name: string;

  /** Adapter version (semver). */
  readonly version: string;

  /** List of actions this adapter can execute. */
  readonly supportedActions: readonly StepAction[];

  /**
   * Initialize adapter with configuration.
   * Called once when the adapter is registered with the registry.
   */
  initialize(config: AdapterConfig): Promise<void>;

  /**
   * Execute an action.
   *
   * @param action  - The action to perform (must be in supportedActions)
   * @param params  - Action-specific parameters (already template-resolved)
   * @param mode    - Execution mode: production, simulation, or dry-run
   * @returns Standardized result
   */
  execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult>;

  /**
   * Rollback a previously executed action.
   *
   * @param action - The original action that was executed
   * @param params - Original parameters, may include output from execute()
   * @returns Result of the rollback attempt
   */
  rollback(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult>;

  /**
   * Check adapter health / connectivity.
   */
  healthCheck(): Promise<HealthCheckResult>;

  /**
   * Return the capabilities of this adapter.
   */
  getCapabilities(): AdapterCapabilities;

  /**
   * Gracefully shut down the adapter.
   * Called when adapter is unregistered or system shuts down.
   * Optional — adapters with no cleanup can omit.
   */
  shutdown?(): Promise<void>;

  /**
   * Validate parameters for an action before execution.
   * Optional — called by the executor to catch errors early.
   */
  validateParameters?(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<ValidationResult>;
}

// ---------------------------------------------------------------------------
// Abstract Base Adapter
// ---------------------------------------------------------------------------

/**
 * Abstract base class that provides sensible defaults for optional methods.
 * Vendor adapters should extend this rather than implementing ActionAdapter
 * from scratch.
 */
export abstract class BaseAdapter implements ActionAdapter {
  abstract readonly name: string;
  abstract readonly version: string;
  abstract readonly supportedActions: readonly StepAction[];

  protected config?: AdapterConfig;
  protected initialized = false;

  async initialize(config: AdapterConfig): Promise<void> {
    this.config = config;
    this.initialized = true;
  }

  abstract execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult>;

  async rollback(
    action: StepAction,
    _params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    return {
      success: false,
      action,
      executor: this.name,
      duration_ms: 0,
      error: {
        code: 'ROLLBACK_NOT_SUPPORTED',
        message: `Adapter '${this.name}' does not support rollback for '${action}'`,
        adapter: this.name,
        action,
        retryable: false,
      },
    };
  }

  async healthCheck(): Promise<HealthCheckResult> {
    return {
      status: this.initialized ? 'healthy' : 'unknown',
      checkedAt: new Date().toISOString(),
    };
  }

  getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: false,
      supportsValidation: false,
      maxConcurrency: 0,
    };
  }

  async shutdown(): Promise<void> {
    this.initialized = false;
  }

  /**
   * Guard that throws if the adapter is not initialized.
   */
  protected assertInitialized(): void {
    if (!this.initialized) {
      throw new Error(`Adapter '${this.name}' is not initialized. Call initialize() first.`);
    }
  }

  /**
   * Guard that throws if the action is not supported.
   */
  protected assertSupportsAction(action: StepAction): void {
    if (!this.supportedActions.includes(action)) {
      throw new Error(
        `Adapter '${this.name}' does not support action '${action}'`,
      );
    }
  }

  /**
   * Helper to build a successful AdapterResult.
   */
  protected successResult(
    action: StepAction,
    durationMs: number,
    output?: unknown,
    metadata?: Record<string, unknown>,
  ): AdapterResult {
    return {
      success: true,
      action,
      executor: this.name,
      duration_ms: durationMs,
      output,
      metadata,
    };
  }

  /**
   * Helper to build a failed AdapterResult.
   */
  protected failureResult(
    action: StepAction,
    durationMs: number,
    code: string,
    message: string,
    retryable = false,
  ): AdapterResult {
    return {
      success: false,
      action,
      executor: this.name,
      duration_ms: durationMs,
      error: {
        code,
        message,
        adapter: this.name,
        action,
        retryable,
      },
    };
  }
}
