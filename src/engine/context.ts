/**
 * Execution Context Manager for RunbookPilot
 *
 * Manages the runtime context for a single runbook execution. The context
 * accumulates step outputs, tracks completion, and supports deep variable
 * access via dot-notation paths. Designed for the deterministic state machine
 * engine -- no LLM in the execution path.
 *
 * Variable namespaces:
 *   alert.*             — fields from the triggering ECS alert event
 *   steps.{id}.output.* — outputs from completed (or in-progress) steps
 *   context.*           — top-level context fields (execution_id, mode, etc.)
 *   env.*               — process environment variables
 *
 * @module engine/context
 */

import { randomUUID } from 'node:crypto';

import type { AlertEvent } from '../types/ecs.ts';
import type {
  ExecutionMode,
  ExecutionState,
  ExecutionError,
  ExecutionContext,
} from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Create-params interface
// ---------------------------------------------------------------------------

/**
 * Parameters required to create a new execution context.
 */
export interface CreateContextParams {
  runbook_id: string;
  runbook_version: string;
  mode: ExecutionMode;
  alert?: AlertEvent;
}

// ---------------------------------------------------------------------------
// ExecutionContextManager
// ---------------------------------------------------------------------------

/**
 * Manages execution context for a single runbook run.
 *
 * Instances are created via the static `create()` factory and hold all
 * accumulated state for the run: step outputs, completion tracking,
 * current state, and error information.
 *
 * The `snapshot()` method returns a deep-cloned, serializable copy of
 * the context suitable for persistence to SQLite.
 *
 * The static `restore()` method reconstitutes a manager from a
 * previously-serialized snapshot.
 */
export class ExecutionContextManager {
  private readonly _context: ExecutionContext;

  // Step outputs stored separately keyed by step ID for deep access.
  private readonly _stepOutputs: Map<string, unknown>;

  // -----------------------------------------------------------------------
  // Private constructor — use static create() or restore()
  // -----------------------------------------------------------------------

  private constructor(context: ExecutionContext, stepOutputs?: Map<string, unknown>) {
    this._context = context;
    this._stepOutputs = stepOutputs ?? new Map();
  }

  // -----------------------------------------------------------------------
  // Static factories
  // -----------------------------------------------------------------------

  /**
   * Create a new execution context with a generated UUID.
   */
  static create(params: CreateContextParams): ExecutionContextManager {
    const context: ExecutionContext = {
      execution_id: randomUUID(),
      runbook_id: params.runbook_id,
      runbook_version: params.runbook_version,
      mode: params.mode,
      alert: params.alert,
      started_at: new Date().toISOString(),
      current_step: undefined,
      completed_steps: [],
      variables: {},
      state: 'idle',
      error: undefined,
    };

    return new ExecutionContextManager(context);
  }

  /**
   * Restore a context manager from a serialized snapshot (e.g., from DB).
   *
   * Accepts `unknown` and performs runtime narrowing to rebuild the
   * manager safely.
   */
  static restore(data: unknown): ExecutionContextManager {
    if (data === null || typeof data !== 'object') {
      throw new Error('Cannot restore ExecutionContext: data must be a non-null object');
    }

    const record = data as Record<string, unknown>;

    // Required string fields
    const requiredStrings: Array<keyof ExecutionContext & string> = [
      'execution_id',
      'runbook_id',
      'runbook_version',
      'started_at',
    ];

    for (const field of requiredStrings) {
      if (typeof record[field] !== 'string') {
        throw new Error(`Cannot restore ExecutionContext: missing or invalid field "${field}"`);
      }
    }

    // Mode
    const validModes: ExecutionMode[] = ['production', 'simulation', 'dry-run'];
    if (!validModes.includes(record['mode'] as ExecutionMode)) {
      throw new Error(`Cannot restore ExecutionContext: invalid mode "${String(record['mode'])}"`);
    }

    // State
    const validStates: ExecutionState[] = [
      'idle',
      'validating',
      'planning',
      'awaiting_approval',
      'executing',
      'rolling_back',
      'completed',
      'failed',
      'cancelled',
    ];
    if (!validStates.includes(record['state'] as ExecutionState)) {
      throw new Error(`Cannot restore ExecutionContext: invalid state "${String(record['state'])}"`);
    }

    // completed_steps
    const completedSteps = Array.isArray(record['completed_steps'])
      ? (record['completed_steps'] as unknown[]).filter(
          (s): s is string => typeof s === 'string',
        )
      : [];

    // variables
    const variables =
      record['variables'] !== null && typeof record['variables'] === 'object'
        ? (record['variables'] as Record<string, unknown>)
        : {};

    const context: ExecutionContext = {
      execution_id: record['execution_id'] as string,
      runbook_id: record['runbook_id'] as string,
      runbook_version: record['runbook_version'] as string,
      mode: record['mode'] as ExecutionMode,
      alert: record['alert'] as AlertEvent | undefined,
      started_at: record['started_at'] as string,
      current_step: typeof record['current_step'] === 'string' ? record['current_step'] : undefined,
      completed_steps: completedSteps,
      variables,
      state: record['state'] as ExecutionState,
      error: record['error'] as ExecutionError | undefined,
    };

    // Rebuild step outputs from variables.steps
    const stepOutputs = new Map<string, unknown>();
    const steps = variables['steps'];
    if (steps !== null && typeof steps === 'object') {
      const stepsRecord = steps as Record<string, unknown>;
      for (const stepId of Object.keys(stepsRecord)) {
        const stepData = stepsRecord[stepId];
        if (stepData !== null && typeof stepData === 'object') {
          const stepRecord = stepData as Record<string, unknown>;
          if ('output' in stepRecord) {
            stepOutputs.set(stepId, stepRecord['output']);
          }
        }
      }
    }

    return new ExecutionContextManager(context, stepOutputs);
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  /** The underlying execution context data (read-only reference). */
  get context(): Readonly<ExecutionContext> {
    return this._context;
  }

  /** Current execution ID. */
  get executionId(): string {
    return this._context.execution_id;
  }

  /** Current execution state. */
  get state(): ExecutionState {
    return this._context.state;
  }

  /** Current step ID, if any. */
  get currentStep(): string | undefined {
    return this._context.current_step;
  }

  /** IDs of all completed steps. */
  get completedSteps(): readonly string[] {
    return this._context.completed_steps;
  }

  // -----------------------------------------------------------------------
  // Variable access
  // -----------------------------------------------------------------------

  /**
   * Deep variable access using dot-notation paths.
   *
   * Supported namespaces:
   *   alert.host.hostname        — drill into the alert event
   *   steps.step-01.output.score — step output values
   *   context.execution_id       — top-level context fields
   *   env.HOME                   — process.env values
   *
   * Returns `undefined` when the path cannot be resolved.
   */
  getVariable(path: string): unknown {
    const segments = path.split('.');
    const namespace = segments[0];
    const rest = segments.slice(1);

    switch (namespace) {
      case 'alert':
        return this._resolve(this._context.alert, rest);

      case 'steps':
        return this._resolveStepPath(rest);

      case 'context':
        return this._resolve(this._context as unknown as Record<string, unknown>, rest);

      case 'env':
        return this._resolveEnv(rest);

      default:
        return undefined;
    }
  }

  /**
   * Resolve a step-namespace path: steps.{stepId}.output.{...}
   */
  private _resolveStepPath(segments: string[]): unknown {
    if (segments.length === 0) {
      // Return the entire steps map as a plain object
      const result: Record<string, unknown> = {};
      for (const [id, output] of this._stepOutputs) {
        result[id] = { output };
      }
      return result;
    }

    const stepId = segments[0];
    const rest = segments.slice(1);

    if (rest.length === 0) {
      // Return { output: ... } for the step
      const output = this._stepOutputs.get(stepId ?? '');
      return output !== undefined ? { output } : undefined;
    }

    // rest[0] should be 'output'
    if (rest[0] !== 'output') {
      return undefined;
    }

    const output = this._stepOutputs.get(stepId ?? '');
    const outputRest = rest.slice(1);
    return this._resolve(output, outputRest);
  }

  /**
   * Resolve an env-namespace path.
   */
  private _resolveEnv(segments: string[]): unknown {
    if (segments.length === 0) {
      return undefined;
    }
    // Env var name can contain dots in theory, but typically it's a single segment.
    // Join remaining segments with '.' to support env var names with dots.
    const envKey = segments.join('.');
    return process.env[envKey];
  }

  /**
   * Walk an object graph following the given path segments.
   * Returns `undefined` if any segment cannot be resolved.
   */
  private _resolve(root: unknown, segments: string[]): unknown {
    let current: unknown = root;

    for (const segment of segments) {
      if (current === null || current === undefined) {
        return undefined;
      }
      if (typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }

    return current;
  }

  // -----------------------------------------------------------------------
  // Step management
  // -----------------------------------------------------------------------

  /**
   * Store the output of a step, keyed under `steps.{stepId}.output`.
   */
  setStepOutput(stepId: string, output: unknown): void {
    this._stepOutputs.set(stepId, output);

    // Also store in variables for snapshot serialization
    if (this._context.variables['steps'] === undefined) {
      this._context.variables['steps'] = {} as Record<string, unknown>;
    }
    const steps = this._context.variables['steps'] as Record<string, unknown>;
    steps[stepId] = { output };
  }

  /**
   * Mark a step as completed: adds to completed_steps and clears current_step.
   */
  markStepCompleted(stepId: string): void {
    if (!this._context.completed_steps.includes(stepId)) {
      this._context.completed_steps.push(stepId);
    }
    if (this._context.current_step === stepId) {
      this._context.current_step = undefined;
    }
  }

  /**
   * Set the currently executing step.
   */
  setCurrentStep(stepId: string): void {
    this._context.current_step = stepId;
  }

  // -----------------------------------------------------------------------
  // State management
  // -----------------------------------------------------------------------

  /**
   * Transition the execution to a new state.
   */
  setState(state: ExecutionState): void {
    this._context.state = state;
  }

  /**
   * Attach an error to the context.
   */
  setError(error: ExecutionError): void {
    this._context.error = error;
  }

  // -----------------------------------------------------------------------
  // Serialization
  // -----------------------------------------------------------------------

  /**
   * Return a deep-cloned, serializable snapshot of the execution context.
   *
   * The snapshot is safe for persistence (e.g., to SQLite) and can be
   * restored with `ExecutionContextManager.restore()`.
   */
  snapshot(): ExecutionContext {
    return structuredClone(this._context);
  }
}
