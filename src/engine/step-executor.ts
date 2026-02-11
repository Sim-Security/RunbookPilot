/**
 * Step Executor
 *
 * Executes individual playbook steps via adapters with error handling,
 * timeout enforcement, and result tracking.
 *
 * @module engine/step-executor
 */

import type {
  RunbookStep,
  StepResult,
  ExecutionMode,
  AdapterResult,
  StepAction,
} from '../types/playbook.ts';
import type { TemplateContext } from './templating.ts';
import { resolveStepParameters } from './templating.ts';

// ---------------------------------------------------------------------------
// Adapter Interface (minimal — full version in S2)
// ---------------------------------------------------------------------------

/**
 * Minimal adapter interface for step execution.
 * Full ActionAdapter interface is defined in S2 (adapter layer).
 */
export interface StepAdapter {
  readonly name: string;
  execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult>;
}

/**
 * Adapter resolver — given an executor name, returns the adapter.
 */
export type AdapterResolver = (executorName: string) => StepAdapter | undefined;

// ---------------------------------------------------------------------------
// Step Executor
// ---------------------------------------------------------------------------

export interface StepExecutorOptions {
  mode: ExecutionMode;
  templateContext: TemplateContext;
  resolveAdapter: AdapterResolver;
}

export interface StepExecutionResult {
  stepResult: StepResult;
  /** Whether execution should continue (based on on_error strategy) */
  shouldContinue: boolean;
  /** Whether this step needs rollback (completed but later steps failed) */
  hasRollback: boolean;
}

/**
 * Execute a single playbook step.
 */
export async function executeStep(
  step: RunbookStep,
  options: StepExecutorOptions,
): Promise<StepExecutionResult> {
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Resolve parameter templates
  const { resolved: resolvedParams } = resolveStepParameters(
    step.parameters,
    options.templateContext,
  );

  // Find adapter
  const adapter = options.resolveAdapter(step.executor);
  if (!adapter) {
    return buildFailureResult(step, startedAt, startTime, {
      code: 'ADAPTER_NOT_FOUND',
      message: `Adapter '${step.executor}' not found`,
      step_id: step.id,
    });
  }

  try {
    // Execute with timeout
    const adapterResult = await executeWithTimeout(
      adapter.execute(step.action, resolvedParams, options.mode),
      step.timeout * 1000,
      step.id,
    );

    if (!adapterResult.success) {
      return buildFailureResult(step, startedAt, startTime, {
        code: 'STEP_EXECUTION_FAILED',
        message: adapterResult.error?.message ?? 'Step execution failed',
        step_id: step.id,
        details: { adapterError: adapterResult.error },
      });
    }

    // Success
    const completedAt = new Date().toISOString();
    return {
      stepResult: {
        step_id: step.id,
        step_name: step.name,
        action: step.action,
        success: true,
        started_at: startedAt,
        completed_at: completedAt,
        duration_ms: Date.now() - startTime,
        output: adapterResult.output,
      },
      shouldContinue: true,
      hasRollback: step.rollback !== undefined,
    };
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));

    return buildFailureResult(step, startedAt, startTime, {
      code: error.name === 'StepTimeoutError' ? 'STEP_TIMEOUT' : 'STEP_EXECUTION_ERROR',
      message: error.message,
      step_id: step.id,
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildFailureResult(
  step: RunbookStep,
  startedAt: string,
  startTime: number,
  error: { code: string; message: string; step_id?: string; details?: Record<string, unknown> },
): StepExecutionResult {
  const completedAt = new Date().toISOString();
  const shouldContinue = step.on_error === 'continue' || step.on_error === 'skip';

  return {
    stepResult: {
      step_id: step.id,
      step_name: step.name,
      action: step.action,
      success: false,
      started_at: startedAt,
      completed_at: completedAt,
      duration_ms: Date.now() - startTime,
      error,
    },
    shouldContinue,
    hasRollback: step.rollback !== undefined,
  };
}

class StepTimeoutError extends Error {
  constructor(stepId: string, timeoutMs: number) {
    super(`Step '${stepId}' timed out after ${timeoutMs}ms`);
    this.name = 'StepTimeoutError';
  }
}

async function executeWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  stepId: string,
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new StepTimeoutError(stepId, timeoutMs)), timeoutMs),
    ),
  ]);
}

/**
 * Evaluate a step condition guard.
 * Returns true if the step should execute, false to skip.
 */
export function evaluateCondition(
  condition: string | undefined,
  ctx: TemplateContext,
): boolean {
  if (!condition) return true;

  try {
    // Simple expression evaluator for guard conditions
    // Resolve any templates in the condition first
    const { resolved } = resolveStepParameters({ _cond: condition }, ctx);
    const resolvedCondition = String(resolved['_cond']);

    // Basic boolean evaluation for common patterns
    if (resolvedCondition === 'true') return true;
    if (resolvedCondition === 'false') return false;

    // Numeric comparisons: "85 > 50" style
    const compMatch = /^(\d+(?:\.\d+)?)\s*(>|<|>=|<=|==|!=)\s*(\d+(?:\.\d+)?)$/.exec(resolvedCondition);
    if (compMatch) {
      const left = Number(compMatch[1]);
      const op = compMatch[2];
      const right = Number(compMatch[3]);
      switch (op) {
        case '>': return left > right;
        case '<': return left < right;
        case '>=': return left >= right;
        case '<=': return left <= right;
        case '==': return left === right;
        case '!=': return left !== right;
      }
    }

    // Default: treat non-empty resolved string as truthy
    return resolvedCondition.trim().length > 0;
  } catch {
    // If condition evaluation fails, default to executing the step
    return true;
  }
}
