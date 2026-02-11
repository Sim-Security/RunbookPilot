/**
 * Rollback Engine
 *
 * Executes rollback steps in reverse order when a playbook execution fails.
 * Rollback is best-effort — individual rollback failures don't prevent
 * subsequent rollbacks from being attempted.
 *
 * @module engine/rollback
 */

import type {
  RunbookStep,
  StepResult,
  RollbackDefinition,
  ExecutionMode,
} from '../types/playbook.ts';
import type { AdapterResolver } from './step-executor.ts';
import type { TemplateContext } from './templating.ts';
import { resolveStepParameters } from './templating.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RollbackResult {
  success: boolean;
  stepsRolledBack: RollbackStepResult[];
  totalAttempted: number;
  totalSucceeded: number;
  totalFailed: number;
  durationMs: number;
}

export interface RollbackStepResult {
  stepId: string;
  stepName: string;
  rollbackAction: string;
  success: boolean;
  durationMs: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// Rollback Engine
// ---------------------------------------------------------------------------

/**
 * Execute rollbacks for completed steps in reverse order.
 *
 * @param completedSteps - Steps that were successfully executed (in execution order)
 * @param allSteps - All runbook steps (for looking up rollback definitions)
 * @param options - Adapter resolver and template context
 */
export async function executeRollback(
  completedSteps: StepResult[],
  allSteps: RunbookStep[],
  options: {
    mode: ExecutionMode;
    templateContext: TemplateContext;
    resolveAdapter: AdapterResolver;
  },
): Promise<RollbackResult> {
  const startTime = Date.now();
  const results: RollbackStepResult[] = [];

  // Build step lookup
  const stepMap = new Map(allSteps.map((s) => [s.id, s]));

  // Reverse order — rollback most recent steps first
  const stepsToRollback = [...completedSteps]
    .reverse()
    .filter((sr) => {
      const step = stepMap.get(sr.step_id);
      return step?.rollback !== undefined;
    });

  for (const completedStep of stepsToRollback) {
    const step = stepMap.get(completedStep.step_id);
    if (!step?.rollback) continue;

    const rollbackResult = await executeOneRollback(
      step,
      step.rollback,
      options,
    );

    results.push(rollbackResult);
  }

  const totalSucceeded = results.filter((r) => r.success).length;

  return {
    success: results.length === totalSucceeded,
    stepsRolledBack: results,
    totalAttempted: results.length,
    totalSucceeded,
    totalFailed: results.length - totalSucceeded,
    durationMs: Date.now() - startTime,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function executeOneRollback(
  step: RunbookStep,
  rollback: RollbackDefinition,
  options: {
    mode: ExecutionMode;
    templateContext: TemplateContext;
    resolveAdapter: AdapterResolver;
  },
): Promise<RollbackStepResult> {
  const startTime = Date.now();
  const executorName = rollback.executor ?? step.executor;
  const adapter = options.resolveAdapter(executorName);

  if (!adapter) {
    return {
      stepId: step.id,
      stepName: step.name,
      rollbackAction: rollback.action,
      success: false,
      durationMs: Date.now() - startTime,
      error: `Adapter '${executorName}' not found for rollback`,
    };
  }

  try {
    const { resolved } = resolveStepParameters(
      rollback.parameters,
      options.templateContext,
    );

    const timeoutMs = rollback.timeout * 1000;
    const result = await executeWithTimeout(
      adapter.execute(rollback.action, resolved, options.mode),
      timeoutMs,
    );

    if (!result.success) {
      return {
        stepId: step.id,
        stepName: step.name,
        rollbackAction: rollback.action,
        success: false,
        durationMs: Date.now() - startTime,
        error: result.error?.message ?? 'Rollback execution failed',
      };
    }

    return {
      stepId: step.id,
      stepName: step.name,
      rollbackAction: rollback.action,
      success: true,
      durationMs: Date.now() - startTime,
    };
  } catch (err) {
    return {
      stepId: step.id,
      stepName: step.name,
      rollbackAction: rollback.action,
      success: false,
      durationMs: Date.now() - startTime,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function executeWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Rollback timed out after ${timeoutMs}ms`)), timeoutMs),
    ),
  ]);
}
