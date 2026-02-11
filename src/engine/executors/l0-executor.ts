/**
 * L0 Executor — Display Only (Recommend)
 *
 * Displays playbook steps as a checklist for manual execution.
 * No automated execution — analyst must complete each step manually.
 *
 * @module engine/executors/l0-executor
 */

import type {
  Runbook,
  RunbookStep,
  StepResult,
  ExecutionResult,
  ExecutionMetrics,
} from '../../types/playbook.ts';
import type { TemplateContext } from '../templating.ts';
import { resolveStepParameters } from '../templating.ts';
import { evaluateCondition } from '../step-executor.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface L0StepDisplay {
  stepId: string;
  name: string;
  description?: string;
  action: string;
  executor: string;
  parameters: Record<string, unknown>;
  dependsOn: string[];
  condition?: string;
  conditionMet: boolean;
}

export interface L0ExecutionPlan {
  runbookName: string;
  automationLevel: 'L0';
  totalSteps: number;
  steps: L0StepDisplay[];
}

/**
 * Callback for L0 step confirmation.
 * Called for each step — returns true if the analyst confirmed completion.
 */
export type L0ConfirmCallback = (step: L0StepDisplay) => Promise<boolean>;

// ---------------------------------------------------------------------------
// L0 Executor
// ---------------------------------------------------------------------------

/**
 * Generate the L0 display plan (checklist) for a runbook.
 */
export function generateL0Plan(
  runbook: Runbook,
  ctx: TemplateContext,
): L0ExecutionPlan {
  const steps: L0StepDisplay[] = runbook.steps.map((step) => {
    const { resolved } = resolveStepParameters(step.parameters, ctx);
    const conditionMet = evaluateCondition(step.condition, ctx);

    return {
      stepId: step.id,
      name: step.name,
      description: step.description,
      action: step.action,
      executor: step.executor,
      parameters: resolved,
      dependsOn: step.depends_on ?? [],
      condition: step.condition,
      conditionMet,
    };
  });

  return {
    runbookName: runbook.metadata.name,
    automationLevel: 'L0',
    totalSteps: steps.length,
    steps,
  };
}

/**
 * Execute L0 runbook — walks through each step, calling the confirm callback.
 * Steps with unmet conditions are skipped.
 */
export async function executeL0(
  runbook: Runbook,
  ctx: TemplateContext,
  confirmStep: L0ConfirmCallback,
): Promise<ExecutionResult> {
  const executionId = ctx.context?.['execution_id'] as string ?? 'unknown';
  const startedAt = new Date().toISOString();
  const startTime = Date.now();
  const stepsExecuted: StepResult[] = [];

  const plan = generateL0Plan(runbook, ctx);
  const completedSteps = new Set<string>();

  for (const display of plan.steps) {
    const stepStartTime = Date.now();
    const stepStartedAt = new Date().toISOString();

    // Check dependencies
    const depsReady = display.dependsOn.every((dep) => completedSteps.has(dep));
    if (!depsReady) {
      stepsExecuted.push(makeSkippedResult(display, stepStartedAt, 'Dependencies not met'));
      continue;
    }

    // Check condition
    if (!display.conditionMet) {
      stepsExecuted.push(makeSkippedResult(display, stepStartedAt, 'Condition not met'));
      completedSteps.add(display.stepId);
      continue;
    }

    // Ask analyst to confirm
    const confirmed = await confirmStep(display);

    const stepResult: StepResult = {
      step_id: display.stepId,
      step_name: display.name,
      action: display.action as RunbookStep['action'],
      success: confirmed,
      started_at: stepStartedAt,
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - stepStartTime,
      output: { manual_confirmation: confirmed },
    };

    stepsExecuted.push(stepResult);

    if (confirmed) {
      completedSteps.add(display.stepId);
    } else {
      // L0: if analyst rejects a step, check on_error
      const originalStep = runbook.steps.find((s) => s.id === display.stepId);
      if (originalStep?.on_error === 'halt') break;
    }
  }

  const metrics = buildMetrics(stepsExecuted, startTime);

  return {
    execution_id: executionId,
    runbook_id: runbook.id,
    success: stepsExecuted.every((s) => s.success),
    state: stepsExecuted.every((s) => s.success) ? 'completed' : 'failed',
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    duration_ms: Date.now() - startTime,
    steps_executed: stepsExecuted,
    metrics,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSkippedResult(display: L0StepDisplay, startedAt: string, reason: string): StepResult {
  return {
    step_id: display.stepId,
    step_name: display.name,
    action: display.action as RunbookStep['action'],
    success: true,
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    duration_ms: 0,
    output: { skipped: true, reason },
  };
}

function buildMetrics(steps: StepResult[], startTime: number): ExecutionMetrics {
  return {
    total_steps: steps.length,
    successful_steps: steps.filter((s) => s.success).length,
    failed_steps: steps.filter((s) => !s.success).length,
    skipped_steps: steps.filter((s) => {
      const output = s.output as Record<string, unknown> | undefined;
      return output?.['skipped'] === true;
    }).length,
    rollbacks_triggered: 0,
    duration_ms: Date.now() - startTime,
  };
}
