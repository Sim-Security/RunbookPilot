/**
 * L1 Executor — Semi-Automated
 *
 * Auto-executes read-only actions (queries, enrichments).
 * Prompts for approval before write actions (isolation, blocking).
 *
 * @module engine/executors/l1-executor
 */

import type {
  Runbook,
  RunbookStep,
  StepResult,
  ExecutionResult,
  ExecutionMode,
  ExecutionMetrics,
} from '../../types/playbook.ts';
import type { TemplateContext } from '../templating.ts';
import type { AdapterResolver } from '../step-executor.ts';
import { executeStep, evaluateCondition } from '../step-executor.ts';
import { isReadOnly } from '../action-classifier.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface L1ApprovalRequest {
  stepId: string;
  stepName: string;
  action: string;
  executor: string;
  parameters: Record<string, unknown>;
  classification: 'write';
}

/**
 * Callback for L1 write-action approval.
 * Returns true if approved, false if denied.
 */
export type L1ApprovalCallback = (request: L1ApprovalRequest) => Promise<boolean>;

export interface L1ExecutorOptions {
  mode: ExecutionMode;
  templateContext: TemplateContext;
  resolveAdapter: AdapterResolver;
  requestApproval: L1ApprovalCallback;
}

// ---------------------------------------------------------------------------
// L1 Executor
// ---------------------------------------------------------------------------

/**
 * Execute L1 runbook — auto-execute reads, prompt for writes.
 */
export async function executeL1(
  runbook: Runbook,
  options: L1ExecutorOptions,
): Promise<ExecutionResult> {
  const executionId = options.templateContext.context?.['execution_id'] as string ?? 'unknown';
  const startedAt = new Date().toISOString();
  const startTime = Date.now();
  const stepsExecuted: StepResult[] = [];
  const completedSteps = new Set<string>();
  let halted = false;

  // Build execution order respecting depends_on
  const executionOrder = resolveExecutionOrder(runbook.steps);

  for (const step of executionOrder) {
    if (halted) break;

    // Check dependencies
    const depsReady = (step.depends_on ?? []).every((dep) => completedSteps.has(dep));
    if (!depsReady) {
      stepsExecuted.push(makeSkippedResult(step, 'Dependencies not met'));
      continue;
    }

    // Evaluate condition
    if (!evaluateCondition(step.condition, options.templateContext)) {
      stepsExecuted.push(makeSkippedResult(step, 'Condition not met'));
      completedSteps.add(step.id);
      continue;
    }

    // Check if write action needs approval
    if (!isReadOnly(step.action)) {
      // Step-level override
      const needsApproval = step.approval_required !== false;

      if (needsApproval) {
        const approved = await options.requestApproval({
          stepId: step.id,
          stepName: step.name,
          action: step.action,
          executor: step.executor,
          parameters: step.parameters,
          classification: 'write',
        });

        if (!approved) {
          stepsExecuted.push({
            step_id: step.id,
            step_name: step.name,
            action: step.action,
            success: false,
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            duration_ms: 0,
            error: {
              code: 'APPROVAL_DENIED',
              message: `Write action '${step.action}' denied by analyst`,
              step_id: step.id,
            },
          });

          if (step.on_error === 'halt') {
            halted = true;
          }
          continue;
        }
      }
    }

    // Execute the step
    const result = await executeStep(step, {
      mode: options.mode,
      templateContext: options.templateContext,
      resolveAdapter: options.resolveAdapter,
    });

    stepsExecuted.push(result.stepResult);

    if (result.stepResult.success) {
      completedSteps.add(step.id);

      // Update template context with step output
      if (options.templateContext.steps) {
        options.templateContext.steps[step.id] = {
          output: result.stepResult.output,
        };
      }
    } else if (!result.shouldContinue) {
      halted = true;
    }
  }

  const allSuccess = stepsExecuted.every((s) => s.success);
  const metrics = buildMetrics(stepsExecuted, startTime);

  return {
    execution_id: executionId,
    runbook_id: runbook.id,
    success: allSuccess,
    state: allSuccess ? 'completed' : halted ? 'failed' : 'completed',
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

/**
 * Resolve step execution order using topological sort on depends_on.
 * Falls back to declared order if no dependencies.
 */
function resolveExecutionOrder(steps: RunbookStep[]): RunbookStep[] {
  const stepMap = new Map(steps.map((s) => [s.id, s]));
  const visited = new Set<string>();
  const result: RunbookStep[] = [];

  function visit(stepId: string): void {
    if (visited.has(stepId)) return;
    visited.add(stepId);

    const step = stepMap.get(stepId);
    if (!step) return;

    for (const dep of step.depends_on ?? []) {
      visit(dep);
    }

    result.push(step);
  }

  for (const step of steps) {
    visit(step.id);
  }

  return result;
}

function makeSkippedResult(step: RunbookStep, reason: string): StepResult {
  return {
    step_id: step.id,
    step_name: step.name,
    action: step.action,
    success: true,
    started_at: new Date().toISOString(),
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
