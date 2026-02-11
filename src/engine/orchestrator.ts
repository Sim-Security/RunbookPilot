/**
 * Execution Orchestrator
 *
 * Coordinates the full lifecycle of a playbook execution:
 * load → validate → plan → [approve] → execute → complete/rollback
 *
 * @module engine/orchestrator
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  Runbook,
  ExecutionMode,
  ExecutionResult,
  StepResult,
} from '../types/playbook.ts';
import type { TemplateContext } from './templating.ts';
import type { AdapterResolver } from './step-executor.ts';
import type { L0ConfirmCallback } from './executors/l0-executor.ts';
import type { L1ApprovalCallback } from './executors/l1-executor.ts';
import { ExecutionStateMachine } from './state-machine.ts';
import { executeL0 } from './executors/l0-executor.ts';
import { executeL1 } from './executors/l1-executor.ts';
import { executeRollback } from './rollback.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OrchestratorOptions {
  /** Execution mode */
  mode: ExecutionMode;
  /** Adapter resolver */
  resolveAdapter: AdapterResolver;
  /** L0 step confirmation callback */
  confirmL0Step?: L0ConfirmCallback;
  /** L1 write-action approval callback */
  requestL1Approval?: L1ApprovalCallback;
  /** Alert event data */
  alert?: Record<string, unknown>;
  /** Additional context variables */
  variables?: Record<string, unknown>;
  /** Callback for state changes */
  onStateChange?: (executionId: string, from: string, to: string) => void;
  /** Callback for step completion */
  onStepComplete?: (executionId: string, stepResult: StepResult) => void;
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/**
 * Execute a runbook end-to-end.
 */
export async function executeRunbook(
  runbook: Runbook,
  options: OrchestratorOptions,
): Promise<ExecutionResult> {
  const executionId = uuidv4();
  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  // Initialize state machine
  const sm = new ExecutionStateMachine(executionId);

  if (options.onStateChange) {
    sm.onStateChange((t) => options.onStateChange!(executionId, t.from, t.to));
  }

  // Build template context
  const templateContext: TemplateContext = {
    alert: options.alert,
    steps: {},
    context: {
      execution_id: executionId,
      mode: options.mode,
      ...(options.variables ?? {}),
    },
    env: process.env as Record<string, string | undefined>,
  };

  try {
    // Transition: idle → validating
    sm.transition('trigger');

    // Validation is already done by the loader, but we confirm here
    if (!runbook.id || !runbook.steps.length) {
      sm.transition('validation_failed');
      return buildFailedResult(executionId, runbook.id, startedAt, startTime, {
        code: 'VALIDATION_FAILED',
        message: 'Runbook failed validation',
      });
    }

    // Transition: validating → planning
    sm.transition('validation_success');

    // Select executor based on automation level
    const level = runbook.config.automation_level;

    // Transition: planning → executing (or awaiting_approval for L2)
    if (level === 'L2' && runbook.config.requires_approval) {
      sm.transition('approval_required');
      // L2 approval flow — for v1, simulation only
      // Will be implemented in S3. For now, cancel.
      sm.transition('approval_denied');
      return buildFailedResult(executionId, runbook.id, startedAt, startTime, {
        code: 'L2_NOT_IMPLEMENTED',
        message: 'L2 execution requires S3 simulation mode (not yet implemented)',
      });
    }

    sm.transition('plan_ready');

    // Execute based on automation level
    let result: ExecutionResult;

    if (level === 'L0') {
      const confirmFn = options.confirmL0Step ?? defaultL0Confirm;
      result = await executeL0(runbook, templateContext, confirmFn);
    } else {
      // L1
      const approvalFn = options.requestL1Approval ?? defaultL1Approval;
      result = await executeL1(runbook, {
        mode: options.mode,
        templateContext,
        resolveAdapter: options.resolveAdapter,
        requestApproval: approvalFn,
      });
    }

    // Notify step completions
    if (options.onStepComplete) {
      for (const sr of result.steps_executed) {
        options.onStepComplete(executionId, sr);
      }
    }

    // Check if we need rollback
    const hasFailure = result.steps_executed.some((s) => !s.success);
    const rollbackEnabled = runbook.config.rollback_on_failure !== false;

    if (hasFailure && rollbackEnabled && level !== 'L0') {
      const completedSteps = result.steps_executed.filter((s) => s.success);
      const stepsWithRollback = runbook.steps.filter((s) => s.rollback);

      if (stepsWithRollback.length > 0 && completedSteps.length > 0) {
        sm.startRollback();

        const rollbackResult = await executeRollback(
          completedSteps,
          runbook.steps,
          {
            mode: options.mode,
            templateContext,
            resolveAdapter: options.resolveAdapter,
          },
        );

        if (rollbackResult.success) {
          sm.transition('rollback_completed');
        } else {
          sm.transition('rollback_failed');
        }

        result.metrics.rollbacks_triggered = rollbackResult.totalAttempted;
      } else {
        sm.transition('step_failed');
      }
    } else if (hasFailure) {
      sm.transition('step_failed');
    } else {
      sm.transition('all_steps_completed');
    }

    // Overwrite execution ID and state
    return {
      ...result,
      execution_id: executionId,
      state: sm.state,
      started_at: startedAt,
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - startTime,
    };
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    return buildFailedResult(executionId, runbook.id, startedAt, startTime, {
      code: 'ORCHESTRATION_ERROR',
      message: error.message,
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildFailedResult(
  executionId: string,
  runbookId: string,
  startedAt: string,
  startTime: number,
  error: { code: string; message: string },
): ExecutionResult {
  return {
    execution_id: executionId,
    runbook_id: runbookId,
    success: false,
    state: 'failed',
    started_at: startedAt,
    completed_at: new Date().toISOString(),
    duration_ms: Date.now() - startTime,
    steps_executed: [],
    error,
    metrics: {
      total_steps: 0,
      successful_steps: 0,
      failed_steps: 0,
      skipped_steps: 0,
      rollbacks_triggered: 0,
      duration_ms: Date.now() - startTime,
    },
  };
}

/** Default L0 confirm — auto-confirms (useful for testing) */
const defaultL0Confirm: L0ConfirmCallback = async () => true;

/** Default L1 approval — auto-approves (useful for testing) */
const defaultL1Approval: L1ApprovalCallback = async () => true;
