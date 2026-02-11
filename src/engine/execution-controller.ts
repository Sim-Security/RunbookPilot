/**
 * Execution Controller
 *
 * Manages execution timeout, cancellation, and lifecycle tracking.
 * Provides a centralized mechanism for the orchestrator and executors
 * to check whether an execution should be aborted (due to timeout or
 * explicit cancellation) and to coordinate clean shutdown of all
 * running executions.
 *
 * @module engine/execution-controller
 */

import { logger } from '../logging/logger.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Options for starting a tracked execution.
 */
export interface ExecutionControllerOptions {
  /** Unique execution identifier */
  execution_id: string;
  /** Timeout in milliseconds. 0 = no timeout. */
  timeout_ms: number;
  /** Callback invoked when the execution times out */
  on_timeout?: () => Promise<void>;
  /** Callback invoked when the execution is cancelled */
  on_cancel?: () => Promise<void>;
}

/**
 * Externally visible handle representing a tracked execution.
 */
export interface ExecutionHandle {
  execution_id: string;
  status: 'running' | 'completed' | 'cancelled' | 'timed_out' | 'failed';
  started_at: string;
  completed_at?: string;
  cancel_reason?: string;
}

// ---------------------------------------------------------------------------
// Internal State
// ---------------------------------------------------------------------------

interface TrackedExecution {
  handle: ExecutionHandle;
  timer: ReturnType<typeof setTimeout> | null;
  on_timeout?: () => Promise<void>;
  on_cancel?: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// ExecutionController
// ---------------------------------------------------------------------------

/**
 * Centralized controller for execution timeout, cancellation, and lifecycle.
 *
 * Usage:
 * 1. Call `startExecution()` when an execution begins.
 * 2. Executors call `shouldAbort()` between steps to detect cancellation/timeout.
 * 3. Call `completeExecution()`, `failExecution()`, or `cancelExecution()` to
 *    finalize the execution and clean up timers.
 * 4. On application shutdown, call `shutdownAll()` to cancel all running executions.
 */
export class ExecutionController {
  private readonly executions = new Map<string, TrackedExecution>();
  private readonly log = logger.child({ component: 'execution-controller' });

  // -----------------------------------------------------------------------
  // Start
  // -----------------------------------------------------------------------

  /**
   * Start tracking an execution with an optional timeout.
   *
   * @throws Error if an execution with the same ID is already tracked.
   */
  startExecution(options: ExecutionControllerOptions): ExecutionHandle {
    if (this.executions.has(options.execution_id)) {
      throw new Error(
        `Execution '${options.execution_id}' is already tracked by the controller`,
      );
    }

    const handle: ExecutionHandle = {
      execution_id: options.execution_id,
      status: 'running',
      started_at: new Date().toISOString(),
    };

    const tracked: TrackedExecution = {
      handle,
      timer: null,
      on_timeout: options.on_timeout,
      on_cancel: options.on_cancel,
    };

    // Schedule timeout if requested
    if (options.timeout_ms > 0) {
      tracked.timer = setTimeout(() => {
        void this.handleTimeout(options.execution_id);
      }, options.timeout_ms);

      // Unref the timer so it does not keep the process alive
      if (tracked.timer && typeof tracked.timer === 'object' && 'unref' in tracked.timer) {
        (tracked.timer as NodeJS.Timeout).unref();
      }
    }

    this.executions.set(options.execution_id, tracked);

    this.log.info('Execution tracking started', {
      execution_id: options.execution_id,
      timeout_ms: options.timeout_ms,
    });

    return { ...handle };
  }

  // -----------------------------------------------------------------------
  // Cancel
  // -----------------------------------------------------------------------

  /**
   * Cancel a running execution.
   *
   * @throws Error if the execution is not found or is not in 'running' status.
   */
  cancelExecution(executionId: string, reason: string): ExecutionHandle {
    const tracked = this.getTrackedOrThrow(executionId);

    if (tracked.handle.status !== 'running') {
      throw new Error(
        `Cannot cancel execution '${executionId}': current status is '${tracked.handle.status}'`,
      );
    }

    this.clearTimer(tracked);

    tracked.handle.status = 'cancelled';
    tracked.handle.completed_at = new Date().toISOString();
    tracked.handle.cancel_reason = reason;

    this.log.info('Execution cancelled', {
      execution_id: executionId,
      reason,
    });

    // Fire the on_cancel callback (fire-and-forget with error logging)
    if (tracked.on_cancel) {
      tracked.on_cancel().catch((err) => {
        this.log.error('on_cancel callback failed', {
          execution_id: executionId,
          error: err instanceof Error ? err.message : String(err),
        });
      });
    }

    return { ...tracked.handle };
  }

  // -----------------------------------------------------------------------
  // Complete
  // -----------------------------------------------------------------------

  /**
   * Mark an execution as completed normally.
   *
   * @throws Error if the execution is not found or is not in 'running' status.
   */
  completeExecution(executionId: string): ExecutionHandle {
    const tracked = this.getTrackedOrThrow(executionId);

    if (tracked.handle.status !== 'running') {
      throw new Error(
        `Cannot complete execution '${executionId}': current status is '${tracked.handle.status}'`,
      );
    }

    this.clearTimer(tracked);

    tracked.handle.status = 'completed';
    tracked.handle.completed_at = new Date().toISOString();

    this.log.info('Execution completed', { execution_id: executionId });

    return { ...tracked.handle };
  }

  // -----------------------------------------------------------------------
  // Fail
  // -----------------------------------------------------------------------

  /**
   * Mark an execution as failed.
   *
   * @throws Error if the execution is not found or is not in 'running' status.
   */
  failExecution(executionId: string, error: string): ExecutionHandle {
    const tracked = this.getTrackedOrThrow(executionId);

    if (tracked.handle.status !== 'running') {
      throw new Error(
        `Cannot fail execution '${executionId}': current status is '${tracked.handle.status}'`,
      );
    }

    this.clearTimer(tracked);

    tracked.handle.status = 'failed';
    tracked.handle.completed_at = new Date().toISOString();

    this.log.error('Execution failed', {
      execution_id: executionId,
      error,
    });

    return { ...tracked.handle };
  }

  // -----------------------------------------------------------------------
  // Query
  // -----------------------------------------------------------------------

  /**
   * Get the current handle for an execution, or `undefined` if not tracked.
   */
  getExecution(executionId: string): ExecutionHandle | undefined {
    const tracked = this.executions.get(executionId);
    if (!tracked) return undefined;
    return { ...tracked.handle };
  }

  /**
   * List all executions that are currently in 'running' status.
   */
  listActive(): ExecutionHandle[] {
    const active: ExecutionHandle[] = [];
    for (const tracked of this.executions.values()) {
      if (tracked.handle.status === 'running') {
        active.push({ ...tracked.handle });
      }
    }
    return active;
  }

  // -----------------------------------------------------------------------
  // Abort Check
  // -----------------------------------------------------------------------

  /**
   * Check whether an execution should be aborted.
   *
   * Executors call this between steps. Returns `true` if the execution
   * has been cancelled or timed out.
   */
  shouldAbort(executionId: string): boolean {
    const tracked = this.executions.get(executionId);
    if (!tracked) return false;
    return tracked.handle.status === 'cancelled' || tracked.handle.status === 'timed_out';
  }

  // -----------------------------------------------------------------------
  // Shutdown
  // -----------------------------------------------------------------------

  /**
   * Cancel all running executions with reason 'system_shutdown'.
   *
   * Waits for all on_cancel callbacks to settle before returning.
   */
  async shutdownAll(): Promise<void> {
    const runningIds: string[] = [];
    for (const tracked of this.executions.values()) {
      if (tracked.handle.status === 'running') {
        runningIds.push(tracked.handle.execution_id);
      }
    }

    if (runningIds.length === 0) {
      this.log.info('Shutdown: no running executions to cancel');
      return;
    }

    this.log.info('Shutdown: cancelling all running executions', {
      count: runningIds.length,
    });

    const cancelPromises: Promise<void>[] = [];

    for (const id of runningIds) {
      const tracked = this.executions.get(id);
      if (!tracked || tracked.handle.status !== 'running') continue;

      this.clearTimer(tracked);

      tracked.handle.status = 'cancelled';
      tracked.handle.completed_at = new Date().toISOString();
      tracked.handle.cancel_reason = 'system_shutdown';

      if (tracked.on_cancel) {
        cancelPromises.push(
          tracked.on_cancel().catch((err) => {
            this.log.error('on_cancel callback failed during shutdown', {
              execution_id: id,
              error: err instanceof Error ? err.message : String(err),
            });
          }),
        );
      }
    }

    // Wait for all callbacks to settle
    await Promise.all(cancelPromises);

    this.log.info('Shutdown complete', { cancelled: runningIds.length });
  }

  // -----------------------------------------------------------------------
  // Internal Helpers
  // -----------------------------------------------------------------------

  /**
   * Handle a timeout firing for a tracked execution.
   */
  private async handleTimeout(executionId: string): Promise<void> {
    const tracked = this.executions.get(executionId);
    if (!tracked) return;

    // Only fire if still running (may have been completed/cancelled in the interim)
    if (tracked.handle.status !== 'running') return;

    tracked.handle.status = 'timed_out';
    tracked.handle.completed_at = new Date().toISOString();
    tracked.timer = null;

    this.log.warn('Execution timed out', { execution_id: executionId });

    if (tracked.on_timeout) {
      try {
        await tracked.on_timeout();
      } catch (err) {
        this.log.error('on_timeout callback failed', {
          execution_id: executionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  /**
   * Retrieve a tracked execution or throw if not found.
   */
  private getTrackedOrThrow(executionId: string): TrackedExecution {
    const tracked = this.executions.get(executionId);
    if (!tracked) {
      throw new Error(`Execution '${executionId}' is not tracked by the controller`);
    }
    return tracked;
  }

  /**
   * Clear a timeout timer if one is active.
   */
  private clearTimer(tracked: TrackedExecution): void {
    if (tracked.timer !== null) {
      clearTimeout(tracked.timer);
      tracked.timer = null;
    }
  }
}
