/**
 * Queue Executor
 *
 * Executes approved actions from the L2 simulation approval queue.
 * Bridges the gap between simulation approval and production execution:
 * approve a pending request, execute the action via the appropriate adapter
 * in production mode, and log the result to the audit trail.
 *
 * This module is the "one-click execute" path for SOC analysts reviewing
 * simulated actions that have been queued for human approval.
 *
 * @module engine/queue-executor
 */

import type { StepAction } from '../types/playbook.ts';
import type {
  ApprovalQueueEntry,
  ListApprovalOptions,
} from '../types/simulation.ts';
import type { ApprovalQueueRepository } from '../db/approval-queue-repository.ts';
import type { AuditLogger } from './audit-logger.ts';
import type { AdapterResolver } from './step-executor.ts';

// ---------------------------------------------------------------------------
// Public Types
// ---------------------------------------------------------------------------

/**
 * Result of executing an approved queue entry.
 */
export interface QueueExecutionResult {
  request_id: string;
  execution_id: string;
  action: StepAction;
  success: boolean;
  output?: unknown;
  error?: string;
  executed_at: string;
  executed_by: string;
}

/**
 * Constructor dependencies for {@link QueueExecutor}.
 */
export interface QueueExecutorDeps {
  approvalRepo: ApprovalQueueRepository;
  auditLogger: AuditLogger;
  resolveAdapter: AdapterResolver;
}

// ---------------------------------------------------------------------------
// QueueExecutor
// ---------------------------------------------------------------------------

/**
 * Executes approved actions from the L2 approval queue.
 *
 * Typical workflow:
 * 1. Analyst reviews pending approvals via {@link listPendingApprovals}.
 * 2. Analyst approves an entry via {@link approveAndExecute}, which
 *    atomically approves, executes, and logs the action.
 * 3. Alternatively, the analyst denies via {@link denyRequest}.
 * 4. Stale entries are cleaned up via {@link expireStale}.
 */
export class QueueExecutor {
  private readonly approvalRepo: ApprovalQueueRepository;
  private readonly auditLogger: AuditLogger;
  private readonly resolveAdapter: AdapterResolver;

  constructor(deps: QueueExecutorDeps) {
    this.approvalRepo = deps.approvalRepo;
    this.auditLogger = deps.auditLogger;
    this.resolveAdapter = deps.resolveAdapter;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Approve a pending request and execute the action in production mode.
   *
   * Steps:
   * 1. Validates the request exists and is pending.
   * 2. Approves it via the approval repository.
   * 3. Parses the JSON-serialized parameters.
   * 4. Resolves the adapter for the action and executes in production mode.
   * 5. Logs the execution to the audit trail.
   * 6. Returns a {@link QueueExecutionResult} with success/failure and output.
   *
   * @param requestId  - The approval request to approve and execute.
   * @param approvedBy - Identifier of the approving analyst.
   * @returns The execution result.
   * @throws {Error} If the request is not found or not pending.
   */
  async approveAndExecute(
    requestId: string,
    approvedBy: string,
  ): Promise<QueueExecutionResult> {
    // 1. Validate the request exists and is pending
    const entry = this.approvalRepo.getById(requestId);
    if (!entry) {
      throw new Error(`Approval request not found: ${requestId}`);
    }
    if (entry.status !== 'pending') {
      throw new Error(
        `Cannot execute request with status '${entry.status}': ${requestId}`,
      );
    }

    // 2. Approve via repository (handles expiration checks internally)
    const approved = this.approvalRepo.approve(requestId, approvedBy);

    // 3. Parse the JSON-serialized parameters
    let parameters: Record<string, unknown>;
    try {
      parameters = JSON.parse(approved.parameters) as Record<string, unknown>;
    } catch {
      throw new Error(
        `Failed to parse parameters for request ${requestId}: invalid JSON`,
      );
    }

    // 4. Resolve the adapter and execute in production mode
    const executedAt = new Date().toISOString();
    const adapter = this.resolveAdapter(approved.step_id);

    if (!adapter) {
      // Log the failure and return an error result
      const errorMsg = `Adapter not found for executor '${approved.step_id}'`;

      this.auditLogger.logApprovalQueueExecuted(
        approved.execution_id,
        approved.runbook_id,
        requestId,
        approvedBy,
        {
          action: approved.action,
          success: false,
          error: errorMsg,
        },
      );

      return {
        request_id: requestId,
        execution_id: approved.execution_id,
        action: approved.action,
        success: false,
        error: errorMsg,
        executed_at: executedAt,
        executed_by: approvedBy,
      };
    }

    try {
      const adapterResult = await adapter.execute(
        approved.action,
        parameters,
        'production',
      );

      // 5. Log to audit trail
      this.auditLogger.logApprovalQueueExecuted(
        approved.execution_id,
        approved.runbook_id,
        requestId,
        approvedBy,
        {
          action: approved.action,
          success: adapterResult.success,
          duration_ms: adapterResult.duration_ms,
          output: adapterResult.output,
          ...(adapterResult.error ? { error: adapterResult.error.message } : {}),
        },
      );

      // 6. Return result
      return {
        request_id: requestId,
        execution_id: approved.execution_id,
        action: approved.action,
        success: adapterResult.success,
        output: adapterResult.output,
        error: adapterResult.error?.message,
        executed_at: executedAt,
        executed_by: approvedBy,
      };
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));

      // Log the failure
      this.auditLogger.logApprovalQueueExecuted(
        approved.execution_id,
        approved.runbook_id,
        requestId,
        approvedBy,
        {
          action: approved.action,
          success: false,
          error: error.message,
        },
      );

      return {
        request_id: requestId,
        execution_id: approved.execution_id,
        action: approved.action,
        success: false,
        error: error.message,
        executed_at: executedAt,
        executed_by: approvedBy,
      };
    }
  }

  /**
   * Deny a pending approval request.
   *
   * @param requestId - The request to deny.
   * @param reason    - Human-readable reason for denial.
   * @returns The updated {@link ApprovalQueueEntry}.
   * @throws {Error} If the entry does not exist or is not pending.
   */
  denyRequest(requestId: string, reason: string): ApprovalQueueEntry {
    return this.approvalRepo.deny(requestId, reason);
  }

  /**
   * List pending (non-expired) approval queue entries.
   *
   * @param options - Optional filtering and pagination parameters.
   * @returns An array of pending {@link ApprovalQueueEntry} items.
   */
  listPendingApprovals(options?: ListApprovalOptions): ApprovalQueueEntry[] {
    return this.approvalRepo.listPending(options);
  }

  /**
   * Expire all stale pending entries whose TTL has elapsed.
   *
   * @returns The number of entries that were expired.
   */
  expireStale(): number {
    return this.approvalRepo.expireStale();
  }
}
