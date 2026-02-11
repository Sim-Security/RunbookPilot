/**
 * Approval Gate Manager
 *
 * Manages approval requests for write actions (L1) and full-runbook
 * approval (L2). Supports configurable timeout with skip/halt/auto-approve
 * behaviors.
 *
 * @module engine/approval-gate
 */

import type { ApprovalStatus } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TimeoutBehavior = 'skip' | 'halt' | 'auto-approve';

export interface ApprovalGateOptions {
  /** Timeout in milliseconds (default: 300000 = 5 minutes) */
  timeoutMs?: number;
  /** What to do on timeout (default: 'halt') */
  timeoutBehavior?: TimeoutBehavior;
}

export interface ApprovalGateResult {
  status: ApprovalStatus;
  approver?: string;
  reason?: string;
  respondedAt: string;
  durationMs: number;
}

/**
 * Approval prompt function. Implementations can use CLI prompts,
 * web UI, Slack, etc. Must resolve to an approval decision.
 */
export type ApprovalPromptFn = (details: ApprovalDetails) => Promise<ApprovalDecision>;

export interface ApprovalDetails {
  executionId: string;
  runbookId: string;
  runbookName: string;
  stepId?: string;
  stepName?: string;
  action?: string;
  parameters?: Record<string, unknown>;
  riskLevel?: 'low' | 'medium' | 'high';
  message: string;
}

export interface ApprovalDecision {
  approved: boolean;
  approver: string;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Approval Gate
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 300_000; // 5 minutes

export class ApprovalGate {
  private readonly timeoutMs: number;
  private readonly timeoutBehavior: TimeoutBehavior;

  constructor(options?: ApprovalGateOptions) {
    this.timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.timeoutBehavior = options?.timeoutBehavior ?? 'halt';
  }

  /**
   * Request approval with timeout enforcement.
   */
  async requestApproval(
    details: ApprovalDetails,
    promptFn: ApprovalPromptFn,
  ): Promise<ApprovalGateResult> {
    const startTime = Date.now();

    try {
      const decision = await this.withTimeout(promptFn(details));
      const durationMs = Date.now() - startTime;

      return {
        status: decision.approved ? 'approved' : 'denied',
        approver: decision.approver,
        reason: decision.reason,
        respondedAt: new Date().toISOString(),
        durationMs,
      };
    } catch (err) {
      if (err instanceof ApprovalTimeoutError) {
        return this.handleTimeout(startTime);
      }
      throw err;
    }
  }

  private handleTimeout(startTime: number): ApprovalGateResult {
    const durationMs = Date.now() - startTime;

    switch (this.timeoutBehavior) {
      case 'auto-approve':
        return {
          status: 'approved',
          approver: 'system:auto-approve',
          reason: 'Approval timeout — auto-approved per configuration',
          respondedAt: new Date().toISOString(),
          durationMs,
        };

      case 'skip':
        return {
          status: 'expired',
          reason: 'Approval timeout — step skipped per configuration',
          respondedAt: new Date().toISOString(),
          durationMs,
        };

      case 'halt':
      default:
        return {
          status: 'expired',
          reason: 'Approval timeout — execution halted',
          respondedAt: new Date().toISOString(),
          durationMs,
        };
    }
  }

  private withTimeout<T>(promise: Promise<T>): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new ApprovalTimeoutError(this.timeoutMs)),
          this.timeoutMs,
        ),
      ),
    ]);
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class ApprovalTimeoutError extends Error {
  readonly timeoutMs: number;

  constructor(timeoutMs: number) {
    super(`Approval timed out after ${timeoutMs}ms`);
    this.name = 'ApprovalTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}
