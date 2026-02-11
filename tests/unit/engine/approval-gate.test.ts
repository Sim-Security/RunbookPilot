import { describe, it, expect, vi } from 'vitest';
import {
  ApprovalGate,
  ApprovalTimeoutError,
} from '../../../src/engine/approval-gate.ts';
import type {
  ApprovalPromptFn,
  ApprovalDetails,
} from '../../../src/engine/approval-gate.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid ApprovalDetails fixture. */
function makeDetails(overrides?: Partial<ApprovalDetails>): ApprovalDetails {
  return {
    executionId: 'exec-001',
    runbookId: 'rb-001',
    runbookName: 'Test Runbook',
    message: 'Approve this action?',
    ...overrides,
  };
}

/** A prompt function that resolves immediately with an approval. */
const approvePrompt: ApprovalPromptFn = async () => ({
  approved: true,
  approver: 'analyst@corp.com',
  reason: 'Looks good',
});

/** A prompt function that resolves immediately with a denial. */
const denyPrompt: ApprovalPromptFn = async () => ({
  approved: false,
  approver: 'analyst@corp.com',
  reason: 'Too risky',
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ApprovalGate', () => {
  // -----------------------------------------------------------------------
  // Construction
  // -----------------------------------------------------------------------

  describe('construction', () => {
    it('uses default options when none provided (5 min timeout, halt behavior)', () => {
      const gate = new ApprovalGate();
      // We verify defaults indirectly via timeout behavior in the timeout tests,
      // but we can at least confirm the instance is created without error.
      expect(gate).toBeInstanceOf(ApprovalGate);
    });

    it('accepts custom timeout and behavior', () => {
      const gate = new ApprovalGate({
        timeoutMs: 10_000,
        timeoutBehavior: 'skip',
      });
      expect(gate).toBeInstanceOf(ApprovalGate);
    });

    it('allows partial options — only timeoutMs', () => {
      const gate = new ApprovalGate({ timeoutMs: 60_000 });
      expect(gate).toBeInstanceOf(ApprovalGate);
    });

    it('allows partial options — only timeoutBehavior', () => {
      const gate = new ApprovalGate({ timeoutBehavior: 'auto-approve' });
      expect(gate).toBeInstanceOf(ApprovalGate);
    });
  });

  // -----------------------------------------------------------------------
  // Approved decision
  // -----------------------------------------------------------------------

  describe('approved decision', () => {
    it('returns approved status when prompt approves', async () => {
      const gate = new ApprovalGate();
      const result = await gate.requestApproval(makeDetails(), approvePrompt);

      expect(result.status).toBe('approved');
      expect(result.approver).toBe('analyst@corp.com');
      expect(result.reason).toBe('Looks good');
      expect(result.respondedAt).toBeTruthy();
      expect(typeof result.durationMs).toBe('number');
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });

    it('returns approved status with no reason when prompt omits reason', async () => {
      const gate = new ApprovalGate();
      const noReasonPrompt: ApprovalPromptFn = async () => ({
        approved: true,
        approver: 'admin',
      });
      const result = await gate.requestApproval(makeDetails(), noReasonPrompt);

      expect(result.status).toBe('approved');
      expect(result.approver).toBe('admin');
      expect(result.reason).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // Denied decision
  // -----------------------------------------------------------------------

  describe('denied decision', () => {
    it('returns denied status when prompt denies', async () => {
      const gate = new ApprovalGate();
      const result = await gate.requestApproval(makeDetails(), denyPrompt);

      expect(result.status).toBe('denied');
      expect(result.approver).toBe('analyst@corp.com');
      expect(result.reason).toBe('Too risky');
    });

    it('returns denied with no reason when prompt omits reason', async () => {
      const gate = new ApprovalGate();
      const noReasonDeny: ApprovalPromptFn = async () => ({
        approved: false,
        approver: 'admin',
      });
      const result = await gate.requestApproval(makeDetails(), noReasonDeny);

      expect(result.status).toBe('denied');
      expect(result.reason).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // Timeout with 'halt' behavior (default)
  // -----------------------------------------------------------------------

  describe('timeout with halt behavior', () => {
    it('returns expired status when prompt exceeds timeout', async () => {
      const gate = new ApprovalGate({ timeoutMs: 50, timeoutBehavior: 'halt' });
      const slowPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 200));
        return { approved: true, approver: 'test' };
      };

      const result = await gate.requestApproval(makeDetails(), slowPrompt);

      expect(result.status).toBe('expired');
      expect(result.reason).toBe('Approval timeout — execution halted');
      expect(result.approver).toBeUndefined();
      expect(result.durationMs).toBeGreaterThanOrEqual(40); // ~50ms, allow small variance
    });

    it('uses halt as the default timeout behavior', async () => {
      const gate = new ApprovalGate({ timeoutMs: 50 });
      const slowPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 200));
        return { approved: true, approver: 'test' };
      };

      const result = await gate.requestApproval(makeDetails(), slowPrompt);

      expect(result.status).toBe('expired');
      expect(result.reason).toBe('Approval timeout — execution halted');
    });
  });

  // -----------------------------------------------------------------------
  // Timeout with 'skip' behavior
  // -----------------------------------------------------------------------

  describe('timeout with skip behavior', () => {
    it('returns expired status with skip reason', async () => {
      const gate = new ApprovalGate({ timeoutMs: 50, timeoutBehavior: 'skip' });
      const slowPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 200));
        return { approved: true, approver: 'test' };
      };

      const result = await gate.requestApproval(makeDetails(), slowPrompt);

      expect(result.status).toBe('expired');
      expect(result.reason).toBe('Approval timeout — step skipped per configuration');
      expect(result.approver).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // Timeout with 'auto-approve' behavior
  // -----------------------------------------------------------------------

  describe('timeout with auto-approve behavior', () => {
    it('returns approved status with system approver', async () => {
      const gate = new ApprovalGate({
        timeoutMs: 50,
        timeoutBehavior: 'auto-approve',
      });
      const slowPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 200));
        return { approved: false, approver: 'test' };
      };

      const result = await gate.requestApproval(makeDetails(), slowPrompt);

      expect(result.status).toBe('approved');
      expect(result.approver).toBe('system:auto-approve');
      expect(result.reason).toBe(
        'Approval timeout — auto-approved per configuration',
      );
    });
  });

  // -----------------------------------------------------------------------
  // Non-timeout errors are rethrown
  // -----------------------------------------------------------------------

  describe('error propagation', () => {
    it('rethrows non-timeout errors from the prompt function', async () => {
      const gate = new ApprovalGate();
      const failPrompt: ApprovalPromptFn = async () => {
        throw new Error('Network failure');
      };

      await expect(
        gate.requestApproval(makeDetails(), failPrompt),
      ).rejects.toThrow('Network failure');
    });

    it('rethrows custom error types from the prompt function', async () => {
      const gate = new ApprovalGate();

      class SlackApiError extends Error {
        constructor() {
          super('Slack API unreachable');
          this.name = 'SlackApiError';
        }
      }

      const failPrompt: ApprovalPromptFn = async () => {
        throw new SlackApiError();
      };

      await expect(
        gate.requestApproval(makeDetails(), failPrompt),
      ).rejects.toThrow(SlackApiError);
    });
  });

  // -----------------------------------------------------------------------
  // Duration tracking
  // -----------------------------------------------------------------------

  describe('duration tracking', () => {
    it('records a positive durationMs for successful approval', async () => {
      const gate = new ApprovalGate();
      const delayedPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 30));
        return { approved: true, approver: 'analyst' };
      };

      const result = await gate.requestApproval(makeDetails(), delayedPrompt);

      expect(result.durationMs).toBeGreaterThanOrEqual(20);
      expect(result.durationMs).toBeLessThan(2000);
    });

    it('records a positive durationMs for timeout scenarios', async () => {
      const gate = new ApprovalGate({ timeoutMs: 50, timeoutBehavior: 'halt' });
      const slowPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 200));
        return { approved: true, approver: 'test' };
      };

      const result = await gate.requestApproval(makeDetails(), slowPrompt);

      expect(result.durationMs).toBeGreaterThanOrEqual(40);
      expect(result.durationMs).toBeLessThan(2000);
    });

    it('includes a valid ISO 8601 respondedAt timestamp', async () => {
      const gate = new ApprovalGate();
      const result = await gate.requestApproval(makeDetails(), approvePrompt);

      // Verify it parses as a valid date
      const date = new Date(result.respondedAt);
      expect(date.getTime()).not.toBeNaN();
      // Verify ISO format
      expect(result.respondedAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/,
      );
    });
  });

  // -----------------------------------------------------------------------
  // ApprovalDetails passthrough
  // -----------------------------------------------------------------------

  describe('details passthrough', () => {
    it('passes full details object to the prompt function', async () => {
      const gate = new ApprovalGate();
      const spy = vi.fn<ApprovalPromptFn>(async () => ({
        approved: true,
        approver: 'tester',
      }));

      const details = makeDetails({
        stepId: 'step-1',
        stepName: 'Block IP',
        action: 'firewall.blockIp',
        parameters: { ip: '192.168.1.1' },
        riskLevel: 'high',
      });

      await gate.requestApproval(details, spy);

      expect(spy).toHaveBeenCalledOnce();
      expect(spy).toHaveBeenCalledWith(details);
    });
  });

  // -----------------------------------------------------------------------
  // ApprovalTimeoutError
  // -----------------------------------------------------------------------

  describe('ApprovalTimeoutError', () => {
    it('is an instance of Error', () => {
      const err = new ApprovalTimeoutError(5000);
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(ApprovalTimeoutError);
    });

    it('has the correct name', () => {
      const err = new ApprovalTimeoutError(5000);
      expect(err.name).toBe('ApprovalTimeoutError');
    });

    it('stores the timeoutMs value', () => {
      const err = new ApprovalTimeoutError(30_000);
      expect(err.timeoutMs).toBe(30_000);
    });

    it('includes timeoutMs in the message', () => {
      const err = new ApprovalTimeoutError(5000);
      expect(err.message).toBe('Approval timed out after 5000ms');
    });

    it('has a stack trace', () => {
      const err = new ApprovalTimeoutError(5000);
      expect(err.stack).toBeDefined();
      expect(err.stack).toContain('ApprovalTimeoutError');
    });

    it('timeoutMs property is readonly', () => {
      const err = new ApprovalTimeoutError(5000);
      // TypeScript enforces readonly at compile time; at runtime we verify it exists
      expect(err.timeoutMs).toBe(5000);
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  describe('edge cases', () => {
    it('handles instant prompt resolution', async () => {
      const gate = new ApprovalGate({ timeoutMs: 50 });
      const instantPrompt: ApprovalPromptFn = async () => ({
        approved: true,
        approver: 'instant',
      });

      const result = await gate.requestApproval(makeDetails(), instantPrompt);
      expect(result.status).toBe('approved');
      expect(result.approver).toBe('instant');
    });

    it('prompt that resolves just before timeout succeeds', async () => {
      const gate = new ApprovalGate({ timeoutMs: 200 });
      const fastEnoughPrompt: ApprovalPromptFn = async () => {
        await new Promise(resolve => setTimeout(resolve, 20));
        return { approved: true, approver: 'fast' };
      };

      const result = await gate.requestApproval(
        makeDetails(),
        fastEnoughPrompt,
      );
      expect(result.status).toBe('approved');
    });

    it('supports multiple sequential requests on the same gate', async () => {
      const gate = new ApprovalGate();

      const r1 = await gate.requestApproval(makeDetails(), approvePrompt);
      const r2 = await gate.requestApproval(makeDetails(), denyPrompt);
      const r3 = await gate.requestApproval(makeDetails(), approvePrompt);

      expect(r1.status).toBe('approved');
      expect(r2.status).toBe('denied');
      expect(r3.status).toBe('approved');
    });
  });
});
