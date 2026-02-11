import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ExecutionController } from '../../../src/engine/execution-controller.ts';
import type {
  ExecutionControllerOptions,
} from '../../../src/engine/execution-controller.ts';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeOptions(overrides: Partial<ExecutionControllerOptions> = {}): ExecutionControllerOptions {
  return {
    execution_id: `exec-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timeout_ms: 0,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// startExecution
// ---------------------------------------------------------------------------

describe('ExecutionController - startExecution', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates a handle with running status', () => {
    const handle = controller.startExecution(makeOptions({ execution_id: 'exec-001' }));

    expect(handle.execution_id).toBe('exec-001');
    expect(handle.status).toBe('running');
    expect(handle.started_at).toBeDefined();
    expect(handle.completed_at).toBeUndefined();
    expect(handle.cancel_reason).toBeUndefined();
  });

  it('started_at is a valid ISO8601 timestamp', () => {
    const handle = controller.startExecution(makeOptions({ execution_id: 'exec-002' }));
    const parsed = new Date(handle.started_at);

    expect(parsed.toISOString()).toBe(handle.started_at);
  });

  it('throws for duplicate execution ID', () => {
    controller.startExecution(makeOptions({ execution_id: 'dup-001' }));

    expect(() => {
      controller.startExecution(makeOptions({ execution_id: 'dup-001' }));
    }).toThrow("already tracked");
  });

  it('allows multiple executions with different IDs', () => {
    const h1 = controller.startExecution(makeOptions({ execution_id: 'exec-a' }));
    const h2 = controller.startExecution(makeOptions({ execution_id: 'exec-b' }));

    expect(h1.execution_id).toBe('exec-a');
    expect(h2.execution_id).toBe('exec-b');
    expect(h1.status).toBe('running');
    expect(h2.status).toBe('running');
  });

  it('returns a copy of the handle (mutations do not affect internal state)', () => {
    const handle = controller.startExecution(makeOptions({ execution_id: 'exec-copy' }));
    handle.status = 'completed';

    const retrieved = controller.getExecution('exec-copy');
    expect(retrieved!.status).toBe('running');
  });
});

// ---------------------------------------------------------------------------
// cancelExecution
// ---------------------------------------------------------------------------

describe('ExecutionController - cancelExecution', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('sets status to cancelled with reason', () => {
    controller.startExecution(makeOptions({ execution_id: 'cancel-001' }));

    const handle = controller.cancelExecution('cancel-001', 'user requested');

    expect(handle.status).toBe('cancelled');
    expect(handle.cancel_reason).toBe('user requested');
    expect(handle.completed_at).toBeDefined();
  });

  it('throws when execution is not found', () => {
    expect(() => {
      controller.cancelExecution('nonexistent', 'reason');
    }).toThrow("not tracked");
  });

  it('throws when execution is not in running status', () => {
    controller.startExecution(makeOptions({ execution_id: 'cancel-002' }));
    controller.completeExecution('cancel-002');

    expect(() => {
      controller.cancelExecution('cancel-002', 'too late');
    }).toThrow("Cannot cancel");
  });

  it('fires on_cancel callback', async () => {
    const onCancel = vi.fn().mockResolvedValue(undefined);

    controller.startExecution(makeOptions({
      execution_id: 'cancel-003',
      on_cancel: onCancel,
    }));

    controller.cancelExecution('cancel-003', 'testing callback');

    // Give the fire-and-forget callback a tick to resolve
    await vi.waitFor(() => {
      expect(onCancel).toHaveBeenCalledTimes(1);
    });
  });
});

// ---------------------------------------------------------------------------
// completeExecution
// ---------------------------------------------------------------------------

describe('ExecutionController - completeExecution', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('sets status to completed', () => {
    controller.startExecution(makeOptions({ execution_id: 'complete-001' }));

    const handle = controller.completeExecution('complete-001');

    expect(handle.status).toBe('completed');
    expect(handle.completed_at).toBeDefined();
  });

  it('throws when execution is not found', () => {
    expect(() => {
      controller.completeExecution('nonexistent');
    }).toThrow("not tracked");
  });

  it('throws when execution is not in running status', () => {
    controller.startExecution(makeOptions({ execution_id: 'complete-002' }));
    controller.cancelExecution('complete-002', 'cancelled first');

    expect(() => {
      controller.completeExecution('complete-002');
    }).toThrow("Cannot complete");
  });
});

// ---------------------------------------------------------------------------
// failExecution
// ---------------------------------------------------------------------------

describe('ExecutionController - failExecution', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('sets status to failed', () => {
    controller.startExecution(makeOptions({ execution_id: 'fail-001' }));

    const handle = controller.failExecution('fail-001', 'adapter error');

    expect(handle.status).toBe('failed');
    expect(handle.completed_at).toBeDefined();
  });

  it('throws when execution is not found', () => {
    expect(() => {
      controller.failExecution('nonexistent', 'error');
    }).toThrow("not tracked");
  });

  it('throws when execution is not in running status', () => {
    controller.startExecution(makeOptions({ execution_id: 'fail-002' }));
    controller.completeExecution('fail-002');

    expect(() => {
      controller.failExecution('fail-002', 'too late');
    }).toThrow("Cannot fail");
  });
});

// ---------------------------------------------------------------------------
// shouldAbort
// ---------------------------------------------------------------------------

describe('ExecutionController - shouldAbort', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('returns false for running execution', () => {
    controller.startExecution(makeOptions({ execution_id: 'abort-001' }));

    expect(controller.shouldAbort('abort-001')).toBe(false);
  });

  it('returns true after cancellation', () => {
    controller.startExecution(makeOptions({ execution_id: 'abort-002' }));
    controller.cancelExecution('abort-002', 'cancelled');

    expect(controller.shouldAbort('abort-002')).toBe(true);
  });

  it('returns true after timeout', async () => {
    vi.useFakeTimers();

    controller.startExecution(makeOptions({
      execution_id: 'abort-003',
      timeout_ms: 1000,
    }));

    expect(controller.shouldAbort('abort-003')).toBe(false);

    await vi.advanceTimersByTimeAsync(1500);

    expect(controller.shouldAbort('abort-003')).toBe(true);

    vi.useRealTimers();
  });

  it('returns false for unknown execution ID', () => {
    expect(controller.shouldAbort('nonexistent')).toBe(false);
  });

  it('returns false for completed execution', () => {
    controller.startExecution(makeOptions({ execution_id: 'abort-004' }));
    controller.completeExecution('abort-004');

    expect(controller.shouldAbort('abort-004')).toBe(false);
  });

  it('returns false for failed execution', () => {
    controller.startExecution(makeOptions({ execution_id: 'abort-005' }));
    controller.failExecution('abort-005', 'error');

    expect(controller.shouldAbort('abort-005')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// listActive
// ---------------------------------------------------------------------------

describe('ExecutionController - listActive', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('returns empty array when no executions', () => {
    expect(controller.listActive()).toEqual([]);
  });

  it('returns only running executions', () => {
    controller.startExecution(makeOptions({ execution_id: 'active-001' }));
    controller.startExecution(makeOptions({ execution_id: 'active-002' }));
    controller.startExecution(makeOptions({ execution_id: 'active-003' }));
    controller.completeExecution('active-002');

    const active = controller.listActive();

    expect(active).toHaveLength(2);
    expect(active.map((h) => h.execution_id)).toContain('active-001');
    expect(active.map((h) => h.execution_id)).toContain('active-003');
    expect(active.map((h) => h.execution_id)).not.toContain('active-002');
  });

  it('excludes cancelled executions', () => {
    controller.startExecution(makeOptions({ execution_id: 'active-a' }));
    controller.startExecution(makeOptions({ execution_id: 'active-b' }));
    controller.cancelExecution('active-a', 'cancelled');

    const active = controller.listActive();
    expect(active).toHaveLength(1);
    expect(active[0]!.execution_id).toBe('active-b');
  });

  it('excludes failed executions', () => {
    controller.startExecution(makeOptions({ execution_id: 'active-c' }));
    controller.startExecution(makeOptions({ execution_id: 'active-d' }));
    controller.failExecution('active-c', 'error');

    const active = controller.listActive();
    expect(active).toHaveLength(1);
    expect(active[0]!.execution_id).toBe('active-d');
  });
});

// ---------------------------------------------------------------------------
// getExecution
// ---------------------------------------------------------------------------

describe('ExecutionController - getExecution', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('returns handle for tracked execution', () => {
    controller.startExecution(makeOptions({ execution_id: 'get-001' }));

    const handle = controller.getExecution('get-001');

    expect(handle).toBeDefined();
    expect(handle!.execution_id).toBe('get-001');
    expect(handle!.status).toBe('running');
  });

  it('returns undefined for unknown execution', () => {
    expect(controller.getExecution('nonexistent')).toBeUndefined();
  });

  it('returns a copy (mutations do not affect internal state)', () => {
    controller.startExecution(makeOptions({ execution_id: 'get-002' }));

    const handle = controller.getExecution('get-002')!;
    handle.status = 'failed';

    expect(controller.getExecution('get-002')!.status).toBe('running');
  });
});

// ---------------------------------------------------------------------------
// Timeout handling
// ---------------------------------------------------------------------------

describe('ExecutionController - timeout', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    vi.useFakeTimers();
    controller = new ExecutionController();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('sets status to timed_out when timeout fires', async () => {
    controller.startExecution(makeOptions({
      execution_id: 'timeout-001',
      timeout_ms: 5000,
    }));

    expect(controller.getExecution('timeout-001')!.status).toBe('running');

    await vi.advanceTimersByTimeAsync(6000);

    expect(controller.getExecution('timeout-001')!.status).toBe('timed_out');
  });

  it('fires on_timeout callback when timeout occurs', async () => {
    const onTimeout = vi.fn().mockResolvedValue(undefined);

    controller.startExecution(makeOptions({
      execution_id: 'timeout-002',
      timeout_ms: 3000,
      on_timeout: onTimeout,
    }));

    await vi.advanceTimersByTimeAsync(4000);

    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('does not fire timeout if execution completes before timer', async () => {
    const onTimeout = vi.fn().mockResolvedValue(undefined);

    controller.startExecution(makeOptions({
      execution_id: 'timeout-003',
      timeout_ms: 5000,
      on_timeout: onTimeout,
    }));

    controller.completeExecution('timeout-003');

    await vi.advanceTimersByTimeAsync(10000);

    expect(onTimeout).not.toHaveBeenCalled();
    expect(controller.getExecution('timeout-003')!.status).toBe('completed');
  });

  it('does not fire timeout if execution is cancelled before timer', async () => {
    const onTimeout = vi.fn().mockResolvedValue(undefined);

    controller.startExecution(makeOptions({
      execution_id: 'timeout-004',
      timeout_ms: 5000,
      on_timeout: onTimeout,
    }));

    controller.cancelExecution('timeout-004', 'pre-emptive');

    await vi.advanceTimersByTimeAsync(10000);

    expect(onTimeout).not.toHaveBeenCalled();
    expect(controller.getExecution('timeout-004')!.status).toBe('cancelled');
  });

  it('timed_out execution has completed_at set', async () => {
    controller.startExecution(makeOptions({
      execution_id: 'timeout-005',
      timeout_ms: 1000,
    }));

    await vi.advanceTimersByTimeAsync(2000);

    const handle = controller.getExecution('timeout-005')!;
    expect(handle.status).toBe('timed_out');
    expect(handle.completed_at).toBeDefined();
  });

  it('does not timeout when timeout_ms is 0', async () => {
    controller.startExecution(makeOptions({
      execution_id: 'timeout-006',
      timeout_ms: 0,
    }));

    await vi.advanceTimersByTimeAsync(60000);

    expect(controller.getExecution('timeout-006')!.status).toBe('running');
  });
});

// ---------------------------------------------------------------------------
// shutdownAll
// ---------------------------------------------------------------------------

describe('ExecutionController - shutdownAll', () => {
  let controller: ExecutionController;

  beforeEach(() => {
    controller = new ExecutionController();
  });

  it('cancels all running executions', async () => {
    controller.startExecution(makeOptions({ execution_id: 'shutdown-001' }));
    controller.startExecution(makeOptions({ execution_id: 'shutdown-002' }));
    controller.startExecution(makeOptions({ execution_id: 'shutdown-003' }));

    await controller.shutdownAll();

    expect(controller.getExecution('shutdown-001')!.status).toBe('cancelled');
    expect(controller.getExecution('shutdown-002')!.status).toBe('cancelled');
    expect(controller.getExecution('shutdown-003')!.status).toBe('cancelled');
  });

  it('sets cancel_reason to system_shutdown', async () => {
    controller.startExecution(makeOptions({ execution_id: 'shutdown-004' }));

    await controller.shutdownAll();

    expect(controller.getExecution('shutdown-004')!.cancel_reason).toBe('system_shutdown');
  });

  it('does not affect already completed/failed executions', async () => {
    controller.startExecution(makeOptions({ execution_id: 'shutdown-005' }));
    controller.startExecution(makeOptions({ execution_id: 'shutdown-006' }));
    controller.completeExecution('shutdown-005');
    controller.failExecution('shutdown-006', 'error');

    await controller.shutdownAll();

    expect(controller.getExecution('shutdown-005')!.status).toBe('completed');
    expect(controller.getExecution('shutdown-006')!.status).toBe('failed');
  });

  it('fires on_cancel callbacks for all running executions', async () => {
    const onCancel1 = vi.fn().mockResolvedValue(undefined);
    const onCancel2 = vi.fn().mockResolvedValue(undefined);

    controller.startExecution(makeOptions({
      execution_id: 'shutdown-007',
      on_cancel: onCancel1,
    }));
    controller.startExecution(makeOptions({
      execution_id: 'shutdown-008',
      on_cancel: onCancel2,
    }));

    await controller.shutdownAll();

    expect(onCancel1).toHaveBeenCalledTimes(1);
    expect(onCancel2).toHaveBeenCalledTimes(1);
  });

  it('handles no running executions gracefully', async () => {
    // No executions started
    await expect(controller.shutdownAll()).resolves.toBeUndefined();
  });

  it('listActive returns empty after shutdownAll', async () => {
    controller.startExecution(makeOptions({ execution_id: 'shutdown-009' }));
    controller.startExecution(makeOptions({ execution_id: 'shutdown-010' }));

    await controller.shutdownAll();

    expect(controller.listActive()).toEqual([]);
  });
});
