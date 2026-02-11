import { describe, it, expect } from 'vitest';
import {
  AdapterOperationError,
  AdapterAuthError,
  AdapterTimeoutError,
  AdapterRateLimitError,
  AdapterNotFoundError,
  AdapterAPIError,
  withRetry,
  CircuitBreaker,
  CircuitOpenError,
  errorToAdapterResult,
} from '../../../src/adapters/error-handler.ts';
import type { StepAction } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ADAPTER = 'test-adapter';
const TEST_ACTION: StepAction = 'block_ip';

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

describe('Adapter Error Types', () => {
  // -----------------------------------------------------------------------
  // AdapterOperationError
  // -----------------------------------------------------------------------
  describe('AdapterOperationError', () => {
    it('stores all fields correctly', () => {
      const err = new AdapterOperationError({
        code: 'TEST_CODE',
        message: 'Something broke',
        adapter: TEST_ADAPTER,
        action: TEST_ACTION,
        retryable: true,
      });

      expect(err.name).toBe('AdapterOperationError');
      expect(err.code).toBe('TEST_CODE');
      expect(err.message).toBe('Something broke');
      expect(err.adapter).toBe(TEST_ADAPTER);
      expect(err.action).toBe(TEST_ACTION);
      expect(err.retryable).toBe(true);
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(AdapterOperationError);
    });

    it('preserves cause when provided', () => {
      const cause = new Error('root cause');
      const err = new AdapterOperationError({
        code: 'X',
        message: 'wrapper',
        adapter: TEST_ADAPTER,
        action: TEST_ACTION,
        retryable: false,
        cause,
      });

      expect(err.cause).toBe(cause);
    });
  });

  // -----------------------------------------------------------------------
  // AdapterAuthError
  // -----------------------------------------------------------------------
  describe('AdapterAuthError', () => {
    it('has correct name, code, and retryable=false', () => {
      const err = new AdapterAuthError(TEST_ADAPTER, TEST_ACTION);

      expect(err.name).toBe('AdapterAuthError');
      expect(err.code).toBe('AUTH_ERROR');
      expect(err.retryable).toBe(false);
      expect(err.adapter).toBe(TEST_ADAPTER);
      expect(err.action).toBe(TEST_ACTION);
      expect(err.message).toContain('Authentication failed');
      expect(err.message).toContain(TEST_ADAPTER);
    });

    it('is instanceof AdapterOperationError and Error', () => {
      const err = new AdapterAuthError(TEST_ADAPTER, TEST_ACTION);

      expect(err).toBeInstanceOf(AdapterAuthError);
      expect(err).toBeInstanceOf(AdapterOperationError);
      expect(err).toBeInstanceOf(Error);
    });

    it('uses custom message when provided', () => {
      const err = new AdapterAuthError(TEST_ADAPTER, TEST_ACTION, 'Token expired');

      expect(err.message).toBe('Token expired');
    });
  });

  // -----------------------------------------------------------------------
  // AdapterTimeoutError
  // -----------------------------------------------------------------------
  describe('AdapterTimeoutError', () => {
    it('has correct name, code, retryable=true, and timeoutMs', () => {
      const err = new AdapterTimeoutError(TEST_ADAPTER, TEST_ACTION, 5000);

      expect(err.name).toBe('AdapterTimeoutError');
      expect(err.code).toBe('TIMEOUT_ERROR');
      expect(err.retryable).toBe(true);
      expect(err.timeoutMs).toBe(5000);
      expect(err.message).toContain('5000ms');
      expect(err.message).toContain(TEST_ADAPTER);
      expect(err.message).toContain(TEST_ACTION);
    });

    it('is instanceof AdapterOperationError and Error', () => {
      const err = new AdapterTimeoutError(TEST_ADAPTER, TEST_ACTION, 3000);

      expect(err).toBeInstanceOf(AdapterTimeoutError);
      expect(err).toBeInstanceOf(AdapterOperationError);
      expect(err).toBeInstanceOf(Error);
    });
  });

  // -----------------------------------------------------------------------
  // AdapterRateLimitError
  // -----------------------------------------------------------------------
  describe('AdapterRateLimitError', () => {
    it('has correct name, code, retryable=true', () => {
      const err = new AdapterRateLimitError(TEST_ADAPTER, TEST_ACTION);

      expect(err.name).toBe('AdapterRateLimitError');
      expect(err.code).toBe('RATE_LIMIT_ERROR');
      expect(err.retryable).toBe(true);
      expect(err.retryAfterMs).toBeUndefined();
      expect(err.message).toContain('Rate limit exceeded');
    });

    it('stores retryAfterMs when provided', () => {
      const err = new AdapterRateLimitError(TEST_ADAPTER, TEST_ACTION, 10_000);

      expect(err.retryAfterMs).toBe(10_000);
      expect(err.message).toContain('retry after 10000ms');
    });

    it('is instanceof AdapterOperationError and Error', () => {
      const err = new AdapterRateLimitError(TEST_ADAPTER, TEST_ACTION, 500);

      expect(err).toBeInstanceOf(AdapterRateLimitError);
      expect(err).toBeInstanceOf(AdapterOperationError);
      expect(err).toBeInstanceOf(Error);
    });
  });

  // -----------------------------------------------------------------------
  // AdapterNotFoundError
  // -----------------------------------------------------------------------
  describe('AdapterNotFoundError', () => {
    it('has correct name, code, retryable=false', () => {
      const err = new AdapterNotFoundError(TEST_ADAPTER, TEST_ACTION);

      expect(err.name).toBe('AdapterNotFoundError');
      expect(err.code).toBe('ADAPTER_NOT_FOUND');
      expect(err.retryable).toBe(false);
      expect(err.message).toContain(TEST_ADAPTER);
      expect(err.message).toContain(TEST_ACTION);
    });

    it('is instanceof AdapterOperationError and Error', () => {
      const err = new AdapterNotFoundError(TEST_ADAPTER, TEST_ACTION);

      expect(err).toBeInstanceOf(AdapterNotFoundError);
      expect(err).toBeInstanceOf(AdapterOperationError);
      expect(err).toBeInstanceOf(Error);
    });
  });

  // -----------------------------------------------------------------------
  // AdapterAPIError
  // -----------------------------------------------------------------------
  describe('AdapterAPIError', () => {
    it('has correct name, code, and stores statusCode', () => {
      const err = new AdapterAPIError(
        TEST_ADAPTER,
        TEST_ACTION,
        'Internal server error',
        500,
        true,
      );

      expect(err.name).toBe('AdapterAPIError');
      expect(err.code).toBe('API_ERROR');
      expect(err.statusCode).toBe(500);
      expect(err.retryable).toBe(true);
      expect(err.message).toBe('Internal server error');
    });

    it('defaults retryable to false', () => {
      const err = new AdapterAPIError(
        TEST_ADAPTER,
        TEST_ACTION,
        'Bad request',
        400,
      );

      expect(err.retryable).toBe(false);
    });

    it('allows undefined statusCode', () => {
      const err = new AdapterAPIError(TEST_ADAPTER, TEST_ACTION, 'Unknown error');

      expect(err.statusCode).toBeUndefined();
      expect(err.retryable).toBe(false);
    });

    it('is instanceof AdapterOperationError and Error', () => {
      const err = new AdapterAPIError(TEST_ADAPTER, TEST_ACTION, 'err', 503, true);

      expect(err).toBeInstanceOf(AdapterAPIError);
      expect(err).toBeInstanceOf(AdapterOperationError);
      expect(err).toBeInstanceOf(Error);
    });
  });
});

// ---------------------------------------------------------------------------
// withRetry
// ---------------------------------------------------------------------------

describe('withRetry()', () => {
  it('succeeds on first try without retrying', async () => {
    let callCount = 0;
    const result = await withRetry(async () => {
      callCount++;
      return 'ok';
    }, { maxAttempts: 3, backoffMs: 1, exponential: false });

    expect(result).toBe('ok');
    expect(callCount).toBe(1);
  });

  it('retries on transient error and eventually succeeds', async () => {
    let callCount = 0;
    const result = await withRetry(async () => {
      callCount++;
      if (callCount < 3) {
        throw new Error('transient failure');
      }
      return 'recovered';
    }, { maxAttempts: 3, backoffMs: 1, exponential: false });

    expect(result).toBe('recovered');
    expect(callCount).toBe(3);
  });

  it('stops retrying on non-retryable AdapterOperationError', async () => {
    let callCount = 0;
    const nonRetryable = new AdapterAuthError(TEST_ADAPTER, TEST_ACTION);

    await expect(
      withRetry(async () => {
        callCount++;
        throw nonRetryable;
      }, { maxAttempts: 5, backoffMs: 1, exponential: false }),
    ).rejects.toThrow(nonRetryable);

    // Should have been called exactly once — no retries for non-retryable
    expect(callCount).toBe(1);
  });

  it('exhausts max attempts and throws the last error', async () => {
    let callCount = 0;

    await expect(
      withRetry(async () => {
        callCount++;
        throw new Error(`failure ${callCount}`);
      }, { maxAttempts: 3, backoffMs: 1, exponential: false }),
    ).rejects.toThrow('failure 3');

    expect(callCount).toBe(3);
  });

  it('respects rate limit retryAfterMs by using it as minimum delay', async () => {
    let callCount = 0;
    const startTime = Date.now();

    // Use a rate limit error with a 20ms retryAfterMs; backoffMs is only 1ms.
    // The delay should be at least 20ms.
    const result = await withRetry(async () => {
      callCount++;
      if (callCount === 1) {
        throw new AdapterRateLimitError(TEST_ADAPTER, TEST_ACTION, 20);
      }
      return 'done';
    }, { maxAttempts: 3, backoffMs: 1, exponential: false });

    const elapsed = Date.now() - startTime;

    expect(result).toBe('done');
    expect(callCount).toBe(2);
    // The delay should have been at least 20ms (from retryAfterMs)
    expect(elapsed).toBeGreaterThanOrEqual(15); // small tolerance for timing
  });

  it('calls onRetry callback with correct arguments', async () => {
    const retryCalls: Array<{ attempt: number; error: Error; delayMs: number }> = [];

    let callCount = 0;
    await withRetry(async () => {
      callCount++;
      if (callCount < 3) {
        throw new Error(`fail-${callCount}`);
      }
      return 'ok';
    }, {
      maxAttempts: 3,
      backoffMs: 2,
      exponential: false,
      onRetry: (attempt, error, delayMs) => {
        retryCalls.push({ attempt, error, delayMs });
      },
    });

    expect(retryCalls).toHaveLength(2);
    expect(retryCalls[0]?.attempt).toBe(1);
    expect(retryCalls[0]?.error.message).toBe('fail-1');
    expect(retryCalls[0]?.delayMs).toBe(2);
    expect(retryCalls[1]?.attempt).toBe(2);
    expect(retryCalls[1]?.error.message).toBe('fail-2');
  });

  it('aborts when onRetry returns false', async () => {
    let callCount = 0;

    await expect(
      withRetry(async () => {
        callCount++;
        throw new Error('always fails');
      }, {
        maxAttempts: 5,
        backoffMs: 1,
        exponential: false,
        onRetry: () => false,
      }),
    ).rejects.toThrow('always fails');

    // Called once, then onRetry returned false so no more retries
    expect(callCount).toBe(1);
  });

  it('retries retryable AdapterOperationError', async () => {
    let callCount = 0;
    const result = await withRetry(async () => {
      callCount++;
      if (callCount < 2) {
        throw new AdapterTimeoutError(TEST_ADAPTER, TEST_ACTION, 1000);
      }
      return 'recovered';
    }, { maxAttempts: 3, backoffMs: 1, exponential: false });

    expect(result).toBe('recovered');
    expect(callCount).toBe(2);
  });

  it('caps delay at maxBackoffMs', async () => {
    const retryCalls: number[] = [];
    let callCount = 0;

    await withRetry(async () => {
      callCount++;
      if (callCount < 3) {
        throw new Error('fail');
      }
      return 'ok';
    }, {
      maxAttempts: 3,
      backoffMs: 100,
      exponential: true,
      maxBackoffMs: 5,
      onRetry: (_attempt, _error, delayMs) => {
        retryCalls.push(delayMs);
      },
    });

    // Both delays should be capped at 5ms
    for (const delay of retryCalls) {
      expect(delay).toBeLessThanOrEqual(5);
    }
  });
});

// ---------------------------------------------------------------------------
// CircuitBreaker
// ---------------------------------------------------------------------------

describe('CircuitBreaker', () => {
  it('starts in closed state', () => {
    const cb = new CircuitBreaker();
    expect(cb.getState()).toBe('closed');
    expect(cb.getFailureCount()).toBe(0);
  });

  it('remains closed when calls succeed', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 50, successThreshold: 1 });

    await cb.execute(async () => 'ok');
    await cb.execute(async () => 'ok');

    expect(cb.getState()).toBe('closed');
    expect(cb.getFailureCount()).toBe(0);
  });

  it('opens after failureThreshold consecutive failures', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 50,
      successThreshold: 1,
    });

    for (let i = 0; i < 3; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow('fail');
    }

    expect(cb.getState()).toBe('open');
    expect(cb.getFailureCount()).toBe(3);
  });

  it('rejects calls with CircuitOpenError when open', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 500,
      successThreshold: 1,
    });

    // Open the circuit
    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow('fail');
    }

    expect(cb.getState()).toBe('open');

    // Next call should throw CircuitOpenError
    await expect(cb.execute(async () => 'should not run')).rejects.toThrow(CircuitOpenError);

    try {
      await cb.execute(async () => 'should not run');
    } catch (err) {
      expect(err).toBeInstanceOf(CircuitOpenError);
      if (err instanceof CircuitOpenError) {
        expect(err.remainingMs).toBeGreaterThan(0);
        expect(err.remainingMs).toBeLessThanOrEqual(500);
        expect(err.name).toBe('CircuitOpenError');
      }
    }
  });

  it('transitions to half-open after resetTimeoutMs elapses', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 30,
      successThreshold: 1,
    });

    // Open the circuit
    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow('fail');
    }
    expect(cb.getState()).toBe('open');

    // Wait for reset timeout
    await new Promise<void>((resolve) => setTimeout(resolve, 50));

    // getState() should now report half-open
    expect(cb.getState()).toBe('half-open');
  });

  it('closes after successThreshold successes in half-open', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 20,
      successThreshold: 2,
    });

    // Open the circuit
    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    }
    expect(cb.getState()).toBe('open');

    // Wait for reset timeout
    await new Promise<void>((resolve) => setTimeout(resolve, 40));

    // Succeed twice to meet successThreshold
    await cb.execute(async () => 'ok');
    await cb.execute(async () => 'ok');

    expect(cb.getState()).toBe('closed');
    expect(cb.getFailureCount()).toBe(0);
  });

  it('reopens on any failure in half-open state', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 20,
      successThreshold: 3,
    });

    // Open the circuit
    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    }
    expect(cb.getState()).toBe('open');

    // Wait for reset timeout
    await new Promise<void>((resolve) => setTimeout(resolve, 40));

    // One success in half-open
    await cb.execute(async () => 'ok');

    // Then a failure in half-open -- should reopen
    await expect(cb.execute(async () => { throw new Error('boom'); })).rejects.toThrow('boom');

    expect(cb.getState()).toBe('open');
  });

  it('reset() returns circuit to closed state', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 60_000,
      successThreshold: 1,
    });

    // Open the circuit
    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    }
    expect(cb.getState()).toBe('open');

    cb.reset();

    expect(cb.getState()).toBe('closed');
    expect(cb.getFailureCount()).toBe(0);

    // Should be able to execute normally after reset
    const result = await cb.execute(async () => 'after-reset');
    expect(result).toBe('after-reset');
  });

  it('resets failure count on success in closed state', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 3,
      resetTimeoutMs: 50,
      successThreshold: 1,
    });

    // Two failures (not enough to open)
    await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    expect(cb.getFailureCount()).toBe(2);

    // One success resets count
    await cb.execute(async () => 'ok');
    expect(cb.getFailureCount()).toBe(0);
  });

  it('allows execution in half-open after timeout', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 1,
      resetTimeoutMs: 20,
      successThreshold: 1,
    });

    // Open with a single failure
    await expect(cb.execute(async () => { throw new Error('fail'); })).rejects.toThrow();
    expect(cb.getState()).toBe('open');

    // Wait for timeout
    await new Promise<void>((resolve) => setTimeout(resolve, 40));

    // Should transition to half-open and allow execution
    const result = await cb.execute(async () => 'recovery');
    expect(result).toBe('recovery');
    // One success with successThreshold=1 should close it
    expect(cb.getState()).toBe('closed');
  });
});

// ---------------------------------------------------------------------------
// errorToAdapterResult
// ---------------------------------------------------------------------------

describe('errorToAdapterResult()', () => {
  it('converts AdapterOperationError to structured AdapterResult', () => {
    const err = new AdapterTimeoutError(TEST_ADAPTER, TEST_ACTION, 5000);
    const result = errorToAdapterResult(err, TEST_ADAPTER, TEST_ACTION, 5000);

    expect(result.success).toBe(false);
    expect(result.action).toBe(TEST_ACTION);
    expect(result.executor).toBe(TEST_ADAPTER);
    expect(result.duration_ms).toBe(5000);
    expect(result.error).toBeDefined();
    expect(result.error?.code).toBe('TIMEOUT_ERROR');
    expect(result.error?.message).toContain('timed out');
    expect(result.error?.adapter).toBe(TEST_ADAPTER);
    expect(result.error?.action).toBe(TEST_ACTION);
    expect(result.error?.retryable).toBe(true);
  });

  it('converts generic Error to UNKNOWN_ERROR result', () => {
    const err = new Error('Something unexpected');
    const result = errorToAdapterResult(err, TEST_ADAPTER, TEST_ACTION, 100);

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe('UNKNOWN_ERROR');
    expect(result.error?.message).toBe('Something unexpected');
    expect(result.error?.adapter).toBe(TEST_ADAPTER);
    expect(result.error?.action).toBe(TEST_ACTION);
    expect(result.error?.retryable).toBe(false);
  });

  it('converts non-Error value to UNKNOWN_ERROR result', () => {
    const result = errorToAdapterResult('string error', TEST_ADAPTER, TEST_ACTION, 50);

    expect(result.success).toBe(false);
    expect(result.error?.code).toBe('UNKNOWN_ERROR');
    expect(result.error?.message).toBe('string error');
    expect(result.error?.retryable).toBe(false);
  });

  it('preserves adapter and action from the AdapterOperationError', () => {
    const err = new AdapterAuthError('other-adapter', 'isolate_host');
    const result = errorToAdapterResult(err, TEST_ADAPTER, TEST_ACTION, 0);

    // The result uses the adapter/action params for top-level fields
    expect(result.executor).toBe(TEST_ADAPTER);
    expect(result.action).toBe(TEST_ACTION);

    // But the error block preserves the error's own adapter/action
    expect(result.error?.adapter).toBe('other-adapter');
    expect(result.error?.action).toBe('isolate_host');
  });

  it('converts AdapterAPIError with statusCode', () => {
    const err = new AdapterAPIError(TEST_ADAPTER, TEST_ACTION, 'Server error', 503, true);
    const result = errorToAdapterResult(err, TEST_ADAPTER, TEST_ACTION, 200);

    expect(result.error?.code).toBe('API_ERROR');
    expect(result.error?.message).toBe('Server error');
    expect(result.error?.retryable).toBe(true);
  });
});
