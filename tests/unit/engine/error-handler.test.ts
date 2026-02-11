import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  withRetry,
  classifyError,
  isErrorRetryable,
  sanitizeError,
  sanitizeAdapterError,
  createExecutionError,
  createAdapterError,
  getUserMessage,
  ERROR_CODES,
} from '../../../src/engine/error-handler.ts';
import type { ErrorCode } from '../../../src/engine/error-handler.ts';
import type { ExecutionError, AdapterError } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// withRetry
// ---------------------------------------------------------------------------

describe('withRetry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('succeeds on first attempt without retrying', async () => {
    const fn = vi.fn().mockResolvedValue('ok');

    const promise = withRetry(fn, { maxAttempts: 3, baseDelayMs: 100 });
    const result = await promise;

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on failure and succeeds on second attempt', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('connection reset'))
      .mockResolvedValue('ok');

    const promise = withRetry(fn, { maxAttempts: 3, baseDelayMs: 100, exponential: false });

    // Advance past the delay for the retry
    await vi.advanceTimersByTimeAsync(200);
    const result = await promise;

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries on failure and succeeds on third attempt', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('fail-1'))
      .mockRejectedValueOnce(new Error('fail-2'))
      .mockResolvedValue('ok');

    const promise = withRetry(fn, { maxAttempts: 3, baseDelayMs: 50, exponential: false });

    await vi.advanceTimersByTimeAsync(200);
    const result = await promise;

    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('gives up after maxAttempts and throws the last error', async () => {
    let callCount = 0;
    const fn = vi.fn(async () => {
      callCount++;
      throw new Error('always fails');
    });

    const promise = withRetry(fn, { maxAttempts: 3, baseDelayMs: 50, exponential: false });

    // Attach the rejection handler before advancing timers to avoid unhandled rejection
    const rejection = expect(promise).rejects.toThrow('always fails');

    await vi.advanceTimersByTimeAsync(500);
    await rejection;
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('respects exponential backoff delays', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('fail-1'))
      .mockRejectedValueOnce(new Error('fail-2'))
      .mockResolvedValue('ok');

    const promise = withRetry(fn, { maxAttempts: 3, baseDelayMs: 100, exponential: true });

    // First retry: baseDelay * 2^0 = 100ms
    await vi.advanceTimersByTimeAsync(100);
    expect(fn).toHaveBeenCalledTimes(2);

    // Second retry: baseDelay * 2^1 = 200ms
    await vi.advanceTimersByTimeAsync(200);
    const result = await promise;
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('skips non-retryable errors immediately', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('authentication failure'));

    const retryableErrors = new Set(['timeout', 'connection']);

    const promise = withRetry(fn, {
      maxAttempts: 5,
      baseDelayMs: 100,
      retryableErrors,
    });

    await expect(promise).rejects.toThrow('authentication failure');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries when error matches retryableErrors set', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('connection timeout occurred'))
      .mockResolvedValue('ok');

    const retryableErrors = new Set(['timeout']);

    const promise = withRetry(fn, {
      maxAttempts: 3,
      baseDelayMs: 50,
      exponential: false,
      retryableErrors,
    });

    await vi.advanceTimersByTimeAsync(200);
    const result = await promise;
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('converts non-Error thrown values to Error objects', async () => {
    const fn = vi.fn().mockRejectedValue('string error');

    const promise = withRetry(fn, { maxAttempts: 1, baseDelayMs: 10 });

    await expect(promise).rejects.toThrow('string error');
  });

  it('works with maxAttempts of 1 (no retries)', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('fail'));

    const promise = withRetry(fn, { maxAttempts: 1, baseDelayMs: 10 });
    await expect(promise).rejects.toThrow('fail');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('uses default options when none provided', async () => {
    const fn = vi.fn().mockResolvedValue('ok');

    const result = await withRetry(fn);
    expect(result).toBe('ok');
  });
});

// ---------------------------------------------------------------------------
// classifyError
// ---------------------------------------------------------------------------

describe('classifyError', () => {
  it('classifies timeout errors', () => {
    const result = classifyError(new Error('Request timeout'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_TIMEOUT);
    expect(result.retryable).toBe(true);
  });

  it('classifies ETIMEDOUT errors', () => {
    const result = classifyError(new Error('connect ETIMEDOUT'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_TIMEOUT);
    expect(result.retryable).toBe(true);
  });

  it('classifies ECONNREFUSED errors', () => {
    const result = classifyError(new Error('connect ECONNREFUSED 127.0.0.1:8080'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_CONNECTION);
    expect(result.retryable).toBe(true);
  });

  it('classifies ECONNRESET errors', () => {
    const result = classifyError(new Error('read ECONNRESET'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_CONNECTION);
    expect(result.retryable).toBe(true);
  });

  it('classifies 401 auth errors', () => {
    const result = classifyError(new Error('HTTP 401 Unauthorized'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_AUTH);
    expect(result.retryable).toBe(false);
  });

  it('classifies "unauthorized" auth errors', () => {
    const result = classifyError(new Error('Unauthorized access'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_AUTH);
    expect(result.retryable).toBe(false);
  });

  it('classifies "auth" errors', () => {
    const result = classifyError(new Error('Auth token expired'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_AUTH);
    expect(result.retryable).toBe(false);
  });

  it('classifies 429 rate limit errors', () => {
    const result = classifyError(new Error('HTTP 429 Too Many Requests'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_RATE_LIMIT);
    expect(result.retryable).toBe(true);
  });

  it('classifies "rate limit" errors', () => {
    const result = classifyError(new Error('Rate limit exceeded'));
    expect(result.code).toBe(ERROR_CODES.ADAPTER_RATE_LIMIT);
    expect(result.retryable).toBe(true);
  });

  it('classifies unknown errors as INTERNAL_ERROR', () => {
    const result = classifyError(new Error('Something unexpected happened'));
    expect(result.code).toBe(ERROR_CODES.INTERNAL_ERROR);
    expect(result.retryable).toBe(false);
  });

  it('handles non-Error values (string)', () => {
    const result = classifyError('string error');
    expect(result.code).toBe(ERROR_CODES.INTERNAL_ERROR);
    expect(result.message).toBe('string error');
  });

  it('handles non-Error values (number)', () => {
    const result = classifyError(42);
    expect(result.code).toBe(ERROR_CODES.INTERNAL_ERROR);
    expect(result.message).toBe('42');
  });

  it('preserves the original error message', () => {
    const msg = 'connect ECONNREFUSED 10.0.0.1:443';
    const result = classifyError(new Error(msg));
    expect(result.message).toBe(msg);
  });
});

// ---------------------------------------------------------------------------
// isErrorRetryable
// ---------------------------------------------------------------------------

describe('isErrorRetryable', () => {
  it('returns true for ECONNRESET', () => {
    expect(isErrorRetryable(new Error('read ECONNRESET'))).toBe(true);
  });

  it('returns true for ECONNREFUSED', () => {
    expect(isErrorRetryable(new Error('connect ECONNREFUSED'))).toBe(true);
  });

  it('returns true for ETIMEDOUT', () => {
    expect(isErrorRetryable(new Error('connect ETIMEDOUT'))).toBe(true);
  });

  it('returns true for EPIPE', () => {
    expect(isErrorRetryable(new Error('write EPIPE'))).toBe(true);
  });

  it('returns true for "network" errors', () => {
    expect(isErrorRetryable(new Error('Network error occurred'))).toBe(true);
  });

  it('returns true for "timeout" errors', () => {
    expect(isErrorRetryable(new Error('Request timeout'))).toBe(true);
  });

  it('returns true for "rate limit" errors', () => {
    expect(isErrorRetryable(new Error('Rate limit exceeded'))).toBe(true);
  });

  it('returns true for "429" errors', () => {
    expect(isErrorRetryable(new Error('HTTP 429'))).toBe(true);
  });

  it('returns true for "503" errors', () => {
    expect(isErrorRetryable(new Error('HTTP 503 Service Unavailable'))).toBe(true);
  });

  it('returns true for "502" errors', () => {
    expect(isErrorRetryable(new Error('HTTP 502 Bad Gateway'))).toBe(true);
  });

  it('returns false for auth errors', () => {
    expect(isErrorRetryable(new Error('Authentication failed'))).toBe(false);
  });

  it('returns false for unknown errors', () => {
    expect(isErrorRetryable(new Error('Something unexpected'))).toBe(false);
  });

  it('handles non-Error values', () => {
    expect(isErrorRetryable('timeout issue')).toBe(true);
    expect(isErrorRetryable('unrelated problem')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sanitizeError
// ---------------------------------------------------------------------------

describe('sanitizeError', () => {
  it('removes stack traces from message', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Something broke at /src/engine/foo.ts:42:10',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.message).not.toContain('/src/engine/foo.ts');
  });

  it('removes file paths from message', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Error in /home/user/project/src/adapter.ts processing',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.message).not.toContain('/home/user/project/src/adapter.ts');
    expect(sanitized.message).toContain('[internal]');
  });

  it('removes "at" stack-like lines', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Error occurred   at Module._compile (internal/modules/cjs/loader.js:1072:14)',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.message).not.toContain('at Module._compile');
  });

  it('removes node process references', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Something failed (node:12345) warning',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.message).not.toContain('(node:12345)');
  });

  it('preserves the error code', () => {
    const error: ExecutionError = {
      code: 'ADAPTER_TIMEOUT',
      message: 'Request timed out',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.code).toBe('ADAPTER_TIMEOUT');
  });

  it('preserves step_id', () => {
    const error: ExecutionError = {
      code: 'PLAYBOOK_STEP_FAILED',
      message: 'Step failed',
      step_id: 'step-42',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.step_id).toBe('step-42');
  });

  it('omits details from sanitized output', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Something happened',
      details: { secret: 'should-not-appear' },
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.details).toBeUndefined();
  });

  it('omits stack from sanitized output', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: 'Something happened',
      stack: 'Error: Something happened\n    at Object.<anonymous> (/src/foo.ts:1:1)',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.stack).toBeUndefined();
  });

  it('trims excessive whitespace', () => {
    const error: ExecutionError = {
      code: 'INTERNAL_ERROR',
      message: '  Too   many    spaces   here  ',
    };

    const sanitized = sanitizeError(error);
    expect(sanitized.message).toBe('Too many spaces here');
  });
});

// ---------------------------------------------------------------------------
// sanitizeAdapterError
// ---------------------------------------------------------------------------

describe('sanitizeAdapterError', () => {
  it('preserves adapter name', () => {
    const error: AdapterError = {
      code: 'ADAPTER_TIMEOUT',
      message: 'Timeout calling /api/v1/isolate.ts endpoint',
      adapter: 'crowdstrike-edr',
      action: 'isolate_host',
      retryable: true,
    };

    const sanitized = sanitizeAdapterError(error);
    expect(sanitized.adapter).toBe('crowdstrike-edr');
  });

  it('preserves action name', () => {
    const error: AdapterError = {
      code: 'ADAPTER_CONNECTION',
      message: 'Connection refused',
      adapter: 'firewall-palo',
      action: 'block_ip',
      retryable: true,
    };

    const sanitized = sanitizeAdapterError(error);
    expect(sanitized.action).toBe('block_ip');
  });

  it('preserves retryable flag', () => {
    const error: AdapterError = {
      code: 'ADAPTER_AUTH',
      message: 'Auth error',
      adapter: 'siem',
      action: 'collect_logs',
      retryable: false,
    };

    const sanitized = sanitizeAdapterError(error);
    expect(sanitized.retryable).toBe(false);
  });

  it('sanitizes the message (removes file paths)', () => {
    const error: AdapterError = {
      code: 'ADAPTER_EXECUTION_FAILED',
      message: 'Request to /opt/adapters/siem/query.ts failed with status 500',
      adapter: 'splunk-siem',
      action: 'query_siem',
      retryable: false,
    };

    const sanitized = sanitizeAdapterError(error);
    expect(sanitized.message).not.toContain('/opt/adapters/siem/query.ts');
    expect(sanitized.message).toContain('[internal]');
  });

  it('preserves step_id', () => {
    const error: AdapterError = {
      code: 'ADAPTER_TIMEOUT',
      message: 'Timeout',
      adapter: 'edr',
      action: 'isolate_host',
      retryable: true,
      step_id: 'step-7',
    };

    const sanitized = sanitizeAdapterError(error);
    expect(sanitized.step_id).toBe('step-7');
  });
});

// ---------------------------------------------------------------------------
// createExecutionError
// ---------------------------------------------------------------------------

describe('createExecutionError', () => {
  it('creates a structured ExecutionError', () => {
    const error = createExecutionError('EXEC_TIMEOUT', 'Execution timed out');
    expect(error.code).toBe('EXEC_TIMEOUT');
    expect(error.message).toBe('Execution timed out');
    expect(error.step_id).toBeUndefined();
    expect(error.details).toBeUndefined();
  });

  it('includes step_id when provided', () => {
    const error = createExecutionError('PLAYBOOK_STEP_FAILED', 'Step failed', 'step-3');
    expect(error.step_id).toBe('step-3');
  });

  it('includes details when provided', () => {
    const details = { expected: 'success', got: 'failure' };
    const error = createExecutionError('EXEC_VALIDATION_FAILED', 'Validation failed', undefined, details);
    expect(error.details).toEqual(details);
  });

  it('includes both step_id and details when provided', () => {
    const error = createExecutionError(
      'PLAYBOOK_STEP_FAILED',
      'Step 5 failed',
      'step-5',
      { reason: 'adapter returned 500' },
    );
    expect(error.step_id).toBe('step-5');
    expect(error.details).toEqual({ reason: 'adapter returned 500' });
  });
});

// ---------------------------------------------------------------------------
// createAdapterError
// ---------------------------------------------------------------------------

describe('createAdapterError', () => {
  it('creates a structured AdapterError', () => {
    const error = createAdapterError(
      'ADAPTER_TIMEOUT',
      'Adapter call timed out',
      'crowdstrike',
      'isolate_host',
      true,
    );

    expect(error.code).toBe('ADAPTER_TIMEOUT');
    expect(error.message).toBe('Adapter call timed out');
    expect(error.adapter).toBe('crowdstrike');
    expect(error.action).toBe('isolate_host');
    expect(error.retryable).toBe(true);
    expect(error.step_id).toBeUndefined();
  });

  it('includes step_id when provided', () => {
    const error = createAdapterError(
      'ADAPTER_CONNECTION',
      'Connection refused',
      'palo-alto',
      'block_ip',
      true,
      'step-2',
    );

    expect(error.step_id).toBe('step-2');
  });

  it('sets retryable to false for auth errors', () => {
    const error = createAdapterError(
      'ADAPTER_AUTH',
      'Invalid credentials',
      'splunk',
      'query_siem',
      false,
    );

    expect(error.retryable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getUserMessage
// ---------------------------------------------------------------------------

describe('getUserMessage', () => {
  it('returns correct message for EXEC_TIMEOUT', () => {
    const msg = getUserMessage(ERROR_CODES.EXEC_TIMEOUT);
    expect(msg).toContain('timed out');
  });

  it('returns correct message for EXEC_CANCELLED', () => {
    const msg = getUserMessage(ERROR_CODES.EXEC_CANCELLED);
    expect(msg).toContain('cancelled');
  });

  it('returns correct message for EXEC_VALIDATION_FAILED', () => {
    const msg = getUserMessage(ERROR_CODES.EXEC_VALIDATION_FAILED);
    expect(msg).toContain('validation');
  });

  it('returns correct message for ADAPTER_TIMEOUT', () => {
    const msg = getUserMessage(ERROR_CODES.ADAPTER_TIMEOUT);
    expect(msg).toContain('timed out');
  });

  it('returns correct message for ADAPTER_CONNECTION', () => {
    const msg = getUserMessage(ERROR_CODES.ADAPTER_CONNECTION);
    expect(msg).toContain('connect');
  });

  it('returns correct message for ADAPTER_AUTH', () => {
    const msg = getUserMessage(ERROR_CODES.ADAPTER_AUTH);
    expect(msg).toContain('uthentication');
  });

  it('returns correct message for ADAPTER_RATE_LIMIT', () => {
    const msg = getUserMessage(ERROR_CODES.ADAPTER_RATE_LIMIT);
    expect(msg).toContain('Rate limit');
  });

  it('returns correct message for PLAYBOOK_NOT_FOUND', () => {
    const msg = getUserMessage(ERROR_CODES.PLAYBOOK_NOT_FOUND);
    expect(msg).toContain('not found');
  });

  it('returns correct message for APPROVAL_DENIED', () => {
    const msg = getUserMessage(ERROR_CODES.APPROVAL_DENIED);
    expect(msg).toContain('denied');
  });

  it('returns correct message for LLM_UNAVAILABLE', () => {
    const msg = getUserMessage(ERROR_CODES.LLM_UNAVAILABLE);
    expect(msg).toContain('unavailable');
  });

  it('returns correct message for INTERNAL_ERROR', () => {
    const msg = getUserMessage(ERROR_CODES.INTERNAL_ERROR);
    expect(msg).toContain('internal error');
  });

  it('returns correct message for INVALID_INPUT', () => {
    const msg = getUserMessage(ERROR_CODES.INVALID_INPUT);
    expect(msg).toContain('Invalid input');
  });

  it('returns all non-empty messages for every error code', () => {
    for (const code of Object.values(ERROR_CODES)) {
      const msg = getUserMessage(code);
      expect(msg.length).toBeGreaterThan(0);
    }
  });

  it('returns a fallback for an unknown error code', () => {
    const msg = getUserMessage('TOTALLY_UNKNOWN_CODE' as ErrorCode);
    expect(msg).toContain('unknown error');
  });
});

// ---------------------------------------------------------------------------
// ERROR_CODES
// ---------------------------------------------------------------------------

describe('ERROR_CODES', () => {
  it('has all expected execution error codes', () => {
    expect(ERROR_CODES.EXEC_TIMEOUT).toBe('EXEC_TIMEOUT');
    expect(ERROR_CODES.EXEC_CANCELLED).toBe('EXEC_CANCELLED');
    expect(ERROR_CODES.EXEC_VALIDATION_FAILED).toBe('EXEC_VALIDATION_FAILED');
    expect(ERROR_CODES.EXEC_STATE_INVALID).toBe('EXEC_STATE_INVALID');
  });

  it('has all expected adapter error codes', () => {
    expect(ERROR_CODES.ADAPTER_TIMEOUT).toBe('ADAPTER_TIMEOUT');
    expect(ERROR_CODES.ADAPTER_CONNECTION).toBe('ADAPTER_CONNECTION');
    expect(ERROR_CODES.ADAPTER_AUTH).toBe('ADAPTER_AUTH');
    expect(ERROR_CODES.ADAPTER_RATE_LIMIT).toBe('ADAPTER_RATE_LIMIT');
    expect(ERROR_CODES.ADAPTER_NOT_FOUND).toBe('ADAPTER_NOT_FOUND');
    expect(ERROR_CODES.ADAPTER_EXECUTION_FAILED).toBe('ADAPTER_EXECUTION_FAILED');
  });

  it('has all expected playbook error codes', () => {
    expect(ERROR_CODES.PLAYBOOK_NOT_FOUND).toBe('PLAYBOOK_NOT_FOUND');
    expect(ERROR_CODES.PLAYBOOK_INVALID).toBe('PLAYBOOK_INVALID');
    expect(ERROR_CODES.PLAYBOOK_STEP_FAILED).toBe('PLAYBOOK_STEP_FAILED');
  });

  it('has all expected approval error codes', () => {
    expect(ERROR_CODES.APPROVAL_TIMEOUT).toBe('APPROVAL_TIMEOUT');
    expect(ERROR_CODES.APPROVAL_DENIED).toBe('APPROVAL_DENIED');
    expect(ERROR_CODES.APPROVAL_EXPIRED).toBe('APPROVAL_EXPIRED');
  });

  it('has all expected LLM error codes', () => {
    expect(ERROR_CODES.LLM_UNAVAILABLE).toBe('LLM_UNAVAILABLE');
    expect(ERROR_CODES.LLM_TIMEOUT).toBe('LLM_TIMEOUT');
    expect(ERROR_CODES.LLM_RATE_LIMIT).toBe('LLM_RATE_LIMIT');
  });

  it('has general error codes', () => {
    expect(ERROR_CODES.INTERNAL_ERROR).toBe('INTERNAL_ERROR');
    expect(ERROR_CODES.INVALID_INPUT).toBe('INVALID_INPUT');
  });

  it('has exactly 21 error codes', () => {
    const codes = Object.keys(ERROR_CODES);
    expect(codes.length).toBe(21);
  });

  it('all values are unique strings', () => {
    const values = Object.values(ERROR_CODES);
    const uniqueValues = new Set(values);
    expect(uniqueValues.size).toBe(values.length);
  });
});
