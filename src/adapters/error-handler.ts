/**
 * Adapter Error Handling
 *
 * Standardized error types, retry logic with exponential backoff,
 * and circuit breaker for repeated adapter failures.
 *
 * @module adapters/error-handler
 */

import type { StepAction, AdapterResult } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/**
 * Base adapter error with structured context.
 */
export class AdapterOperationError extends Error {
  readonly code: string;
  readonly adapter: string;
  readonly action: StepAction;
  readonly retryable: boolean;

  constructor(opts: {
    code: string;
    message: string;
    adapter: string;
    action: StepAction;
    retryable: boolean;
    cause?: Error;
  }) {
    super(opts.message, { cause: opts.cause });
    this.name = 'AdapterOperationError';
    this.code = opts.code;
    this.adapter = opts.adapter;
    this.action = opts.action;
    this.retryable = opts.retryable;
  }
}

export class AdapterAuthError extends AdapterOperationError {
  constructor(adapter: string, action: StepAction, message?: string) {
    super({
      code: 'AUTH_ERROR',
      message: message ?? `Authentication failed for adapter '${adapter}'`,
      adapter,
      action,
      retryable: false,
    });
    this.name = 'AdapterAuthError';
  }
}

export class AdapterTimeoutError extends AdapterOperationError {
  readonly timeoutMs: number;

  constructor(adapter: string, action: StepAction, timeoutMs: number) {
    super({
      code: 'TIMEOUT_ERROR',
      message: `Adapter '${adapter}' timed out after ${timeoutMs}ms for action '${action}'`,
      adapter,
      action,
      retryable: true,
    });
    this.name = 'AdapterTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

export class AdapterRateLimitError extends AdapterOperationError {
  readonly retryAfterMs?: number;

  constructor(adapter: string, action: StepAction, retryAfterMs?: number) {
    super({
      code: 'RATE_LIMIT_ERROR',
      message: `Rate limit exceeded for adapter '${adapter}' on action '${action}'` +
        (retryAfterMs ? ` (retry after ${retryAfterMs}ms)` : ''),
      adapter,
      action,
      retryable: true,
    });
    this.name = 'AdapterRateLimitError';
    this.retryAfterMs = retryAfterMs;
  }
}

export class AdapterNotFoundError extends AdapterOperationError {
  constructor(adapter: string, action: StepAction) {
    super({
      code: 'ADAPTER_NOT_FOUND',
      message: `Adapter '${adapter}' not found for action '${action}'`,
      adapter,
      action,
      retryable: false,
    });
    this.name = 'AdapterNotFoundError';
  }
}

export class AdapterAPIError extends AdapterOperationError {
  readonly statusCode?: number;

  constructor(
    adapter: string,
    action: StepAction,
    message: string,
    statusCode?: number,
    retryable = false,
  ) {
    super({
      code: 'API_ERROR',
      message,
      adapter,
      action,
      retryable,
    });
    this.name = 'AdapterAPIError';
    this.statusCode = statusCode;
  }
}

// ---------------------------------------------------------------------------
// Retry Logic
// ---------------------------------------------------------------------------

export interface RetryOptions {
  maxAttempts: number;
  backoffMs: number;
  exponential: boolean;
  /** Maximum backoff in ms (cap for exponential). Default 30_000. */
  maxBackoffMs?: number;
  /** Called before each retry. Return false to abort. */
  onRetry?: (attempt: number, error: Error, delayMs: number) => boolean | void;
}

const DEFAULT_RETRY: RetryOptions = {
  maxAttempts: 3,
  backoffMs: 1000,
  exponential: true,
  maxBackoffMs: 30_000,
};

/**
 * Execute a function with retry and exponential backoff.
 *
 * Only retries when the error is an AdapterOperationError with `retryable: true`,
 * or when the error is a generic Error (assumed transient).
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  opts: Partial<RetryOptions> = {},
): Promise<T> {
  const config = { ...DEFAULT_RETRY, ...opts };
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));

      // Don't retry non-retryable errors
      if (err instanceof AdapterOperationError && !err.retryable) {
        throw err;
      }

      // Last attempt — no more retries
      if (attempt === config.maxAttempts) {
        throw lastError;
      }

      // Calculate delay
      let delayMs = config.exponential
        ? config.backoffMs * Math.pow(2, attempt - 1)
        : config.backoffMs;

      // Rate limit errors may specify retry-after
      if (err instanceof AdapterRateLimitError && err.retryAfterMs) {
        delayMs = Math.max(delayMs, err.retryAfterMs);
      }

      // Cap at maxBackoffMs
      delayMs = Math.min(delayMs, config.maxBackoffMs ?? 30_000);

      // Notify callback
      if (config.onRetry) {
        const shouldContinue = config.onRetry(attempt, lastError, delayMs);
        if (shouldContinue === false) {
          throw lastError;
        }
      }

      await sleep(delayMs);
    }
  }

  // Should never reach here
  throw lastError ?? new Error('Retry exhausted');
}

// ---------------------------------------------------------------------------
// Circuit Breaker
// ---------------------------------------------------------------------------

export type CircuitState = 'closed' | 'open' | 'half-open';

export interface CircuitBreakerOptions {
  /** Number of consecutive failures before opening. Default 5. */
  failureThreshold: number;
  /** Time in ms before attempting recovery (half-open). Default 60_000. */
  resetTimeoutMs: number;
  /** Number of successes in half-open required to close. Default 2. */
  successThreshold: number;
}

const DEFAULT_CIRCUIT: CircuitBreakerOptions = {
  failureThreshold: 5,
  resetTimeoutMs: 60_000,
  successThreshold: 2,
};

/**
 * Circuit breaker for adapter calls.
 *
 * States:
 *   closed    → normal operation, failures counted
 *   open      → all calls rejected immediately
 *   half-open → limited calls allowed to test recovery
 */
export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private readonly opts: CircuitBreakerOptions;

  constructor(opts: Partial<CircuitBreakerOptions> = {}) {
    this.opts = { ...DEFAULT_CIRCUIT, ...opts };
  }

  /**
   * Execute a function through the circuit breaker.
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      // Check if reset timeout has elapsed → move to half-open
      if (Date.now() - this.lastFailureTime >= this.opts.resetTimeoutMs) {
        this.state = 'half-open';
        this.successCount = 0;
      } else {
        throw new CircuitOpenError(this.opts.resetTimeoutMs - (Date.now() - this.lastFailureTime));
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  /** Current circuit state. */
  getState(): CircuitState {
    // Check if open should transition to half-open (for reads that don't trigger execute)
    if (this.state === 'open' && Date.now() - this.lastFailureTime >= this.opts.resetTimeoutMs) {
      return 'half-open';
    }
    return this.state;
  }

  /** Reset the circuit breaker to closed state. */
  reset(): void {
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }

  /** Current failure count. */
  getFailureCount(): number {
    return this.failureCount;
  }

  private onSuccess(): void {
    if (this.state === 'half-open') {
      this.successCount++;
      if (this.successCount >= this.opts.successThreshold) {
        this.state = 'closed';
        this.failureCount = 0;
        this.successCount = 0;
      }
    } else {
      // In closed state, reset failure count on success
      this.failureCount = 0;
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === 'half-open') {
      // Any failure in half-open → back to open
      this.state = 'open';
      this.successCount = 0;
    } else if (this.failureCount >= this.opts.failureThreshold) {
      this.state = 'open';
    }
  }
}

/**
 * Error thrown when the circuit breaker is open.
 */
export class CircuitOpenError extends Error {
  readonly remainingMs: number;

  constructor(remainingMs: number) {
    super(`Circuit breaker is open. Retry in ${Math.ceil(remainingMs / 1000)}s`);
    this.name = 'CircuitOpenError';
    this.remainingMs = remainingMs;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Convert an unknown error into a structured AdapterResult failure.
 */
export function errorToAdapterResult(
  error: unknown,
  adapter: string,
  action: StepAction,
  durationMs: number,
): AdapterResult {
  if (error instanceof AdapterOperationError) {
    return {
      success: false,
      action,
      executor: adapter,
      duration_ms: durationMs,
      error: {
        code: error.code,
        message: error.message,
        adapter: error.adapter,
        action: error.action,
        retryable: error.retryable,
      },
    };
  }

  const message = error instanceof Error ? error.message : String(error);
  return {
    success: false,
    action,
    executor: adapter,
    duration_ms: durationMs,
    error: {
      code: 'UNKNOWN_ERROR',
      message,
      adapter,
      action,
      retryable: false,
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
