/**
 * RunbookPilot Error Handler (S5-009)
 *
 * Production-ready error handling: user-facing error sanitization,
 * retry logic for transient failures, and structured error codes.
 *
 * @module engine/error-handler
 */

import type { ExecutionError, AdapterError, StepAction } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export const ERROR_CODES = {
  // Execution errors
  EXEC_TIMEOUT: 'EXEC_TIMEOUT',
  EXEC_CANCELLED: 'EXEC_CANCELLED',
  EXEC_VALIDATION_FAILED: 'EXEC_VALIDATION_FAILED',
  EXEC_STATE_INVALID: 'EXEC_STATE_INVALID',

  // Adapter errors
  ADAPTER_TIMEOUT: 'ADAPTER_TIMEOUT',
  ADAPTER_CONNECTION: 'ADAPTER_CONNECTION',
  ADAPTER_AUTH: 'ADAPTER_AUTH',
  ADAPTER_RATE_LIMIT: 'ADAPTER_RATE_LIMIT',
  ADAPTER_NOT_FOUND: 'ADAPTER_NOT_FOUND',
  ADAPTER_EXECUTION_FAILED: 'ADAPTER_EXECUTION_FAILED',

  // Playbook errors
  PLAYBOOK_NOT_FOUND: 'PLAYBOOK_NOT_FOUND',
  PLAYBOOK_INVALID: 'PLAYBOOK_INVALID',
  PLAYBOOK_STEP_FAILED: 'PLAYBOOK_STEP_FAILED',

  // Approval errors
  APPROVAL_TIMEOUT: 'APPROVAL_TIMEOUT',
  APPROVAL_DENIED: 'APPROVAL_DENIED',
  APPROVAL_EXPIRED: 'APPROVAL_EXPIRED',

  // LLM errors
  LLM_UNAVAILABLE: 'LLM_UNAVAILABLE',
  LLM_TIMEOUT: 'LLM_TIMEOUT',
  LLM_RATE_LIMIT: 'LLM_RATE_LIMIT',

  // General
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  INVALID_INPUT: 'INVALID_INPUT',
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs: number;
  exponential: boolean;
  retryableErrors?: Set<string>;
}

const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  baseDelayMs: 1000,
  exponential: true,
};

/**
 * Retry a function with configurable backoff.
 * Only retries on errors that match retryableErrors (if provided).
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {},
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Check if this error is retryable
      if (opts.retryableErrors && !isRetryable(lastError, opts.retryableErrors)) {
        throw lastError;
      }

      if (attempt < opts.maxAttempts) {
        const delay = opts.exponential
          ? opts.baseDelayMs * Math.pow(2, attempt - 1)
          : opts.baseDelayMs;
        await sleep(delay);
      }
    }
  }

  throw lastError!;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryable(error: Error, retryableErrors: Set<string>): boolean {
  const message = error.message.toLowerCase();
  for (const pattern of retryableErrors) {
    if (message.includes(pattern.toLowerCase())) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

const RETRYABLE_PATTERNS = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EPIPE',
  'network',
  'timeout',
  'rate limit',
  '429',
  '503',
  '502',
]);

/**
 * Classify an error and determine if it's retryable.
 */
export function classifyError(error: unknown): {
  code: ErrorCode;
  message: string;
  retryable: boolean;
} {
  const msg = error instanceof Error ? error.message : String(error);
  const lower = msg.toLowerCase();

  if (lower.includes('timeout') || lower.includes('etimedout')) {
    return { code: ERROR_CODES.ADAPTER_TIMEOUT, message: msg, retryable: true };
  }
  if (lower.includes('econnrefused') || lower.includes('econnreset')) {
    return { code: ERROR_CODES.ADAPTER_CONNECTION, message: msg, retryable: true };
  }
  if (lower.includes('401') || lower.includes('unauthorized') || lower.includes('auth')) {
    return { code: ERROR_CODES.ADAPTER_AUTH, message: msg, retryable: false };
  }
  if (lower.includes('429') || lower.includes('rate limit')) {
    return { code: ERROR_CODES.ADAPTER_RATE_LIMIT, message: msg, retryable: true };
  }

  return { code: ERROR_CODES.INTERNAL_ERROR, message: msg, retryable: false };
}

/**
 * Check if a raw error is retryable based on known patterns.
 */
export function isErrorRetryable(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error);
  return isRetryable(new Error(msg), RETRYABLE_PATTERNS);
}

// ---------------------------------------------------------------------------
// User-facing error sanitization
// ---------------------------------------------------------------------------

/**
 * Sanitize an error for user-facing output.
 * Removes stack traces, internal paths, and sensitive details.
 */
export function sanitizeError(error: ExecutionError): ExecutionError {
  return {
    code: error.code,
    message: sanitizeMessage(error.message),
    step_id: error.step_id,
    // Omit details and stack for user-facing output
  };
}

/**
 * Sanitize an adapter error for user-facing output.
 */
export function sanitizeAdapterError(error: AdapterError): AdapterError {
  return {
    code: error.code,
    message: sanitizeMessage(error.message),
    step_id: error.step_id,
    adapter: error.adapter,
    action: error.action,
    retryable: error.retryable,
  };
}

function sanitizeMessage(message: string): string {
  // Remove file paths
  let sanitized = message.replace(/\/[^\s:]+\.(ts|js|json)/g, '[internal]');
  // Remove stack-like lines
  sanitized = sanitized.replace(/\s+at\s+.+/g, '');
  // Remove internal error details
  sanitized = sanitized.replace(/\(node:\d+\)/g, '');
  // Trim excessive whitespace
  sanitized = sanitized.replace(/\s+/g, ' ').trim();
  return sanitized;
}

// ---------------------------------------------------------------------------
// Error creation helpers
// ---------------------------------------------------------------------------

/**
 * Create a structured ExecutionError.
 */
export function createExecutionError(
  code: ErrorCode,
  message: string,
  stepId?: string,
  details?: Record<string, unknown>,
): ExecutionError {
  return {
    code,
    message,
    step_id: stepId,
    details,
  };
}

/**
 * Create a structured AdapterError.
 */
export function createAdapterError(
  code: ErrorCode,
  message: string,
  adapter: string,
  action: StepAction,
  retryable: boolean,
  stepId?: string,
): AdapterError {
  return {
    code,
    message,
    adapter,
    action,
    retryable,
    step_id: stepId,
  };
}

/**
 * User-friendly error messages for common error codes.
 */
export function getUserMessage(code: ErrorCode): string {
  const messages: Record<ErrorCode, string> = {
    [ERROR_CODES.EXEC_TIMEOUT]: 'Execution timed out. Try increasing the timeout or check adapter connectivity.',
    [ERROR_CODES.EXEC_CANCELLED]: 'Execution was cancelled by the user or system.',
    [ERROR_CODES.EXEC_VALIDATION_FAILED]: 'Playbook validation failed. Check the playbook YAML syntax.',
    [ERROR_CODES.EXEC_STATE_INVALID]: 'Invalid execution state transition. This is an internal error.',
    [ERROR_CODES.ADAPTER_TIMEOUT]: 'Adapter call timed out. Check network connectivity and adapter health.',
    [ERROR_CODES.ADAPTER_CONNECTION]: 'Could not connect to adapter endpoint. Verify the service is running.',
    [ERROR_CODES.ADAPTER_AUTH]: 'Authentication failed. Check adapter credentials in config.',
    [ERROR_CODES.ADAPTER_RATE_LIMIT]: 'Rate limit exceeded. The request will be retried automatically.',
    [ERROR_CODES.ADAPTER_NOT_FOUND]: 'Adapter not found. Check the adapter name in the playbook step.',
    [ERROR_CODES.ADAPTER_EXECUTION_FAILED]: 'Adapter execution failed. Check adapter logs for details.',
    [ERROR_CODES.PLAYBOOK_NOT_FOUND]: 'Playbook not found. Verify the playbook path or ID.',
    [ERROR_CODES.PLAYBOOK_INVALID]: 'Playbook is invalid. Run `runbookpilot validate` for details.',
    [ERROR_CODES.PLAYBOOK_STEP_FAILED]: 'A playbook step failed. Check the execution log for details.',
    [ERROR_CODES.APPROVAL_TIMEOUT]: 'Approval request timed out. Resubmit or increase timeout.',
    [ERROR_CODES.APPROVAL_DENIED]: 'Approval was denied by the reviewer.',
    [ERROR_CODES.APPROVAL_EXPIRED]: 'Approval request expired before review.',
    [ERROR_CODES.LLM_UNAVAILABLE]: 'LLM service unavailable. Enrichment will proceed without AI summary.',
    [ERROR_CODES.LLM_TIMEOUT]: 'LLM request timed out. Enrichment will proceed without AI summary.',
    [ERROR_CODES.LLM_RATE_LIMIT]: 'LLM rate limit reached. Retrying with backoff.',
    [ERROR_CODES.INTERNAL_ERROR]: 'An internal error occurred. Check the logs for details.',
    [ERROR_CODES.INVALID_INPUT]: 'Invalid input. Check the command arguments and options.',
  };

  return messages[code] ?? 'An unknown error occurred.';
}
