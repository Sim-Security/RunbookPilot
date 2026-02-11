import { describe, it, expect } from 'vitest';
import { BaseAdapter } from '../../../src/adapters/adapter-interface.ts';
import type {
  AdapterCapabilities,
  HealthCheckResult,
} from '../../../src/adapters/adapter-interface.ts';
import type {
  StepAction,
  ExecutionMode,
  AdapterResult,
  AdapterConfig,
} from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Concrete test subclass
// ---------------------------------------------------------------------------

/**
 * Minimal concrete implementation of BaseAdapter for testing
 * the abstract class behaviour.
 */
class TestAdapter extends BaseAdapter {
  readonly name = 'test-adapter';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = ['block_ip', 'unblock_ip'];

  async execute(
    action: StepAction,
    _params: Record<string, unknown>,
    _mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);
    return this.successResult(action, 42, { executed: true });
  }

  // Expose protected helpers so tests can call them directly
  publicAssertInitialized(): void {
    this.assertInitialized();
  }

  publicAssertSupportsAction(action: StepAction): void {
    this.assertSupportsAction(action);
  }

  publicSuccessResult(
    action: StepAction,
    durationMs: number,
    output?: unknown,
    metadata?: Record<string, unknown>,
  ): AdapterResult {
    return this.successResult(action, durationMs, output, metadata);
  }

  publicFailureResult(
    action: StepAction,
    durationMs: number,
    code: string,
    message: string,
    retryable?: boolean,
  ): AdapterResult {
    return this.failureResult(action, durationMs, code, message, retryable);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return {
    name: 'test-adapter',
    type: 'mock',
    enabled: true,
    config: {},
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('BaseAdapter', () => {
  // -----------------------------------------------------------------------
  // assertInitialized
  // -----------------------------------------------------------------------
  describe('assertInitialized()', () => {
    it('throws before initialize() is called', () => {
      const adapter = new TestAdapter();

      expect(() => adapter.publicAssertInitialized()).toThrow(
        "Adapter 'test-adapter' is not initialized. Call initialize() first.",
      );
    });

    it('does not throw after initialize() is called', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());

      expect(() => adapter.publicAssertInitialized()).not.toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // initialize
  // -----------------------------------------------------------------------
  describe('initialize()', () => {
    it('sets the initialized flag so assertInitialized passes', async () => {
      const adapter = new TestAdapter();

      // Before init — should throw
      expect(() => adapter.publicAssertInitialized()).toThrow();

      await adapter.initialize(makeConfig());

      // After init — should not throw
      expect(() => adapter.publicAssertInitialized()).not.toThrow();
    });

    it('stores the supplied config', async () => {
      const adapter = new TestAdapter();
      const cfg = makeConfig({ timeout: 60 });
      await adapter.initialize(cfg);

      // We can verify by checking healthCheck succeeds (depends on initialized flag)
      const health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');
    });
  });

  // -----------------------------------------------------------------------
  // assertSupportsAction
  // -----------------------------------------------------------------------
  describe('assertSupportsAction()', () => {
    it('throws for an unsupported action', () => {
      const adapter = new TestAdapter();

      expect(() => adapter.publicAssertSupportsAction('isolate_host')).toThrow(
        "Adapter 'test-adapter' does not support action 'isolate_host'",
      );
    });

    it('does not throw for a supported action', () => {
      const adapter = new TestAdapter();

      expect(() => adapter.publicAssertSupportsAction('block_ip')).not.toThrow();
      expect(() => adapter.publicAssertSupportsAction('unblock_ip')).not.toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // successResult
  // -----------------------------------------------------------------------
  describe('successResult()', () => {
    it('builds a correct successful AdapterResult', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicSuccessResult('block_ip', 150, { blocked: true });

      expect(result).toEqual({
        success: true,
        action: 'block_ip',
        executor: 'test-adapter',
        duration_ms: 150,
        output: { blocked: true },
        metadata: undefined,
      });
    });

    it('includes metadata when provided', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicSuccessResult(
        'unblock_ip',
        200,
        null,
        { correlation_id: 'abc-123' },
      );

      expect(result.success).toBe(true);
      expect(result.metadata).toEqual({ correlation_id: 'abc-123' });
    });

    it('sets output to undefined when omitted', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicSuccessResult('block_ip', 10);

      expect(result.output).toBeUndefined();
      expect(result.metadata).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // failureResult
  // -----------------------------------------------------------------------
  describe('failureResult()', () => {
    it('builds a correct failed AdapterResult', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicFailureResult(
        'block_ip',
        300,
        'TIMEOUT',
        'Connection timed out',
      );

      expect(result).toEqual({
        success: false,
        action: 'block_ip',
        executor: 'test-adapter',
        duration_ms: 300,
        error: {
          code: 'TIMEOUT',
          message: 'Connection timed out',
          adapter: 'test-adapter',
          action: 'block_ip',
          retryable: false,
        },
      });
    });

    it('sets retryable to true when specified', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicFailureResult(
        'unblock_ip',
        50,
        'RATE_LIMIT',
        'Too many requests',
        true,
      );

      expect(result.error?.retryable).toBe(true);
    });

    it('defaults retryable to false', () => {
      const adapter = new TestAdapter();
      const result = adapter.publicFailureResult('block_ip', 0, 'ERR', 'fail');

      expect(result.error?.retryable).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // rollback (default)
  // -----------------------------------------------------------------------
  describe('rollback() default implementation', () => {
    it('returns ROLLBACK_NOT_SUPPORTED', async () => {
      const adapter = new TestAdapter();
      const result = await adapter.rollback('block_ip', { ip: '1.2.3.4' });

      expect(result.success).toBe(false);
      expect(result.action).toBe('block_ip');
      expect(result.executor).toBe('test-adapter');
      expect(result.duration_ms).toBe(0);
      expect(result.error).toBeDefined();
      expect(result.error?.code).toBe('ROLLBACK_NOT_SUPPORTED');
      expect(result.error?.message).toContain('test-adapter');
      expect(result.error?.message).toContain('block_ip');
      expect(result.error?.retryable).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // healthCheck (default)
  // -----------------------------------------------------------------------
  describe('healthCheck() default implementation', () => {
    it('returns unknown status before initialization', async () => {
      const adapter = new TestAdapter();
      const health: HealthCheckResult = await adapter.healthCheck();

      expect(health.status).toBe('unknown');
      expect(health.checkedAt).toBeTruthy();
      // checkedAt should be a valid ISO 8601 string
      expect(() => new Date(health.checkedAt)).not.toThrow();
      expect(new Date(health.checkedAt).toISOString()).toBe(health.checkedAt);
    });

    it('returns healthy status after initialization', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());

      const health: HealthCheckResult = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.checkedAt).toBeTruthy();
    });
  });

  // -----------------------------------------------------------------------
  // getCapabilities (default)
  // -----------------------------------------------------------------------
  describe('getCapabilities() default implementation', () => {
    it('returns correct default capabilities', () => {
      const adapter = new TestAdapter();
      const caps: AdapterCapabilities = adapter.getCapabilities();

      expect(caps.supportedActions).toEqual(['block_ip', 'unblock_ip']);
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsRollback).toBe(false);
      expect(caps.supportsValidation).toBe(false);
      expect(caps.maxConcurrency).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // shutdown
  // -----------------------------------------------------------------------
  describe('shutdown()', () => {
    it('sets initialized to false', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());

      // Verify initialized
      expect(() => adapter.publicAssertInitialized()).not.toThrow();

      await adapter.shutdown();

      // After shutdown, assertInitialized should throw
      expect(() => adapter.publicAssertInitialized()).toThrow(
        "Adapter 'test-adapter' is not initialized. Call initialize() first.",
      );
    });

    it('healthCheck returns unknown after shutdown', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());
      await adapter.shutdown();

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unknown');
    });
  });

  // -----------------------------------------------------------------------
  // execute (via concrete subclass)
  // -----------------------------------------------------------------------
  describe('execute() via concrete subclass', () => {
    it('succeeds for a supported action when initialized', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());

      const result = await adapter.execute('block_ip', { ip: '10.0.0.1' }, 'production');

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(result.executor).toBe('test-adapter');
      expect(result.output).toEqual({ executed: true });
    });

    it('throws when not initialized', async () => {
      const adapter = new TestAdapter();

      await expect(
        adapter.execute('block_ip', {}, 'production'),
      ).rejects.toThrow("Adapter 'test-adapter' is not initialized");
    });

    it('throws for an unsupported action', async () => {
      const adapter = new TestAdapter();
      await adapter.initialize(makeConfig());

      await expect(
        adapter.execute('isolate_host', {}, 'production'),
      ).rejects.toThrow("does not support action 'isolate_host'");
    });
  });
});
