/**
 * S2-012: Adapter Integration Tests
 *
 * Tests the full adapter lifecycle using mock mode: registration,
 * discovery, execution, rollback, health checks, error handling,
 * retry logic, and concurrent adapter calls.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AdapterRegistry } from '../../src/adapters/registry.ts';
import { MockAdapter, createFailingMockAdapter } from '../../src/adapters/mock/mock-adapter.ts';
import { CircuitBreaker, withRetry, AdapterTimeoutError, AdapterRateLimitError } from '../../src/adapters/error-handler.ts';
import { parseAdapterConfig, redactAdapterConfig } from '../../src/adapters/adapter-config.ts';
import type { AdapterConfig, StepAction } from '../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockConfig(name = 'mock', overrides: Record<string, unknown> = {}): AdapterConfig {
  return {
    name,
    type: 'mock',
    enabled: true,
    config: overrides,
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
  };
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

describe('Adapter Integration Tests', () => {
  let registry: AdapterRegistry;

  beforeEach(() => {
    registry = new AdapterRegistry();
  });

  afterEach(async () => {
    await registry.shutdownAll();
  });

  // -------------------------------------------------------------------------
  // Full Lifecycle
  // -------------------------------------------------------------------------

  describe('full adapter lifecycle', () => {
    it('register → execute → rollback → healthcheck → shutdown', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      // Execute
      const result = await adapter.execute('block_ip', { ip: '192.168.1.1' }, 'production');
      expect(result.success).toBe(true);
      expect(result.output).toBeDefined();

      // Rollback
      const rollback = await adapter.rollback('block_ip', { ip: '192.168.1.1' });
      expect(rollback.success).toBe(true);

      // Health check
      const health = await registry.healthCheck('mock');
      expect(health.status).toBe('healthy');

      // Shutdown
      await registry.shutdownAll();
      expect(registry.size).toBe(0);
    });

    it('registers multiple adapters and routes by action', async () => {
      const firewall = new MockAdapter({ name: 'firewall' });
      const edr = new MockAdapter({ name: 'edr' });
      const siem = new MockAdapter({ name: 'siem' });

      await registry.register(firewall, mockConfig('firewall'));
      await registry.register(edr, mockConfig('edr'));
      await registry.register(siem, mockConfig('siem'));

      expect(registry.size).toBe(3);
      expect(registry.list()).toContain('firewall');
      expect(registry.list()).toContain('edr');
      expect(registry.list()).toContain('siem');

      // All mock adapters support all actions
      const blockers = registry.getForAction('block_ip');
      expect(blockers.length).toBe(3);
    });
  });

  // -------------------------------------------------------------------------
  // Adapter Resolution via createResolver()
  // -------------------------------------------------------------------------

  describe('adapter resolution', () => {
    it('createResolver bridges to step-executor AdapterResolver', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      const resolver = registry.createResolver();

      const resolved = resolver('mock');
      expect(resolved).toBeDefined();
      expect(resolved!.name).toBe('mock');

      const missing = resolver('nonexistent');
      expect(missing).toBeUndefined();
    });

    it('resolved adapter executes actions correctly', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      const resolver = registry.createResolver();
      const resolved = resolver('mock')!;

      const result = await resolved.execute('collect_logs', { query: 'test' }, 'simulation');
      expect(result.success).toBe(true);
      expect(result.action).toBe('collect_logs');
    });
  });

  // -------------------------------------------------------------------------
  // Action Success Scenarios
  // -------------------------------------------------------------------------

  describe('action success scenarios', () => {
    let adapter: MockAdapter;

    beforeEach(async () => {
      adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());
    });

    const actions: StepAction[] = [
      'block_ip', 'isolate_host', 'collect_logs', 'enrich_ioc',
      'create_ticket', 'notify_analyst', 'disable_account', 'quarantine_file',
    ];

    for (const action of actions) {
      it(`executes '${action}' successfully in mock mode`, async () => {
        const result = await adapter.execute(action, {}, 'production');
        expect(result.success).toBe(true);
        expect(result.action).toBe(action);
        expect(result.executor).toBe('mock');
        expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      });
    }

    it('simulation mode returns success with mock flag', async () => {
      const result = await adapter.execute('block_ip', { ip: '10.0.0.1' }, 'simulation');
      expect(result.success).toBe(true);
      expect(result.metadata).toEqual({ mock: true, mode: 'simulation' });
    });

    it('dry-run mode returns success with mock flag', async () => {
      const result = await adapter.execute('block_ip', { ip: '10.0.0.1' }, 'dry-run');
      expect(result.success).toBe(true);
      expect(result.metadata).toEqual({ mock: true, mode: 'dry-run' });
    });
  });

  // -------------------------------------------------------------------------
  // Error Handling (auth failure, timeout, rate limit)
  // -------------------------------------------------------------------------

  describe('error handling', () => {
    it('adapter failure returns structured error result', async () => {
      const adapter = createFailingMockAdapter(['block_ip']);
      await registry.register(adapter, mockConfig());

      const result = await adapter.execute('block_ip', { ip: '1.1.1.1' }, 'production');
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('MOCK_FAILURE');
    });

    it('adapter throwing is caught by caller', async () => {
      const adapter = new MockAdapter({
        behaviors: {
          block_ip: { throwError: true, errorMessage: 'Connection refused' },
        },
      });
      await registry.register(adapter, mockConfig());

      await expect(
        adapter.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('Connection refused');
    });

    it('unhealthy adapter reports unhealthy health check', async () => {
      const adapter = new MockAdapter({ unhealthy: true });
      await registry.register(adapter, mockConfig());

      const health = await registry.healthCheck('mock');
      expect(health.status).toBe('unhealthy');
    });
  });

  // -------------------------------------------------------------------------
  // Retry Logic
  // -------------------------------------------------------------------------

  describe('retry logic', () => {
    it('withRetry succeeds after transient failures', async () => {
      let attempts = 0;
      const result = await withRetry(
        async () => {
          attempts++;
          if (attempts < 3) {
            throw new AdapterTimeoutError('mock', 'block_ip', 1000);
          }
          return 'success';
        },
        { maxAttempts: 3, backoffMs: 1, exponential: false },
      );

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    });

    it('withRetry exhausts attempts and throws', async () => {
      await expect(
        withRetry(
          async () => {
            throw new AdapterTimeoutError('mock', 'block_ip', 1000);
          },
          { maxAttempts: 2, backoffMs: 1, exponential: false },
        ),
      ).rejects.toThrow('timed out');
    });

    it('withRetry respects rate limit retryAfterMs', async () => {
      let attempts = 0;
      const start = performance.now();

      await withRetry(
        async () => {
          attempts++;
          if (attempts === 1) {
            throw new AdapterRateLimitError('mock', 'enrich_ioc', 50);
          }
          return 'ok';
        },
        { maxAttempts: 3, backoffMs: 1, exponential: false },
      );

      const elapsed = performance.now() - start;
      expect(attempts).toBe(2);
      expect(elapsed).toBeGreaterThanOrEqual(40); // ~50ms rate limit
    });
  });

  // -------------------------------------------------------------------------
  // Circuit Breaker
  // -------------------------------------------------------------------------

  describe('circuit breaker integration', () => {
    it('opens after repeated failures and rejects subsequent calls', async () => {
      const breaker = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 100, successThreshold: 1 });
      const adapter = createFailingMockAdapter(['block_ip']);
      await registry.register(adapter, mockConfig());

      // Trigger 3 failures
      for (let i = 0; i < 3; i++) {
        try {
          await breaker.execute(() => adapter.execute('block_ip', {}, 'production').then(r => {
            if (!r.success) throw new Error('failed');
            return r;
          }));
        } catch {
          // expected
        }
      }

      expect(breaker.getState()).toBe('open');

      // Subsequent call should be rejected immediately
      await expect(
        breaker.execute(() => adapter.execute('block_ip', {}, 'production')),
      ).rejects.toThrow('Circuit breaker is open');
    });

    it('recovers after reset timeout', async () => {
      const breaker = new CircuitBreaker({ failureThreshold: 2, resetTimeoutMs: 50, successThreshold: 1 });
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      // Trigger failures
      for (let i = 0; i < 2; i++) {
        try {
          await breaker.execute(async () => { throw new Error('fail'); });
        } catch {
          // expected
        }
      }

      expect(breaker.getState()).toBe('open');

      // Wait for reset
      await new Promise(resolve => setTimeout(resolve, 60));

      // Should transition to half-open and allow call
      const result = await breaker.execute(() =>
        adapter.execute('collect_logs', { query: 'test' }, 'production'),
      );
      expect(result.success).toBe(true);
      expect(breaker.getState()).toBe('closed');
    });
  });

  // -------------------------------------------------------------------------
  // Concurrent Adapter Calls
  // -------------------------------------------------------------------------

  describe('concurrent adapter calls', () => {
    it('handles 10 concurrent executions', async () => {
      const adapter = new MockAdapter({ defaultLatencyMs: 5 });
      await registry.register(adapter, mockConfig());

      const actions: StepAction[] = [
        'block_ip', 'collect_logs', 'enrich_ioc', 'isolate_host',
        'create_ticket', 'notify_analyst', 'disable_account',
        'quarantine_file', 'query_siem', 'check_reputation',
      ];

      const results = await Promise.all(
        actions.map((action) =>
          adapter.execute(action, {}, 'production'),
        ),
      );

      expect(results).toHaveLength(10);
      for (const result of results) {
        expect(result.success).toBe(true);
      }

      expect(adapter.getCallCount()).toBe(10);
    });

    it('concurrent health checks on multiple adapters', async () => {
      for (let i = 0; i < 5; i++) {
        const adapter = new MockAdapter({ name: `adapter-${i}` });
        await registry.register(adapter, mockConfig(`adapter-${i}`));
      }

      const healthResults = await registry.healthCheckAll();
      expect(healthResults.size).toBe(5);

      for (const [_name, result] of healthResults) {
        expect(result.status).toBe('healthy');
      }
    });
  });

  // -------------------------------------------------------------------------
  // Registration and Discovery
  // -------------------------------------------------------------------------

  describe('registration and discovery', () => {
    it('prevents duplicate registration', async () => {
      const adapter1 = new MockAdapter();
      const adapter2 = new MockAdapter();

      await registry.register(adapter1, mockConfig());

      await expect(
        registry.register(adapter2, mockConfig()),
      ).rejects.toThrow('already registered');
    });

    it('unregister removes from action index', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      expect(registry.getForAction('block_ip').length).toBe(1);

      await registry.unregister('mock');

      expect(registry.getForAction('block_ip').length).toBe(0);
      expect(registry.has('mock')).toBe(false);
    });

    it('getStats returns accurate coverage data', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      const stats = registry.getStats();
      expect(stats.totalAdapters).toBe(1);
      expect(stats.enabledAdapters).toBe(1);
      expect(stats.disabledAdapters).toBe(0);
      expect(stats.actionCoverage.size).toBeGreaterThan(0);
      expect(stats.actionCoverage.get('block_ip')).toContain('mock');
    });
  });

  // -------------------------------------------------------------------------
  // Configuration Integration
  // -------------------------------------------------------------------------

  describe('configuration integration', () => {
    it('parseAdapterConfig creates valid config for adapter init', async () => {
      const config = parseAdapterConfig('test-adapter', {
        name: 'test-adapter',
        type: 'mock',
        enabled: true,
        config: { latency: 5 },
        timeout: 15,
      });

      const adapter = new MockAdapter({ name: 'test-adapter' });
      await registry.register(adapter, config);

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(true);
    });

    it('redactAdapterConfig hides secrets in config', () => {
      const config = parseAdapterConfig('vt', {
        name: 'vt',
        type: 'enrichment',
        config: { base_url: 'https://vt.api.com' },
        credentials: { type: 'api_key', api_key: 'super-secret-key-123' },
      });

      const redacted = redactAdapterConfig(config);
      const creds = redacted.credentials as Record<string, unknown>;
      const credValues = creds.credentials as Record<string, unknown>;
      expect(credValues.api_key).toBe('***');
      expect(redacted.name).toBe('vt');
    });

    it('disabled adapter config is reflected in stats', async () => {
      const disabledConfig: AdapterConfig = {
        ...mockConfig('disabled-adapter'),
        enabled: false,
      };

      const adapter = new MockAdapter({ name: 'disabled-adapter' });
      await registry.register(adapter, disabledConfig);

      const stats = registry.getStats();
      expect(stats.disabledAdapters).toBe(1);
      expect(stats.enabledAdapters).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // Mock Adapter Call Recording
  // -------------------------------------------------------------------------

  describe('call recording for test assertions', () => {
    it('records all calls across multiple actions', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      await adapter.execute('block_ip', { ip: '1.1.1.1' }, 'production');
      await adapter.execute('collect_logs', { query: 'test' }, 'simulation');
      await adapter.execute('enrich_ioc', { ioc: 'abc123' }, 'dry-run');
      await adapter.rollback('block_ip', { ip: '1.1.1.1' });

      expect(adapter.getCallCount()).toBe(4);
      expect(adapter.wasCalled('block_ip')).toBe(true);
      expect(adapter.wasCalled('collect_logs')).toBe(true);
      expect(adapter.wasCalled('enrich_ioc')).toBe(true);
      expect(adapter.wasCalledTimes('block_ip', 2)).toBe(true); // execute + rollback
      expect(adapter.wasCalled('kill_process')).toBe(false);

      adapter.clearCalls();
      expect(adapter.getCallCount()).toBe(0);
    });

    it('getLastCall returns most recent execution', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      await adapter.execute('block_ip', {}, 'production');
      await adapter.execute('enrich_ioc', { ioc: 'hash' }, 'simulation');

      const last = adapter.getLastCall();
      expect(last).toBeDefined();
      expect(last!.action).toBe('enrich_ioc');
      expect(last!.mode).toBe('simulation');
    });
  });

  // -------------------------------------------------------------------------
  // Behavior Overrides at Runtime
  // -------------------------------------------------------------------------

  describe('runtime behavior overrides', () => {
    it('setBehavior changes action results dynamically', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      // Default: success
      let result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(true);

      // Override to fail
      adapter.setBehavior('block_ip', {
        success: false,
        errorCode: 'BLOCKED',
        errorMessage: 'Firewall unavailable',
      });

      result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('BLOCKED');

      // Clear override
      adapter.clearBehavior('block_ip');
      result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(true);
    });

    it('setHealthy toggles health check result', async () => {
      const adapter = new MockAdapter();
      await registry.register(adapter, mockConfig());

      let health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');

      adapter.setHealthy(false);
      health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');

      adapter.setHealthy(true);
      health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');
    });
  });
});
