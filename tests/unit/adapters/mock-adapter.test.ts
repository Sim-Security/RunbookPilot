/**
 * Unit tests for MockAdapter
 *
 * @module tests/unit/adapters/mock-adapter
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  MockAdapter,
  createMockAdapter,
  createFailingMockAdapter,
  createSlowMockAdapter,
} from '../../../src/adapters/mock/mock-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function defaultConfig(overrides: Record<string, unknown> = {}): AdapterConfig {
  return {
    name: 'mock',
    type: 'mock',
    enabled: true,
    config: overrides,
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('MockAdapter', () => {
  let adapter: MockAdapter;

  beforeEach(async () => {
    adapter = new MockAdapter();
    await adapter.initialize(defaultConfig());
  });

  // -----------------------------------------------------------------------
  // Construction
  // -----------------------------------------------------------------------

  describe('Construction', () => {
    it('creates with default options', () => {
      const a = new MockAdapter();
      expect(a.name).toBe('mock');
      expect(a.version).toBe('1.0.0');
    });

    it('creates with custom name', () => {
      const a = new MockAdapter({ name: 'my-mock' });
      expect(a.name).toBe('my-mock');
    });

    it('supports all actions', () => {
      const a = new MockAdapter();
      expect(a.supportedActions.length).toBeGreaterThan(20);
      expect(a.supportedActions).toContain('block_ip');
      expect(a.supportedActions).toContain('isolate_host');
      expect(a.supportedActions).toContain('collect_logs');
      expect(a.supportedActions).toContain('enrich_ioc');
      expect(a.supportedActions).toContain('create_ticket');
      expect(a.supportedActions).toContain('disable_account');
      expect(a.supportedActions).toContain('quarantine_file');
      expect(a.supportedActions).toContain('kill_process');
      expect(a.supportedActions).toContain('execute_script');
      expect(a.supportedActions).toContain('wait');
    });
  });

  // -----------------------------------------------------------------------
  // initialize()
  // -----------------------------------------------------------------------

  describe('initialize()', () => {
    it('reads latency from config', async () => {
      const a = new MockAdapter();
      await a.initialize(defaultConfig({ latency: 50 }));

      // The adapter should now use 50ms default latency.
      // We verify indirectly: execute should take at least ~50ms.
      const start = performance.now();
      await a.execute('block_ip', {}, 'production');
      const elapsed = performance.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(40); // allow some margin
    });

    it('reads unhealthy flag from config', async () => {
      const a = new MockAdapter();
      await a.initialize(defaultConfig({ unhealthy: true }));

      const health = await a.healthCheck();
      expect(health.status).toBe('unhealthy');
    });
  });

  // -----------------------------------------------------------------------
  // execute()
  // -----------------------------------------------------------------------

  describe('execute()', () => {
    it('returns success by default', async () => {
      const result = await adapter.execute('block_ip', { ip: '10.0.0.1' }, 'production');
      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(result.executor).toBe('mock');
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
    });

    it('returns mock output for block_ip', async () => {
      const result = await adapter.execute('block_ip', { ip: '192.168.1.1' }, 'production');
      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.mock).toBe(true);
      expect(output.ip).toBe('192.168.1.1');
      expect(output.status).toBe('completed');
      expect(output.action).toBe('block_ip');
    });

    it('returns mock output for collect_logs', async () => {
      const result = await adapter.execute('collect_logs', {}, 'production');
      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.event_count).toBe(42);
      expect(output.events).toBeDefined();
      expect(Array.isArray(output.events)).toBe(true);
    });

    it('returns mock output for enrich_ioc', async () => {
      const result = await adapter.execute('enrich_ioc', {}, 'production');
      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.detections).toBe(5);
      expect(output.total_engines).toBe(70);
      expect(output.threat_label).toBe('trojan.generic');
      expect(output.score).toBe(7.2);
    });

    it('returns mock output for create_ticket', async () => {
      const result = await adapter.execute('create_ticket', {}, 'production');
      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.ticket_id).toBe('INC-MOCK-001');
      expect(output.url).toBe('https://mock.ticket/INC-MOCK-001');
    });

    it('includes mode in output metadata', async () => {
      const result = await adapter.execute('block_ip', {}, 'simulation');
      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mode).toBe('simulation');
      expect(result.metadata!.mock).toBe(true);
    });

    it('respects custom behavior: success=false returns failure', async () => {
      adapter.setBehavior('block_ip', {
        success: false,
        errorCode: 'CUSTOM_ERR',
        errorMessage: 'Custom failure message',
      });

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('CUSTOM_ERR');
      expect(result.error!.message).toBe('Custom failure message');
    });

    it('respects custom behavior: latencyMs simulates delay', async () => {
      adapter.setBehavior('block_ip', { latencyMs: 100 });

      const start = performance.now();
      await adapter.execute('block_ip', {}, 'production');
      const elapsed = performance.now() - start;

      expect(elapsed).toBeGreaterThanOrEqual(80); // allow margin
    });

    it('returns custom output when set', async () => {
      const customOutput = { custom: true, data: [1, 2, 3] };
      adapter.setBehavior('block_ip', { output: customOutput });

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(true);
      expect(result.output).toEqual(customOutput);
    });

    it('throwError behavior throws an actual error', async () => {
      adapter.setBehavior('block_ip', {
        throwError: true,
        errorMessage: 'Kaboom',
      });

      await expect(
        adapter.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('Kaboom');
    });

    it('throwError uses default message when errorMessage not provided', async () => {
      adapter.setBehavior('collect_logs', { throwError: true });

      await expect(
        adapter.execute('collect_logs', {}, 'production'),
      ).rejects.toThrow("Mock error for 'collect_logs'");
    });

    it('throws if not initialized', async () => {
      const uninit = new MockAdapter();
      await expect(
        uninit.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('throws for unsupported action', async () => {
      // Force an unsupported action by casting
      await expect(
        adapter.execute('totally_fake_action' as never, {}, 'production'),
      ).rejects.toThrow('does not support action');
    });

    it('records the call with the correct result', async () => {
      const result = await adapter.execute('block_ip', { ip: '5.5.5.5' }, 'dry-run');
      const lastCall = adapter.getLastCall();

      expect(lastCall).toBeDefined();
      expect(lastCall!.action).toBe('block_ip');
      expect(lastCall!.params).toEqual({ ip: '5.5.5.5' });
      expect(lastCall!.mode).toBe('dry-run');
      expect(lastCall!.result).toEqual(result);
      expect(lastCall!.timestamp).toBeDefined();
    });

    it('uses default failure code and message when behavior has no overrides', async () => {
      adapter.setBehavior('block_ip', { success: false });

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('MOCK_FAILURE');
      expect(result.error!.message).toContain('block_ip');
    });

    it('respects retryable flag on failure behavior', async () => {
      adapter.setBehavior('block_ip', { success: false, retryable: true });

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(false);
      expect(result.error!.retryable).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // rollback()
  // -----------------------------------------------------------------------

  describe('rollback()', () => {
    it('returns success with rolled_back flag', async () => {
      const result = await adapter.rollback('block_ip', { ip: '1.2.3.4' });
      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(result.executor).toBe('mock');

      const output = result.output as Record<string, unknown>;
      expect(output.rolled_back).toBe(true);
      expect(output.original_action).toBe('block_ip');
      expect(output.params).toEqual({ ip: '1.2.3.4' });
    });

    it('includes mock metadata', async () => {
      const result = await adapter.rollback('isolate_host', { host: 'ws001' });
      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mock).toBe(true);
    });

    it('records the rollback call', async () => {
      await adapter.rollback('block_ip', { ip: '1.1.1.1' });

      const calls = adapter.getCalls();
      expect(calls.length).toBe(1);
      expect(calls[0]!.action).toBe('block_ip');
    });
  });

  // -----------------------------------------------------------------------
  // healthCheck()
  // -----------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy by default', async () => {
      const health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');
      expect(health.message).toBe('Mock adapter operational');
      expect(health.latencyMs).toBe(0);
      expect(health.checkedAt).toBeDefined();
    });

    it('returns unhealthy when configured', async () => {
      const unhealthy = new MockAdapter({ unhealthy: true });
      await unhealthy.initialize(defaultConfig());

      const health = await unhealthy.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toBe('Mock adapter configured as unhealthy');
    });
  });

  // -----------------------------------------------------------------------
  // getCapabilities()
  // -----------------------------------------------------------------------

  describe('getCapabilities()', () => {
    it('reports simulation, rollback, and validation support', () => {
      const caps = adapter.getCapabilities();
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsRollback).toBe(true);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(0);
      expect(caps.supportedActions).toBe(adapter.supportedActions);
    });
  });

  // -----------------------------------------------------------------------
  // validateParameters()
  // -----------------------------------------------------------------------

  describe('validateParameters()', () => {
    it('returns valid for supported actions', async () => {
      const result = await adapter.validateParameters('block_ip', { ip: '10.0.0.1' });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('returns invalid for unsupported actions', async () => {
      const result = await adapter.validateParameters(
        'not_real_action' as never,
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
      expect(result.errors![0]).toContain('Unsupported action');
    });
  });

  // -----------------------------------------------------------------------
  // Call Recording
  // -----------------------------------------------------------------------

  describe('Call Recording', () => {
    it('getCalls() records all calls', async () => {
      await adapter.execute('block_ip', { ip: '1.1.1.1' }, 'production');
      await adapter.execute('collect_logs', {}, 'simulation');
      await adapter.execute('enrich_ioc', {}, 'dry-run');

      const calls = adapter.getCalls();
      expect(calls).toHaveLength(3);
      expect(calls[0]!.action).toBe('block_ip');
      expect(calls[1]!.action).toBe('collect_logs');
      expect(calls[2]!.action).toBe('enrich_ioc');
    });

    it('getCallsForAction() filters by action', async () => {
      await adapter.execute('block_ip', { ip: '1.1.1.1' }, 'production');
      await adapter.execute('collect_logs', {}, 'simulation');
      await adapter.execute('block_ip', { ip: '2.2.2.2' }, 'production');

      const blockCalls = adapter.getCallsForAction('block_ip');
      expect(blockCalls).toHaveLength(2);
      expect(blockCalls[0]!.params).toEqual({ ip: '1.1.1.1' });
      expect(blockCalls[1]!.params).toEqual({ ip: '2.2.2.2' });
    });

    it('getLastCall() returns most recent', async () => {
      await adapter.execute('block_ip', {}, 'production');
      await adapter.execute('collect_logs', {}, 'simulation');

      const last = adapter.getLastCall();
      expect(last).toBeDefined();
      expect(last!.action).toBe('collect_logs');
    });

    it('getLastCall() returns undefined when no calls made', () => {
      expect(adapter.getLastCall()).toBeUndefined();
    });

    it('getCallCount() returns total', async () => {
      expect(adapter.getCallCount()).toBe(0);

      await adapter.execute('block_ip', {}, 'production');
      expect(adapter.getCallCount()).toBe(1);

      await adapter.execute('collect_logs', {}, 'production');
      expect(adapter.getCallCount()).toBe(2);
    });

    it('clearCalls() resets', async () => {
      await adapter.execute('block_ip', {}, 'production');
      await adapter.execute('collect_logs', {}, 'production');
      expect(adapter.getCallCount()).toBe(2);

      adapter.clearCalls();

      expect(adapter.getCallCount()).toBe(0);
      expect(adapter.getCalls()).toHaveLength(0);
      expect(adapter.getLastCall()).toBeUndefined();
    });

    it('wasCalled() checks if action was called', async () => {
      expect(adapter.wasCalled('block_ip')).toBe(false);

      await adapter.execute('block_ip', {}, 'production');
      expect(adapter.wasCalled('block_ip')).toBe(true);
      expect(adapter.wasCalled('collect_logs')).toBe(false);
    });

    it('wasCalledTimes() checks call count for an action', async () => {
      expect(adapter.wasCalledTimes('block_ip', 0)).toBe(true);

      await adapter.execute('block_ip', {}, 'production');
      expect(adapter.wasCalledTimes('block_ip', 1)).toBe(true);
      expect(adapter.wasCalledTimes('block_ip', 2)).toBe(false);

      await adapter.execute('block_ip', {}, 'production');
      expect(adapter.wasCalledTimes('block_ip', 2)).toBe(true);
    });

    it('throwError still records the call before throwing', async () => {
      adapter.setBehavior('block_ip', { throwError: true });

      await expect(adapter.execute('block_ip', {}, 'production')).rejects.toThrow();

      // The call should still be recorded
      expect(adapter.getCallCount()).toBe(1);
      const call = adapter.getLastCall();
      expect(call).toBeDefined();
      expect(call!.action).toBe('block_ip');
      expect(call!.result.success).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Behavior API
  // -----------------------------------------------------------------------

  describe('Behavior API', () => {
    it('setBehavior() changes runtime behavior', async () => {
      // Default succeeds
      const r1 = await adapter.execute('block_ip', {}, 'production');
      expect(r1.success).toBe(true);

      // Set to fail
      adapter.setBehavior('block_ip', { success: false });
      const r2 = await adapter.execute('block_ip', {}, 'production');
      expect(r2.success).toBe(false);
    });

    it('clearBehavior() removes override', async () => {
      adapter.setBehavior('block_ip', { success: false });
      const r1 = await adapter.execute('block_ip', {}, 'production');
      expect(r1.success).toBe(false);

      adapter.clearBehavior('block_ip');
      const r2 = await adapter.execute('block_ip', {}, 'production');
      expect(r2.success).toBe(true);
    });

    it('setHealthy() toggles health', async () => {
      const h1 = await adapter.healthCheck();
      expect(h1.status).toBe('healthy');

      adapter.setHealthy(false);
      const h2 = await adapter.healthCheck();
      expect(h2.status).toBe('unhealthy');

      adapter.setHealthy(true);
      const h3 = await adapter.healthCheck();
      expect(h3.status).toBe('healthy');
    });

    it('per-action behavior does not affect other actions', async () => {
      adapter.setBehavior('block_ip', { success: false });

      const blockResult = await adapter.execute('block_ip', {}, 'production');
      expect(blockResult.success).toBe(false);

      const logsResult = await adapter.execute('collect_logs', {}, 'production');
      expect(logsResult.success).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Factory Functions
  // -----------------------------------------------------------------------

  describe('Factory functions', () => {
    it('createMockAdapter() creates a default adapter', () => {
      const a = createMockAdapter();
      expect(a).toBeInstanceOf(MockAdapter);
      expect(a.name).toBe('mock');
    });

    it('createMockAdapter() accepts options', () => {
      const a = createMockAdapter({ name: 'custom-mock' });
      expect(a.name).toBe('custom-mock');
    });

    it('createFailingMockAdapter() creates adapter that fails specific actions', async () => {
      const a = createFailingMockAdapter(['block_ip', 'isolate_host'], 'Test failure');
      await a.initialize(defaultConfig());

      const blockResult = await a.execute('block_ip', {}, 'production');
      expect(blockResult.success).toBe(false);
      expect(blockResult.error!.message).toBe('Test failure');
      expect(blockResult.error!.code).toBe('MOCK_FAILURE');

      const isolateResult = await a.execute('isolate_host', {}, 'production');
      expect(isolateResult.success).toBe(false);
      expect(isolateResult.error!.message).toBe('Test failure');

      // Other actions should still succeed
      const logsResult = await a.execute('collect_logs', {}, 'production');
      expect(logsResult.success).toBe(true);
    });

    it('createFailingMockAdapter() uses default error message', async () => {
      const a = createFailingMockAdapter(['block_ip']);
      await a.initialize(defaultConfig());

      const result = await a.execute('block_ip', {}, 'production');
      expect(result.success).toBe(false);
      expect(result.error!.message).toBe('Simulated failure');
    });

    it('createSlowMockAdapter() creates adapter with latency', async () => {
      const a = createSlowMockAdapter(100);
      await a.initialize(defaultConfig());

      const start = performance.now();
      await a.execute('block_ip', {}, 'production');
      const elapsed = performance.now() - start;

      expect(elapsed).toBeGreaterThanOrEqual(80); // allow margin
    });

    it('createSlowMockAdapter() applies latency to all actions', async () => {
      const a = createSlowMockAdapter(80);
      await a.initialize(defaultConfig());

      const start = performance.now();
      await a.execute('collect_logs', {}, 'production');
      const elapsed = performance.now() - start;

      expect(elapsed).toBeGreaterThanOrEqual(60); // allow margin
    });
  });

  // -----------------------------------------------------------------------
  // Default Output Variations
  // -----------------------------------------------------------------------

  describe('Default output per action type', () => {
    it('isolate_host returns host and isolation_id', async () => {
      const result = await adapter.execute('isolate_host', { host: 'ws-001' }, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.host).toBe('ws-001');
      expect(output.isolation_id).toBe('mock-iso-001');
    });

    it('query_siem returns events', async () => {
      const result = await adapter.execute('query_siem', {}, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.event_count).toBe(42);
    });

    it('check_reputation returns detections and score', async () => {
      const result = await adapter.execute('check_reputation', {}, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.score).toBe(7.2);
      expect(output.detections).toBe(5);
    });

    it('retrieve_edr_data returns process_tree', async () => {
      const result = await adapter.execute('retrieve_edr_data', {}, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.process_tree).toBeDefined();
      expect(Array.isArray(output.process_tree)).toBe(true);
    });

    it('notify_analyst returns delivered and recipient', async () => {
      const result = await adapter.execute('notify_analyst', { recipient: 'soc@corp.com' }, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.delivered).toBe(true);
      expect(output.recipient).toBe('soc@corp.com');
    });

    it('disable_account returns account and status', async () => {
      const result = await adapter.execute('disable_account', { account: 'admin@corp.com' }, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.account).toBe('admin@corp.com');
      expect(output.status).toBe('completed');
    });

    it('quarantine_file returns path and status', async () => {
      const result = await adapter.execute('quarantine_file', { path: '/tmp/malware.exe' }, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.path).toBe('/tmp/malware.exe');
      expect(output.status).toBe('completed');
    });

    it('kill_process returns pid and killed flag', async () => {
      const result = await adapter.execute('kill_process', { pid: 9999 }, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.pid).toBe(9999);
      expect(output.killed).toBe(true);
    });

    it('wait returns base output only', async () => {
      const result = await adapter.execute('wait', {}, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.mock).toBe(true);
      expect(output.mode).toBe('production');
      expect(output.action).toBe('wait');
    });

    it('uses fallback defaults when params not provided', async () => {
      const result = await adapter.execute('block_ip', {}, 'production');
      const output = result.output as Record<string, unknown>;
      expect(output.ip).toBe('0.0.0.0');
    });
  });

  // -----------------------------------------------------------------------
  // shutdown()
  // -----------------------------------------------------------------------

  describe('shutdown()', () => {
    it('marks adapter as not initialized after shutdown', async () => {
      await adapter.shutdown();

      await expect(
        adapter.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('can be re-initialized after shutdown', async () => {
      await adapter.shutdown();
      await adapter.initialize(defaultConfig());

      const result = await adapter.execute('block_ip', {}, 'production');
      expect(result.success).toBe(true);
    });
  });
});
