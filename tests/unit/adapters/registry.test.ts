/**
 * Unit tests for AdapterRegistry
 *
 * @module tests/unit/adapters/registry
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  AdapterRegistry,
  getAdapterRegistry,
  resetAdapterRegistry,
} from '../../../src/adapters/registry.ts';
import { MockAdapter } from '../../../src/adapters/mock/mock-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockConfig(name = 'mock'): AdapterConfig {
  return {
    name,
    type: 'mock',
    enabled: true,
    config: {},
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
  };
}

function makeMockAdapter(name = 'mock'): MockAdapter {
  return new MockAdapter({ name });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AdapterRegistry', () => {
  let registry: AdapterRegistry;

  beforeEach(() => {
    registry = new AdapterRegistry();
    resetAdapterRegistry();
  });

  // -----------------------------------------------------------------------
  // register()
  // -----------------------------------------------------------------------

  describe('register()', () => {
    it('registers an adapter and makes it retrievable by name', async () => {
      const adapter = makeMockAdapter('mock-a');
      await registry.register(adapter, mockConfig('mock-a'));

      expect(registry.get('mock-a')).toBe(adapter);
    });

    it('calls initialize() on the adapter', async () => {
      const adapter = makeMockAdapter('mock-init');
      const config = mockConfig('mock-init');
      await registry.register(adapter, config);

      // After register, the adapter should be initialized (execute should not throw)
      const result = await adapter.execute('block_ip', { ip: '1.2.3.4' }, 'production');
      expect(result.success).toBe(true);
    });

    it('throws if adapter name is already registered', async () => {
      const adapter1 = makeMockAdapter('dup');
      const adapter2 = makeMockAdapter('dup');

      await registry.register(adapter1, mockConfig('dup'));
      await expect(registry.register(adapter2, mockConfig('dup'))).rejects.toThrow(
        "Adapter 'dup' is already registered",
      );
    });
  });

  // -----------------------------------------------------------------------
  // unregister()
  // -----------------------------------------------------------------------

  describe('unregister()', () => {
    it('removes adapter and calls shutdown()', async () => {
      const adapter = makeMockAdapter('bye');
      await registry.register(adapter, mockConfig('bye'));
      expect(registry.has('bye')).toBe(true);

      const removed = await registry.unregister('bye');
      expect(removed).toBe(true);
      expect(registry.has('bye')).toBe(false);

      // After shutdown, execute should throw because initialized = false
      await expect(
        adapter.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('returns false for unknown name', async () => {
      const removed = await registry.unregister('nonexistent');
      expect(removed).toBe(false);
    });

    it('removes adapter from action index', async () => {
      const adapter = makeMockAdapter('indexed');
      await registry.register(adapter, mockConfig('indexed'));

      // Before unregister, getForAction should find it
      expect(registry.getForAction('block_ip').length).toBe(1);

      await registry.unregister('indexed');

      // After unregister, action index should be cleared
      expect(registry.getForAction('block_ip')).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // get()
  // -----------------------------------------------------------------------

  describe('get()', () => {
    it('returns adapter by name', async () => {
      const adapter = makeMockAdapter('target');
      await registry.register(adapter, mockConfig('target'));

      expect(registry.get('target')).toBe(adapter);
    });

    it('returns undefined for unknown name', () => {
      expect(registry.get('ghost')).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // getForAction()
  // -----------------------------------------------------------------------

  describe('getForAction()', () => {
    it('returns adapters that support a given action', async () => {
      const adapter = makeMockAdapter('action-test');
      await registry.register(adapter, mockConfig('action-test'));

      const results = registry.getForAction('block_ip');
      expect(results).toHaveLength(1);
      expect(results[0]!.name).toBe('action-test');
    });

    it('returns empty array for unsupported action', () => {
      // Nothing registered, so no adapter for any action
      const results = registry.getForAction('block_ip');
      expect(results).toEqual([]);
    });

    it('returns multiple adapters if more than one supports the action', async () => {
      const adapter1 = makeMockAdapter('first');
      const adapter2 = makeMockAdapter('second');

      await registry.register(adapter1, mockConfig('first'));
      await registry.register(adapter2, mockConfig('second'));

      const results = registry.getForAction('block_ip');
      expect(results).toHaveLength(2);

      const names = results.map((a) => a.name);
      expect(names).toContain('first');
      expect(names).toContain('second');
    });
  });

  // -----------------------------------------------------------------------
  // has()
  // -----------------------------------------------------------------------

  describe('has()', () => {
    it('returns true for a registered adapter', async () => {
      const adapter = makeMockAdapter('exists');
      await registry.register(adapter, mockConfig('exists'));

      expect(registry.has('exists')).toBe(true);
    });

    it('returns false for an unknown adapter', () => {
      expect(registry.has('nope')).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // list()
  // -----------------------------------------------------------------------

  describe('list()', () => {
    it('returns names of all registered adapters', async () => {
      await registry.register(makeMockAdapter('alpha'), mockConfig('alpha'));
      await registry.register(makeMockAdapter('beta'), mockConfig('beta'));
      await registry.register(makeMockAdapter('gamma'), mockConfig('gamma'));

      const names = registry.list();
      expect(names).toHaveLength(3);
      expect(names).toContain('alpha');
      expect(names).toContain('beta');
      expect(names).toContain('gamma');
    });

    it('returns empty array when no adapters are registered', () => {
      expect(registry.list()).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // listDetailed()
  // -----------------------------------------------------------------------

  describe('listDetailed()', () => {
    it('returns full RegisteredAdapter entries', async () => {
      const config = mockConfig('detailed');
      const adapter = makeMockAdapter('detailed');
      await registry.register(adapter, config);

      const entries = registry.listDetailed();
      expect(entries).toHaveLength(1);

      const entry = entries[0]!;
      expect(entry.adapter).toBe(adapter);
      expect(entry.config).toBe(config);
      expect(entry.registeredAt).toBeDefined();
      // registeredAt should be a valid ISO date string
      expect(new Date(entry.registeredAt).toISOString()).toBe(entry.registeredAt);
    });
  });

  // -----------------------------------------------------------------------
  // size
  // -----------------------------------------------------------------------

  describe('size', () => {
    it('returns correct count', async () => {
      expect(registry.size).toBe(0);

      await registry.register(makeMockAdapter('a'), mockConfig('a'));
      expect(registry.size).toBe(1);

      await registry.register(makeMockAdapter('b'), mockConfig('b'));
      expect(registry.size).toBe(2);

      await registry.unregister('a');
      expect(registry.size).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // healthCheckAll()
  // -----------------------------------------------------------------------

  describe('healthCheckAll()', () => {
    it('runs health check on all adapters', async () => {
      await registry.register(makeMockAdapter('h1'), mockConfig('h1'));
      await registry.register(makeMockAdapter('h2'), mockConfig('h2'));

      const results = await registry.healthCheckAll();

      expect(results.size).toBe(2);
      expect(results.get('h1')?.status).toBe('healthy');
      expect(results.get('h2')?.status).toBe('healthy');
    });

    it('handles adapter health check errors gracefully', async () => {
      const adapter = makeMockAdapter('error-health');
      await registry.register(adapter, mockConfig('error-health'));

      // Monkey-patch healthCheck to throw
      adapter.healthCheck = async () => {
        throw new Error('Connection refused');
      };

      const results = await registry.healthCheckAll();
      const result = results.get('error-health');

      expect(result).toBeDefined();
      expect(result!.status).toBe('unhealthy');
      expect(result!.message).toBe('Connection refused');
    });
  });

  // -----------------------------------------------------------------------
  // healthCheck(name)
  // -----------------------------------------------------------------------

  describe('healthCheck(name)', () => {
    it('returns health for a specific adapter', async () => {
      await registry.register(makeMockAdapter('single-hc'), mockConfig('single-hc'));

      const result = await registry.healthCheck('single-hc');
      expect(result.status).toBe('healthy');
      expect(result.checkedAt).toBeDefined();
    });

    it('returns unknown for unregistered adapter', async () => {
      const result = await registry.healthCheck('missing');
      expect(result.status).toBe('unknown');
      expect(result.message).toContain('missing');
    });

    it('stores the result as lastHealthCheck on the entry', async () => {
      await registry.register(makeMockAdapter('track-hc'), mockConfig('track-hc'));

      await registry.healthCheck('track-hc');

      const entries = registry.listDetailed();
      const entry = entries.find((e) => e.adapter.name === 'track-hc');
      expect(entry?.lastHealthCheck).toBeDefined();
      expect(entry!.lastHealthCheck!.status).toBe('healthy');
    });

    it('handles health check errors for a specific adapter', async () => {
      const adapter = makeMockAdapter('err-hc');
      await registry.register(adapter, mockConfig('err-hc'));

      adapter.healthCheck = async () => {
        throw new Error('Timeout');
      };

      const result = await registry.healthCheck('err-hc');
      expect(result.status).toBe('unhealthy');
      expect(result.message).toBe('Timeout');
    });
  });

  // -----------------------------------------------------------------------
  // getStats()
  // -----------------------------------------------------------------------

  describe('getStats()', () => {
    it('returns correct counts and action coverage', async () => {
      const enabledConfig = mockConfig('enabled-adapter');
      enabledConfig.enabled = true;
      await registry.register(makeMockAdapter('enabled-adapter'), enabledConfig);

      const disabledConfig = mockConfig('disabled-adapter');
      disabledConfig.enabled = false;
      await registry.register(makeMockAdapter('disabled-adapter'), disabledConfig);

      const stats = registry.getStats();
      expect(stats.totalAdapters).toBe(2);
      expect(stats.enabledAdapters).toBe(1);
      expect(stats.disabledAdapters).toBe(1);
      expect(stats.actionCoverage).toBeInstanceOf(Map);

      // Both mock adapters support block_ip
      const blockIpAdapters = stats.actionCoverage.get('block_ip');
      expect(blockIpAdapters).toBeDefined();
      expect(blockIpAdapters).toContain('enabled-adapter');
      expect(blockIpAdapters).toContain('disabled-adapter');
    });

    it('returns empty stats for empty registry', () => {
      const stats = registry.getStats();
      expect(stats.totalAdapters).toBe(0);
      expect(stats.enabledAdapters).toBe(0);
      expect(stats.disabledAdapters).toBe(0);
      expect(stats.actionCoverage.size).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // createResolver()
  // -----------------------------------------------------------------------

  describe('createResolver()', () => {
    it('returns an AdapterResolver function', () => {
      const resolver = registry.createResolver();
      expect(typeof resolver).toBe('function');
    });

    it('resolver returns adapter for known name', async () => {
      const adapter = makeMockAdapter('resolvable');
      await registry.register(adapter, mockConfig('resolvable'));

      const resolver = registry.createResolver();
      const resolved = resolver('resolvable');

      expect(resolved).toBeDefined();
      expect(resolved!.name).toBe('resolvable');
    });

    it('resolver returns undefined for unknown name', () => {
      const resolver = registry.createResolver();
      expect(resolver('no-such-adapter')).toBeUndefined();
    });

    it('resolved adapter is usable as StepAdapter', async () => {
      const adapter = makeMockAdapter('step-compat');
      await registry.register(adapter, mockConfig('step-compat'));

      const resolver = registry.createResolver();
      const resolved = resolver('step-compat');

      expect(resolved).toBeDefined();
      const result = await resolved!.execute('block_ip', { ip: '10.0.0.1' }, 'simulation');
      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
    });
  });

  // -----------------------------------------------------------------------
  // shutdownAll()
  // -----------------------------------------------------------------------

  describe('shutdownAll()', () => {
    it('shuts down all adapters and clears registry', async () => {
      const adapter1 = makeMockAdapter('s1');
      const adapter2 = makeMockAdapter('s2');

      await registry.register(adapter1, mockConfig('s1'));
      await registry.register(adapter2, mockConfig('s2'));
      expect(registry.size).toBe(2);

      await registry.shutdownAll();

      expect(registry.size).toBe(0);
      expect(registry.list()).toEqual([]);
      expect(registry.getForAction('block_ip')).toEqual([]);

      // Adapters should be shut down (no longer initialized)
      await expect(
        adapter1.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('not initialized');
      await expect(
        adapter2.execute('block_ip', {}, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('handles errors during shutdown gracefully', async () => {
      const adapter = makeMockAdapter('err-shutdown');
      await registry.register(adapter, mockConfig('err-shutdown'));

      // Monkey-patch shutdown to throw
      adapter.shutdown = async () => {
        throw new Error('Shutdown failed');
      };

      // Should not throw despite the error
      await expect(registry.shutdownAll()).resolves.not.toThrow();
      expect(registry.size).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // getAdapterRegistry() / resetAdapterRegistry()
  // -----------------------------------------------------------------------

  describe('getAdapterRegistry() / resetAdapterRegistry()', () => {
    it('returns a singleton instance', () => {
      const reg1 = getAdapterRegistry();
      const reg2 = getAdapterRegistry();
      expect(reg1).toBe(reg2);
    });

    it('reset clears the singleton so next call creates a new instance', () => {
      const reg1 = getAdapterRegistry();
      resetAdapterRegistry();
      const reg2 = getAdapterRegistry();

      expect(reg1).not.toBe(reg2);
    });

    it('returned singleton is an AdapterRegistry', () => {
      const reg = getAdapterRegistry();
      expect(reg).toBeInstanceOf(AdapterRegistry);
    });
  });
});
