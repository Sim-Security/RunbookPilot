/**
 * Unit tests for IPBlockAdapter
 *
 * Tests firewall IP/domain blocking and unblocking across all execution modes
 * (production, simulation, dry-run). All fetch calls are mocked via globalThis.fetch.
 *
 * @module tests/unit/adapters/firewall-adapter
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { IPBlockAdapter } from '../../../src/adapters/firewall/ip-block-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof globalThis.fetch>();

beforeEach(() => {
  globalThis.fetch = mockFetch;
  mockFetch.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides?: Partial<AdapterConfig>): AdapterConfig {
  return {
    name: 'ip-block-adapter',
    type: 'firewall',
    enabled: true,
    config: {
      base_url: 'https://firewall.example.com',
    },
    credentials: {
      type: 'api_key',
      credentials: { api_key: 'test-api-key-1234' },
    },
    timeout: 30,
    ...overrides,
  };
}

function makeMinimalConfig(): AdapterConfig {
  return {
    name: 'ip-block-adapter',
    type: 'firewall',
    enabled: true,
    config: {},
  };
}

async function initAdapter(config?: AdapterConfig): Promise<IPBlockAdapter> {
  const adapter = new IPBlockAdapter();
  await adapter.initialize(config ?? makeConfig());
  return adapter;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('IPBlockAdapter', () => {
  // ---- Initialization ----------------------------------------------------

  describe('initialize()', () => {
    it('stores config values after initialization', async () => {
      const adapter = new IPBlockAdapter();
      const config = makeConfig();
      await adapter.initialize(config);

      // After initialization, the adapter should respond to healthCheck without
      // the "not initialized" message, proving it stored config properly.
      mockFetch.mockResolvedValueOnce(
        new Response('OK', { status: 200 }),
      );
      const health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');
      expect(health.message).toContain('Firewall API reachable');
    });

    it('sets name and version correctly', () => {
      const adapter = new IPBlockAdapter();
      expect(adapter.name).toBe('ip-block-adapter');
      expect(adapter.version).toBe('1.0.0');
    });

    it('defines all supported actions', () => {
      const adapter = new IPBlockAdapter();
      expect(adapter.supportedActions).toEqual([
        'block_ip',
        'unblock_ip',
        'block_domain',
        'unblock_domain',
      ]);
    });
  });

  // ---- Execution: simulation mode ----------------------------------------

  describe('execute() in simulation mode', () => {
    it('returns simulated success for block_ip without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(result.executor).toBe('ip-block-adapter');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('simulation');
      expect(output.simulated).toBe(true);
      expect(output.applied).toBe(false);
      expect(output.target).toBe('10.0.0.1');
      expect(output.rule_id).toMatch(/^sim-/);
    });

    it('returns simulated success for unblock_ip without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'unblock_ip',
        { ip: '192.168.1.100' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('unblock_ip');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('simulation');
      expect(output.target).toBe('192.168.1.100');
    });

    it('returns simulated success for block_domain without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'block_domain',
        { domain: 'malware.example.com' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_domain');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.target).toBe('malware.example.com');
      expect(output.simulated).toBe(true);
    });

    it('returns simulated success for unblock_domain without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'unblock_domain',
        { domain: 'safe.example.com' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('unblock_domain');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.target).toBe('safe.example.com');
    });
  });

  // ---- Execution: dry-run mode -------------------------------------------

  describe('execute() in dry-run mode', () => {
    it('validates params and returns success without calling fetch for block_ip', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('dry-run');
      expect(output.message).toContain('Dry-run validation passed');
    });

    it('validates params and returns success without calling fetch for block_domain', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'block_domain',
        { domain: 'example.com' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('dry-run');
    });

    it('returns validation error for missing ip in dry-run', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute('block_ip', {}, 'dry-run');

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VALIDATION_ERROR');
      expect(result.error?.message).toContain("requires a string 'ip' parameter");
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ---- Execution: production mode ----------------------------------------

  describe('execute() in production mode', () => {
    it('calls fetch with correct URL, method, and headers for block_ip', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, rule_id: 'fw-123', ip: '1.2.3.4' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.execute(
        'block_ip',
        { ip: '1.2.3.4' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/ip/block');
      expect((options as RequestInit).method).toBe('POST');
      expect((options as RequestInit).headers).toEqual({
        'Content-Type': 'application/json',
        Authorization: 'Bearer test-api-key-1234',
      });

      const body = JSON.parse((options as RequestInit).body as string) as Record<string, unknown>;
      expect(body.ip).toBe('1.2.3.4');
      expect(body.reason).toBe('RunbookPilot automated action');
      expect(body.duration).toBeNull();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('production');
      expect((output.response as Record<string, unknown>).rule_id).toBe('fw-123');
    });

    it('calls fetch with DELETE method for unblock_ip', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, ip: '10.0.0.5' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.execute(
        'unblock_ip',
        { ip: '10.0.0.5' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/ip/unblock');
      expect((options as RequestInit).method).toBe('DELETE');
    });

    it('calls fetch with correct URL for block_domain', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, domain: 'evil.com' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.execute(
        'block_domain',
        { domain: 'evil.com' },
        'production',
      );

      expect(result.success).toBe(true);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/domain/block');
      expect((options as RequestInit).method).toBe('POST');

      const body = JSON.parse((options as RequestInit).body as string) as Record<string, unknown>;
      expect(body.domain).toBe('evil.com');
    });

    it('calls fetch with DELETE method for unblock_domain', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, domain: 'safe.com' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.execute(
        'unblock_domain',
        { domain: 'safe.com' },
        'production',
      );

      expect(result.success).toBe(true);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/domain/unblock');
      expect((options as RequestInit).method).toBe('DELETE');
    });

    it('passes custom reason and duration in the request body', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      await adapter.execute(
        'block_ip',
        { ip: '8.8.8.8', reason: 'Known C2 server', duration: 3600 },
        'production',
      );

      const body = JSON.parse(
        (mockFetch.mock.calls[0]![1] as RequestInit).body as string,
      ) as Record<string, unknown>;
      expect(body.reason).toBe('Known C2 server');
      expect(body.duration).toBe(3600);
    });

    it('includes httpStatus in metadata on success', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ ok: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.metadata).toEqual({ mode: 'production', httpStatus: 200 });
    });

    it('fails when base_url is not configured', async () => {
      const adapter = await initAdapter(makeMinimalConfig());

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MISSING_CONFIG');
      expect(result.error?.message).toContain('base_url');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('fails when api_key credential is missing', async () => {
      const adapter = await initAdapter(
        makeConfig({ credentials: undefined }),
      );

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MISSING_CREDENTIALS');
      expect(result.error?.message).toContain('api_key');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ---- Execution: production failure -------------------------------------

  describe('execute() production failure', () => {
    it('returns API_ERROR for non-ok HTTP responses', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('Forbidden: invalid API key', { status: 403 }),
      );

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('API_ERROR');
      expect(result.error?.message).toContain('HTTP 403');
      expect(result.error?.message).toContain('Forbidden: invalid API key');
      expect(result.error?.retryable).toBe(false);
    });

    it('marks server errors (5xx) as retryable', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('Internal Server Error', { status: 500 }),
      );

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('API_ERROR');
      expect(result.error?.retryable).toBe(true);
    });

    it('returns NETWORK_ERROR when fetch throws', async () => {
      const adapter = await initAdapter();

      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NETWORK_ERROR');
      expect(result.error?.message).toContain('Connection refused');
      expect(result.error?.retryable).toBe(true);
    });

    it('returns NETWORK_ERROR with generic message for non-Error throws', async () => {
      const adapter = await initAdapter();

      mockFetch.mockRejectedValueOnce('some string error');

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NETWORK_ERROR');
      expect(result.error?.message).toContain('Unknown error');
    });
  });

  // ---- Rollback ----------------------------------------------------------

  describe('rollback()', () => {
    it('calls unblock_ip when rolling back block_ip', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, ip: '10.0.0.1' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.rollback('block_ip', { ip: '10.0.0.1' });

      expect(result.success).toBe(true);
      expect(result.action).toBe('unblock_ip');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/ip/unblock');
    });

    it('calls block_ip when rolling back unblock_ip', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true, ip: '10.0.0.1' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.rollback('unblock_ip', { ip: '10.0.0.1' });

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_ip');

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/ip/block');
    });

    it('calls unblock_domain when rolling back block_domain', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.rollback('block_domain', { domain: 'evil.com' });

      expect(result.success).toBe(true);
      expect(result.action).toBe('unblock_domain');

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/domain/unblock');
    });

    it('calls block_domain when rolling back unblock_domain', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response(
          JSON.stringify({ success: true }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        ),
      );

      const result = await adapter.rollback('unblock_domain', { domain: 'safe.com' });

      expect(result.success).toBe(true);
      expect(result.action).toBe('block_domain');

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/api/v1/rules/domain/block');
    });

    it('throws when adapter is not initialized', async () => {
      const adapter = new IPBlockAdapter();

      await expect(
        adapter.rollback('block_ip', { ip: '10.0.0.1' }),
      ).rejects.toThrow('not initialized');
    });
  });

  // ---- Health Check ------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy when firewall API responds with 200', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('OK', { status: 200 }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('Firewall API reachable');
      expect(health.message).toContain('200');
      expect(health.latencyMs).toBeDefined();
      expect(health.checkedAt).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://firewall.example.com/health');
      expect((options as RequestInit).method).toBe('GET');
    });

    it('returns degraded when firewall API returns non-ok status', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('Service Unavailable', { status: 503 }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('degraded');
      expect(health.message).toContain('503');
    });

    it('returns unhealthy when fetch throws', async () => {
      const adapter = await initAdapter();

      mockFetch.mockRejectedValueOnce(new Error('DNS lookup failed'));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('DNS lookup failed');
    });

    it('returns unknown when adapter is not initialized', async () => {
      const adapter = new IPBlockAdapter();

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unknown');
      expect(health.message).toBe('Adapter not initialized');
    });

    it('returns healthy when no base_url is configured', async () => {
      const adapter = await initAdapter(makeMinimalConfig());

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('simulation mode');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ---- Validate Parameters -----------------------------------------------

  describe('validateParameters()', () => {
    let adapter: IPBlockAdapter;

    beforeEach(async () => {
      adapter = await initAdapter();
    });

    it('validates block_ip with a valid IPv4 address', async () => {
      const result = await adapter.validateParameters('block_ip', { ip: '192.168.1.1' });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('validates block_ip with a valid IPv6 address', async () => {
      const result = await adapter.validateParameters('block_ip', {
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      });
      expect(result.valid).toBe(true);
    });

    it('validates block_ip with compressed IPv6 address', async () => {
      const result = await adapter.validateParameters('block_ip', { ip: '::1' });
      expect(result.valid).toBe(true);
    });

    it('rejects block_ip with missing ip parameter', async () => {
      const result = await adapter.validateParameters('block_ip', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors![0]).toContain("requires a string 'ip' parameter");
    });

    it('rejects block_ip with non-string ip parameter', async () => {
      const result = await adapter.validateParameters('block_ip', { ip: 12345 });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'ip' parameter");
    });

    it('rejects block_ip with invalid IP address format', async () => {
      const result = await adapter.validateParameters('block_ip', { ip: '999.999.999.999' });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('Invalid IP address');
    });

    it('rejects unblock_ip with invalid IP', async () => {
      const result = await adapter.validateParameters('unblock_ip', { ip: 'not-an-ip' });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('Invalid IP address');
    });

    it('validates block_domain with a valid domain', async () => {
      const result = await adapter.validateParameters('block_domain', {
        domain: 'malware.example.com',
      });
      expect(result.valid).toBe(true);
    });

    it('rejects block_domain with missing domain parameter', async () => {
      const result = await adapter.validateParameters('block_domain', {});
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'domain' parameter");
    });

    it('rejects unblock_domain with non-string domain', async () => {
      const result = await adapter.validateParameters('unblock_domain', { domain: 42 });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'domain' parameter");
    });
  });

  // ---- getCapabilities ---------------------------------------------------

  describe('getCapabilities()', () => {
    it('returns correct capabilities', () => {
      const adapter = new IPBlockAdapter();
      const caps = adapter.getCapabilities();

      expect(caps.supportedActions).toEqual([
        'block_ip',
        'unblock_ip',
        'block_domain',
        'unblock_domain',
      ]);
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsRollback).toBe(true);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(10);
    });
  });

  // ---- Edge Cases --------------------------------------------------------

  describe('edge cases', () => {
    it('throws when executing without initialization', async () => {
      const adapter = new IPBlockAdapter();

      await expect(
        adapter.execute('block_ip', { ip: '10.0.0.1' }, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('throws when action is not supported', async () => {
      const adapter = await initAdapter();

      await expect(
        adapter.execute('kill_process' as 'block_ip', {}, 'production'),
      ).rejects.toThrow('does not support action');
    });

    it('returns failure for unknown execution mode', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'block_ip',
        { ip: '10.0.0.1' },
        'unknown-mode' as 'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_MODE');
    });

    it('returns validation error before making any fetch call in production', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'block_ip',
        { ip: 'not-valid' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VALIDATION_ERROR');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });
});
