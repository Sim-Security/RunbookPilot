/**
 * Unit tests for HostIsolationAdapter
 *
 * Tests host isolation and connectivity restoration via mocked EDR APIs.
 * All fetch calls are mocked via globalThis.fetch.
 *
 * @module tests/unit/adapters/host-isolation-adapter
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HostIsolationAdapter } from '../../../src/adapters/edr/host-isolation-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Fetch Mock
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

function crowdstrikeConfig(overrides: Record<string, unknown> = {}): AdapterConfig {
  return {
    name: 'edr-host-isolation',
    type: 'edr',
    enabled: true,
    config: {
      base_url: 'https://api.crowdstrike.example.com',
      vendor: 'crowdstrike',
      ...overrides,
    },
    credentials: {
      type: 'api_key',
      credentials: { api_key: 'cs-test-key-123' },
    },
    timeout: 30,
  };
}

function genericConfig(overrides: Record<string, unknown> = {}): AdapterConfig {
  return {
    name: 'edr-host-isolation',
    type: 'edr',
    enabled: true,
    config: {
      base_url: 'https://edr.generic.example.com',
      vendor: 'generic',
      ...overrides,
    },
    credentials: {
      type: 'api_key',
      credentials: { api_key: 'generic-key-456' },
    },
    timeout: 30,
  };
}

function mockJsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: { 'Content-Type': 'application/json' },
  });
}

function mockTextResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    statusText: 'Error',
    headers: { 'Content-Type': 'text/plain' },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('HostIsolationAdapter', () => {
  let adapter: HostIsolationAdapter;

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  describe('Initialization', () => {
    it('stores base_url, api_key, and vendor from config', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      expect(adapter.name).toBe('edr-host-isolation');
      expect(adapter.version).toBe('1.0.0');
      expect(adapter.supportedActions).toContain('isolate_host');
      expect(adapter.supportedActions).toContain('restore_connectivity');
    });

    it('accepts generic vendor', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(genericConfig());

      expect(adapter.name).toBe('edr-host-isolation');
    });

    it('accepts wazuh vendor', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(genericConfig({ vendor: 'wazuh' }));

      expect(adapter.name).toBe('edr-host-isolation');
    });

    it('rejects unsupported vendor', async () => {
      adapter = new HostIsolationAdapter();
      await expect(
        adapter.initialize(genericConfig({ vendor: 'unsupported_vendor' })),
      ).rejects.toThrow('unsupported vendor');
    });

    it('throws if execute is called before initialize', async () => {
      adapter = new HostIsolationAdapter();
      await expect(
        adapter.execute('isolate_host', { host_id: 'h1' }, 'production'),
      ).rejects.toThrow('not initialized');
    });
  });

  // -----------------------------------------------------------------------
  // execute() - simulation mode
  // -----------------------------------------------------------------------

  describe('execute() simulation mode', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('isolate_host returns simulated success', async () => {
      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'host-abc-123' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('isolate_host');
      expect(result.executor).toBe('edr-host-isolation');
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.action).toBe('isolate_host');
      expect(output.host).toBe('host-abc-123');
      expect(output.status).toBe('contained');
      expect(typeof output.isolation_id).toBe('string');
      expect((output.isolation_id as string).startsWith('sim-iso-')).toBe(true);

      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mode).toBe('simulation');
      expect(result.metadata!.vendor).toBe('crowdstrike');
    });

    it('restore_connectivity returns simulated success', async () => {
      const result = await adapter.execute(
        'restore_connectivity',
        { host: 'workstation-01' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('restore_connectivity');

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.status).toBe('lifted');
      expect(output.host).toBe('workstation-01');
    });

    it('does not call fetch in simulation mode', async () => {
      await adapter.execute('isolate_host', { host_id: 'h1' }, 'simulation');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // execute() - dry-run mode
  // -----------------------------------------------------------------------

  describe('execute() dry-run mode', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('validates only, does not call fetch', async () => {
      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'host-dry-run' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('isolate_host');

      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.action).toBe('isolate_host');
      expect(output.host).toBe('host-dry-run');
      expect(output.message).toContain('isolate');

      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('restore_connectivity dry-run uses host param', async () => {
      const result = await adapter.execute(
        'restore_connectivity',
        { host: 'server-42' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.host).toBe('server-42');
      expect(output.message).toContain('restore connectivity');
    });

    it('dry-run falls back to "unknown" when no host param', async () => {
      const result = await adapter.execute(
        'isolate_host',
        {},
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host).toBe('unknown');
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production mode (CrowdStrike)
  // -----------------------------------------------------------------------

  describe('execute() production mode - CrowdStrike', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('isolate_host POSTs contain action to correct CrowdStrike URL', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'action-001', status: 'contained' }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'cs-host-abc' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('isolate_host');

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('cs-host-abc');
      expect(output.status).toBe('contained');
      expect(output.api_response).toEqual({ id: 'action-001', status: 'contained' });

      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mode).toBe('production');
      expect(result.metadata!.vendor).toBe('crowdstrike');
      expect(result.metadata!.status_code).toBe(200);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        'https://api.crowdstrike.example.com/devices/entities/devices-actions/v2',
      );
      expect(options!.method).toBe('POST');

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.action_name).toBe('contain');
      expect(body.ids).toEqual(['cs-host-abc']);

      const headers = options!.headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer cs-test-key-123');
      expect(headers['Content-Type']).toBe('application/json');
    });

    it('restore_connectivity POSTs lift_containment action', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'action-002', status: 'lifted' }),
      );

      const result = await adapter.execute(
        'restore_connectivity',
        { host_id: 'cs-host-def' },
        'production',
      );

      expect(result.success).toBe(true);

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('cs-host-def');
      expect(output.status).toBe('lifted');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.action_name).toBe('lift_containment');
      expect(body.ids).toEqual(['cs-host-def']);
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production mode (Generic)
  // -----------------------------------------------------------------------

  describe('execute() production mode - Generic', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(genericConfig());
    });

    it('isolate_host POSTs to /api/isolate for generic vendor', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'isolated' }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'gen-host-01' },
        'production',
      );

      expect(result.success).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://edr.generic.example.com/api/isolate');
      expect(options!.method).toBe('POST');

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.host_id).toBe('gen-host-01');

      const headers = options!.headers as Record<string, string>;
      expect(headers['X-API-Key']).toBe('generic-key-456');
    });

    it('restore_connectivity POSTs to /api/unisolate for generic vendor', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'restored' }),
      );

      const result = await adapter.execute(
        'restore_connectivity',
        { host_id: 'gen-host-02' },
        'production',
      );

      expect(result.success).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://edr.generic.example.com/api/unisolate');
    });
  });

  // -----------------------------------------------------------------------
  // Host ID Resolution
  // -----------------------------------------------------------------------

  describe('Host ID resolution', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('looks up host_id by hostname when only host param is provided', async () => {
      // First call: host lookup returns a resource ID
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: ['resolved-host-id-999'] }),
      );
      // Second call: the actual isolation action
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'action-003', status: 'contained' }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host: 'workstation-42.corp.local' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('resolved-host-id-999');

      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Verify first call is a GET lookup
      const [lookupUrl, lookupOpts] = mockFetch.mock.calls[0]!;
      expect(lookupOpts!.method).toBe('GET');
      expect(String(lookupUrl)).toContain('/devices/queries/devices/v1');
      expect(String(lookupUrl)).toContain('workstation-42.corp.local');

      // Verify second call is the POST action
      const [, actionOpts] = mockFetch.mock.calls[1]!;
      expect(actionOpts!.method).toBe('POST');
      const body = JSON.parse(actionOpts!.body as string) as Record<string, unknown>;
      expect(body.ids).toEqual(['resolved-host-id-999']);
    });

    it('generic vendor looks up host_id via /api/hosts endpoint', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(genericConfig());

      // Lookup
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ host_id: 'gen-resolved-42' }),
      );
      // Action
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'isolated' }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host: 'server-01' },
        'production',
      );

      expect(result.success).toBe(true);

      const [lookupUrl] = mockFetch.mock.calls[0]!;
      expect(String(lookupUrl)).toContain('/api/hosts?hostname=server-01');
    });

    it('skips lookup when host_id is provided directly', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'contained' }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'direct-id', host: 'some-hostname' },
        'production',
      );

      expect(result.success).toBe(true);
      // Only one fetch call (the action), no lookup
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('direct-id');
    });

    it('throws when host lookup returns empty resources for CrowdStrike', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: [] }),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host: 'nonexistent-host' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain('Host not found');
    });

    it('throws when host lookup returns non-ok response', async () => {
      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Unauthorized', 401),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host: 'some-host' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain('Host lookup failed');
      expect(result.error!.message).toContain('401');
    });

    it('throws when neither host nor host_id is provided in production', async () => {
      const result = await adapter.execute(
        'isolate_host',
        {},
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain("'host' or 'host_id' is required");
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production failure
  // -----------------------------------------------------------------------

  describe('execute() production failure', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('returns failure when API returns non-ok status', async () => {
      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Internal Server Error', 500),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'host-fail-01' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('API_ERROR');
      expect(result.error!.message).toContain('500');
      expect(result.error!.message).toContain('Internal Server Error');
      expect(result.error!.retryable).toBe(true);
    });

    it('returns non-retryable failure for 4xx errors', async () => {
      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Forbidden', 403),
      );

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'host-fail-02' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('API_ERROR');
      expect(result.error!.retryable).toBe(false);
    });

    it('returns failure when fetch throws a network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network unreachable'));

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'host-net-err' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain('Network unreachable');
      expect(result.error!.retryable).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // rollback()
  // -----------------------------------------------------------------------

  describe('rollback()', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('isolate_host rolls back to restore_connectivity', async () => {
      // The rollback calls execute('restore_connectivity', ..., 'production')
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'rollback-001', status: 'lifted' }),
      );

      const result = await adapter.rollback(
        'isolate_host',
        { host_id: 'host-rollback-01' },
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('restore_connectivity');

      const output = result.output as Record<string, unknown>;
      expect(output.status).toBe('lifted');

      // Verify the API call used lift_containment
      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.action_name).toBe('lift_containment');
    });

    it('restore_connectivity rolls back to isolate_host', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'rollback-002', status: 'contained' }),
      );

      const result = await adapter.rollback(
        'restore_connectivity',
        { host_id: 'host-rollback-02' },
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('isolate_host');

      const output = result.output as Record<string, unknown>;
      expect(output.status).toBe('contained');

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.action_name).toBe('contain');
    });

    it('throws for unsupported rollback action', async () => {
      await expect(
        adapter.rollback('block_ip' as never, {}),
      ).rejects.toThrow('No reverse action defined');
    });
  });

  // -----------------------------------------------------------------------
  // healthCheck()
  // -----------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy when API responds ok', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(mockJsonResponse({ status: 'ok' }));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toBe('EDR API reachable');
      expect(health.latencyMs).toBeGreaterThanOrEqual(0);
      expect(health.checkedAt).toBeDefined();

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://api.crowdstrike.example.com/health');
    });

    it('returns degraded when API returns non-ok status', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Service degraded', 503),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('degraded');
      expect(health.message).toContain('503');
    });

    it('returns unhealthy when fetch throws', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockRejectedValueOnce(new Error('Connection refused'));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('Connection refused');
    });

    it('returns unknown when not initialized', async () => {
      adapter = new HostIsolationAdapter();

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unknown');
      expect(health.message).toBe('Adapter not initialized');
    });
  });

  // -----------------------------------------------------------------------
  // validateParameters()
  // -----------------------------------------------------------------------

  describe('validateParameters()', () => {
    beforeEach(async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('valid when host param is provided', async () => {
      const result = await adapter.validateParameters(
        'isolate_host',
        { host: 'workstation-01' },
      );
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('valid when host_id param is provided', async () => {
      const result = await adapter.validateParameters(
        'restore_connectivity',
        { host_id: 'abc-123' },
      );
      expect(result.valid).toBe(true);
    });

    it('invalid when neither host nor host_id is provided', async () => {
      const result = await adapter.validateParameters(
        'isolate_host',
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBeGreaterThan(0);
      expect(result.errors![0]).toContain('host');
    });

    it('invalid for unsupported action', async () => {
      const result = await adapter.validateParameters(
        'block_ip' as never,
        { host: 'h1' },
      );
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('Unsupported action');
    });

    it('invalid when host is empty string', async () => {
      const result = await adapter.validateParameters(
        'isolate_host',
        { host: '' },
      );
      expect(result.valid).toBe(false);
    });

    it('invalid when host_id is empty string', async () => {
      const result = await adapter.validateParameters(
        'isolate_host',
        { host_id: '' },
      );
      expect(result.valid).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // getCapabilities()
  // -----------------------------------------------------------------------

  describe('getCapabilities()', () => {
    it('reports correct capabilities', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      const caps = adapter.getCapabilities();

      expect(caps.supportsRollback).toBe(true);
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(5);
      expect(caps.supportedActions).toContain('isolate_host');
      expect(caps.supportedActions).toContain('restore_connectivity');
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  describe('Edge cases', () => {
    it('strips trailing slashes from base_url', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig({ base_url: 'https://api.example.com///' }));

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'contained' }),
      );

      await adapter.execute('isolate_host', { host_id: 'h1' }, 'production');

      const [url] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://api.example.com/devices/entities/devices-actions/v2',
      );
    });

    it('handles json parse failure on successful response gracefully', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      // Return a response whose .json() will fail, falling back to {}
      const badJsonResponse = new Response('not json', {
        status: 200,
        statusText: 'OK',
      });

      mockFetch.mockResolvedValueOnce(badJsonResponse);

      const result = await adapter.execute(
        'isolate_host',
        { host_id: 'h1' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.api_response).toEqual({});
    });

    it('throws for unsupported action in execute', async () => {
      adapter = new HostIsolationAdapter();
      await adapter.initialize(crowdstrikeConfig());

      await expect(
        adapter.execute('block_ip' as never, {}, 'production'),
      ).rejects.toThrow('does not support action');
    });
  });
});
