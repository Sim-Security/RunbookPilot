/**
 * Unit tests for LogCollectionAdapter (SIEM)
 *
 * All HTTP calls go through globalThis.fetch, which is mocked via vi.fn().
 *
 * @module tests/unit/adapters/siem-adapter
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { LogCollectionAdapter } from '../../../src/adapters/siem/log-collection-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Fetch mock
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

const BASE_URL = 'http://es.local:9200';
const API_KEY = 'test-api-key-123';

function defaultConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return {
    name: 'siem-log-collection',
    type: 'siem',
    enabled: true,
    config: { base_url: BASE_URL },
    credentials: {
      type: 'api_key',
      credentials: { api_key: API_KEY },
    },
    timeout: 30,
    retry: { max_attempts: 3, backoff_ms: 1000, exponential: true },
    ...overrides,
  };
}

/** Build a minimal Elasticsearch-style search response. */
function esSearchResponse(
  hits: Array<Record<string, unknown>>,
  took = 5,
): Record<string, unknown> {
  return {
    took,
    timed_out: false,
    _shards: { total: 1, successful: 1, skipped: 0, failed: 0 },
    hits: {
      total: { value: hits.length, relation: 'eq' },
      max_score: 1.0,
      hits: hits.map((source, i) => ({
        _index: 'logs-2026.02.11',
        _id: `doc-${i}`,
        _score: 1.0,
        _source: source,
      })),
    },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function textResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/plain' },
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('LogCollectionAdapter', () => {
  let adapter: LogCollectionAdapter;

  beforeEach(async () => {
    adapter = new LogCollectionAdapter();
    await adapter.initialize(defaultConfig());
  });

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  describe('Initialization', () => {
    it('stores base_url and api_key from config', () => {
      expect(adapter.name).toBe('siem-log-collection');
      expect(adapter.version).toBe('1.0.0');
    });

    it('strips trailing slashes from base_url', async () => {
      const a = new LogCollectionAdapter();
      await a.initialize(
        defaultConfig({ config: { base_url: 'http://es.local:9200///' } }),
      );

      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([{ msg: 'ok' }])),
      );

      await a.execute('collect_logs', { query: '*' }, 'production');

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe('http://es.local:9200/logs-*/_search');
    });

    it('throws when executing before initialize()', async () => {
      const uninit = new LogCollectionAdapter();
      await expect(
        uninit.execute('collect_logs', { query: '*' }, 'production'),
      ).rejects.toThrow(/not initialized/i);
    });

    it('throws when action is unsupported', async () => {
      await expect(
        adapter.execute('block_ip' as never, {}, 'production'),
      ).rejects.toThrow(/does not support action/i);
    });
  });

  // -----------------------------------------------------------------------
  // Capabilities
  // -----------------------------------------------------------------------

  describe('getCapabilities()', () => {
    it('reports correct capabilities', () => {
      const caps = adapter.getCapabilities();
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsRollback).toBe(false);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(10);
      expect(caps.supportedActions).toContain('collect_logs');
      expect(caps.supportedActions).toContain('query_siem');
      expect(caps.supportedActions).toContain('collect_network_traffic');
      expect(caps.supportedActions).toContain('snapshot_memory');
      expect(caps.supportedActions).toContain('collect_file_metadata');
    });
  });

  // -----------------------------------------------------------------------
  // Simulation mode
  // -----------------------------------------------------------------------

  describe('execute() - simulation mode', () => {
    it('returns simulated log events for collect_logs', async () => {
      const result = await adapter.execute(
        'collect_logs',
        { query: 'event.action:login' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('collect_logs');
      expect(result.executor).toBe('siem-log-collection');
      expect(result.metadata).toEqual({ mode: 'simulation' });

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.event_count).toBe(25);
      expect(output.query_time_ms).toBe(42);
      expect(Array.isArray(output.events)).toBe(true);
      expect((output.events as unknown[]).length).toBe(5);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated log events for query_siem', async () => {
      const result = await adapter.execute(
        'query_siem',
        { query: 'process.name:powershell.exe' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('query_siem');
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.event_count).toBe(25);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated network events for collect_network_traffic', async () => {
      const result = await adapter.execute(
        'collect_network_traffic',
        { host: '10.0.0.50' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.event_count).toBe(10);
      const events = output.events as Array<Record<string, unknown>>;
      expect(events.length).toBe(3);
      expect(events[0]!['source.ip']).toBe('10.0.0.50');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated snapshot data for snapshot_memory', async () => {
      const result = await adapter.execute(
        'snapshot_memory',
        { host_id: 'ws-001' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.snapshot_id).toBe('sim-snap-001');
      expect(output.host).toBe('ws-001');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated file metadata for collect_file_metadata', async () => {
      const result = await adapter.execute(
        'collect_file_metadata',
        { path: '/usr/bin/suspicious' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.path).toBe('/usr/bin/suspicious');
      expect(output.size).toBe(4096);
      expect(output.owner).toBe('root');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('uses fallback host "unknown" when neither host_id nor host provided for snapshot_memory', async () => {
      const result = await adapter.execute(
        'snapshot_memory',
        {},
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host).toBe('unknown');
    });
  });

  // -----------------------------------------------------------------------
  // Dry-run mode
  // -----------------------------------------------------------------------

  describe('execute() - dry-run mode', () => {
    it('validates and returns dry-run result for collect_logs', async () => {
      const result = await adapter.execute(
        'collect_logs',
        { query: 'host.name:ws-001' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.params_valid).toBe(true);
      expect(output.action).toBe('collect_logs');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns validation error when query is missing for collect_logs', async () => {
      const result = await adapter.execute('collect_logs', {}, 'dry-run');

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'query' is required");
    });

    it('returns validation error when host/ip missing for collect_network_traffic', async () => {
      const result = await adapter.execute(
        'collect_network_traffic',
        {},
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'host' or 'ip' is required");
    });

    it('returns validation error when host/host_id missing for snapshot_memory', async () => {
      const result = await adapter.execute('snapshot_memory', {}, 'dry-run');

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'host_id' or 'host' is required");
    });

    it('returns validation error when path/hash missing for collect_file_metadata', async () => {
      const result = await adapter.execute(
        'collect_file_metadata',
        {},
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'path' or 'hash' is required");
    });

    it('passes dry-run validation for query_siem with valid params', async () => {
      const result = await adapter.execute(
        'query_siem',
        { query: 'event.category:process' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - collect_logs / query_siem
  // -----------------------------------------------------------------------

  describe('execute() - production mode (collect_logs / query_siem)', () => {
    const sampleHits = [
      { '@timestamp': '2026-02-11T10:00:00Z', message: 'login attempt' },
      { '@timestamp': '2026-02-11T10:01:00Z', message: 'login success' },
    ];

    it('sends POST to /${index}/_search for collect_logs', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse(sampleHits, 8)),
      );

      const result = await adapter.execute(
        'collect_logs',
        { query: 'event.action:login', index: 'auth-logs' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('collect_logs');

      const output = result.output as Record<string, unknown>;
      expect(output.event_count).toBe(2);
      expect(output.query_time_ms).toBe(8);
      expect(Array.isArray(output.events)).toBe(true);
      const events = output.events as Array<Record<string, unknown>>;
      expect(events[0]!.message).toBe('login attempt');

      // Verify fetch call
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(`${BASE_URL}/auth-logs/_search`);
      expect(init!.method).toBe('POST');
      expect(init!.headers).toEqual(
        expect.objectContaining({
          'Content-Type': 'application/json',
          'Authorization': `ApiKey ${API_KEY}`,
        }),
      );
    });

    it('uses default index "logs-*" when not specified', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse(sampleHits)),
      );

      await adapter.execute(
        'collect_logs',
        { query: 'host.name:ws-001' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/logs-*/_search`);
    });

    it('sends POST for query_siem the same way', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse(sampleHits)),
      );

      const result = await adapter.execute(
        'query_siem',
        { query: 'process.name:cmd.exe' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('includes time_range in the Elasticsearch DSL query', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([])),
      );

      await adapter.execute(
        'collect_logs',
        {
          query: '*',
          time_range: { from: '2026-02-10T00:00:00Z', to: '2026-02-11T00:00:00Z' },
        },
        'production',
      );

      const body = JSON.parse(String(mockFetch.mock.calls[0]![1]!.body)) as Record<string, unknown>;
      const boolMust = ((body.query as Record<string, unknown>).bool as Record<string, unknown>).must as unknown[];
      expect(boolMust.length).toBe(2);
      const rangeClause = boolMust[1] as Record<string, unknown>;
      expect(rangeClause).toHaveProperty('range');
    });

    it('respects custom limit parameter', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([])),
      );

      await adapter.execute(
        'collect_logs',
        { query: '*', limit: 50 },
        'production',
      );

      const body = JSON.parse(String(mockFetch.mock.calls[0]![1]!.body)) as Record<string, unknown>;
      expect(body.size).toBe(50);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - collect_network_traffic
  // -----------------------------------------------------------------------

  describe('execute() - production mode (collect_network_traffic)', () => {
    it('sends POST to /${index}/_search with network DSL query', async () => {
      const networkHits = [
        { 'source.ip': '10.0.0.50', 'destination.ip': '8.8.8.8' },
      ];

      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse(networkHits, 3)),
      );

      const result = await adapter.execute(
        'collect_network_traffic',
        { host: '10.0.0.50', index: 'network-logs' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.event_count).toBe(1);
      expect(output.query_time_ms).toBe(3);

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/network-logs/_search`);

      // Verify the DSL has bool/should matching source.ip, destination.ip, host.name
      const body = JSON.parse(String(mockFetch.mock.calls[0]![1]!.body)) as Record<string, unknown>;
      const boolMust = ((body.query as Record<string, unknown>).bool as Record<string, unknown>).must as unknown[];
      const innerBool = (boolMust[0] as Record<string, unknown>).bool as Record<string, unknown>;
      const should = innerBool.should as unknown[];
      expect(should.length).toBe(3);
    });

    it('uses default index "network-*" when not specified', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([])),
      );

      await adapter.execute(
        'collect_network_traffic',
        { ip: '192.168.1.10' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/network-*/_search`);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - snapshot_memory
  // -----------------------------------------------------------------------

  describe('execute() - production mode (snapshot_memory)', () => {
    it('sends POST to custom snapshot endpoint', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          snapshot_id: 'snap-9876',
          initiated_at: '2026-02-11T12:00:00Z',
        }),
      );

      const result = await adapter.execute(
        'snapshot_memory',
        { host_id: 'ws-005' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.snapshot_id).toBe('snap-9876');
      expect(output.host).toBe('ws-005');

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/_snapshot/memory/ws-005`);
      expect(mockFetch.mock.calls[0]![1]!.method).toBe('POST');
    });

    it('falls back to host param when host_id is absent', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ id: 'snap-fallback' }),
      );

      const result = await adapter.execute(
        'snapshot_memory',
        { host: 'srv-db-01' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.snapshot_id).toBe('snap-fallback');
      expect(output.host).toBe('srv-db-01');

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/_snapshot/memory/srv-db-01`);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - collect_file_metadata
  // -----------------------------------------------------------------------

  describe('execute() - production mode (collect_file_metadata)', () => {
    it('queries file metadata and returns found result', async () => {
      const fileHit = {
        file: {
          path: '/var/log/auth.log',
          hash: { sha256: 'deadbeef1234', sha1: 'abc', md5: '123' },
          size: 8192,
          mtime: '2026-02-10T18:00:00Z',
          owner: 'syslog',
        },
        '@timestamp': '2026-02-11T06:00:00Z',
      };

      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([fileHit])),
      );

      const result = await adapter.execute(
        'collect_file_metadata',
        { path: '/var/log/auth.log' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.found).toBe(true);
      expect(output.path).toBe('/var/log/auth.log');
      expect(output.hash).toBe('deadbeef1234');
      expect(output.size).toBe(8192);
      expect(output.modified_at).toBe('2026-02-10T18:00:00Z');
      expect(output.owner).toBe('syslog');

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/filebeat-*/_search`);
    });

    it('returns found=false when no hits', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([])),
      );

      const result = await adapter.execute(
        'collect_file_metadata',
        { hash: 'nonexistenthash' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.found).toBe(false);
      expect(output.message).toContain('No file metadata found');
    });

    it('uses custom index when specified', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(esSearchResponse([])),
      );

      await adapter.execute(
        'collect_file_metadata',
        { path: '/tmp/test', index: 'custom-files' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/custom-files/_search`);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - failure handling
  // -----------------------------------------------------------------------

  describe('execute() - production failure', () => {
    it('returns failure result on HTTP 500', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Internal Server Error', 500),
      );

      const result = await adapter.execute(
        'collect_logs',
        { query: '*' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('SIEM_QUERY_ERROR');
      expect(result.error!.message).toContain('HTTP 500');
      expect(result.error!.retryable).toBe(true);
    });

    it('returns failure result on HTTP 400 (not retryable)', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Bad Request: invalid query', 400),
      );

      const result = await adapter.execute(
        'query_siem',
        { query: 'invalid:::' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('SIEM_QUERY_ERROR');
      expect(result.error!.retryable).toBe(false);
    });

    it('handles network/fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const result = await adapter.execute(
        'collect_logs',
        { query: '*' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('SIEM_ERROR');
      expect(result.error!.message).toContain('ECONNREFUSED');
      expect(result.error!.retryable).toBe(true);
    });

    it('handles HTTP 500 for snapshot_memory', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('snapshot service unavailable', 500),
      );

      const result = await adapter.execute(
        'snapshot_memory',
        { host: 'ws-001' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('SNAPSHOT_ERROR');
      expect(result.error!.retryable).toBe(true);
    });

    it('handles HTTP 403 for collect_network_traffic (not retryable)', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Forbidden', 403),
      );

      const result = await adapter.execute(
        'collect_network_traffic',
        { host: '10.0.0.1' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('SIEM_QUERY_ERROR');
      expect(result.error!.retryable).toBe(false);
    });

    it('handles HTTP 500 for collect_file_metadata (retryable)', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Internal error', 500),
      );

      const result = await adapter.execute(
        'collect_file_metadata',
        { path: '/var/log/test' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('SIEM_QUERY_ERROR');
      expect(result.error!.retryable).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Health Check
  // -----------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy when cluster status is green', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ status: 'green', cluster_name: 'soc-cluster' }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('green');
      expect(health.latencyMs).toBeTypeOf('number');
      expect(health.checkedAt).toBeTruthy();

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/_cluster/health`);
      expect(mockFetch.mock.calls[0]![1]!.method).toBe('GET');
    });

    it('returns degraded when cluster status is yellow', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ status: 'yellow' }),
      );

      const health = await adapter.healthCheck();
      expect(health.status).toBe('degraded');
      expect(health.message).toContain('yellow');
    });

    it('returns unhealthy when cluster status is red', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ status: 'red' }),
      );

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('red');
    });

    it('returns unhealthy on HTTP error response', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Unauthorized', 401),
      );

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('HTTP 401');
    });

    it('returns unhealthy on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('ECONNREFUSED');
    });

    it('returns unknown when adapter is not initialized', async () => {
      const uninit = new LogCollectionAdapter();
      const health = await uninit.healthCheck();
      expect(health.status).toBe('unknown');
      expect(health.message).toContain('not initialized');
    });

    it('returns unknown when base_url is empty', async () => {
      const a = new LogCollectionAdapter();
      await a.initialize(defaultConfig({ config: { base_url: '' } }));

      const health = await a.healthCheck();
      expect(health.status).toBe('unknown');
    });

    it('includes Authorization header when api_key is set', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ status: 'green' }),
      );

      await adapter.healthCheck();

      const headers = mockFetch.mock.calls[0]![1]!.headers as Record<string, string>;
      expect(headers['Authorization']).toBe(`ApiKey ${API_KEY}`);
    });
  });

  // -----------------------------------------------------------------------
  // validateParameters()
  // -----------------------------------------------------------------------

  describe('validateParameters()', () => {
    it('requires query for collect_logs', async () => {
      const result = await adapter.validateParameters('collect_logs', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Parameter 'query' is required for collect_logs");
    });

    it('passes when query is provided for collect_logs', async () => {
      const result = await adapter.validateParameters('collect_logs', {
        query: 'host.name:ws-001',
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('requires query for query_siem', async () => {
      const result = await adapter.validateParameters('query_siem', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Parameter 'query' is required for query_siem");
    });

    it('requires host or ip for collect_network_traffic', async () => {
      const result = await adapter.validateParameters(
        'collect_network_traffic',
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("'host' or 'ip' is required");
    });

    it('passes when host is provided for collect_network_traffic', async () => {
      const result = await adapter.validateParameters(
        'collect_network_traffic',
        { host: '10.0.0.1' },
      );
      expect(result.valid).toBe(true);
    });

    it('passes when ip is provided for collect_network_traffic', async () => {
      const result = await adapter.validateParameters(
        'collect_network_traffic',
        { ip: '10.0.0.1' },
      );
      expect(result.valid).toBe(true);
    });

    it('requires host_id or host for snapshot_memory', async () => {
      const result = await adapter.validateParameters('snapshot_memory', {});
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("'host_id' or 'host' is required");
    });

    it('requires path or hash for collect_file_metadata', async () => {
      const result = await adapter.validateParameters(
        'collect_file_metadata',
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("'path' or 'hash' is required");
    });

    it('rejects unsupported actions', async () => {
      const result = await adapter.validateParameters('block_ip', {});
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('Unsupported action');
    });
  });

  // -----------------------------------------------------------------------
  // Rollback
  // -----------------------------------------------------------------------

  describe('rollback()', () => {
    it('returns not-supported result (read-only adapter)', async () => {
      const result = await adapter.rollback('collect_logs', {});
      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('ROLLBACK_NOT_SUPPORTED');
    });
  });
});
