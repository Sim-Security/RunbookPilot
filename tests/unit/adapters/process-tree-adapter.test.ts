/**
 * Unit tests for ProcessTreeAdapter
 *
 * Tests EDR data retrieval, process termination, and scan initiation
 * via mocked EDR APIs. All fetch calls are mocked via globalThis.fetch.
 *
 * @module tests/unit/adapters/process-tree-adapter
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ProcessTreeAdapter } from '../../../src/adapters/edr/process-tree-adapter.ts';
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
    name: 'edr-process-tree',
    type: 'edr',
    enabled: true,
    config: {
      base_url: 'https://api.crowdstrike.example.com',
      vendor: 'crowdstrike',
      ...overrides,
    },
    credentials: {
      type: 'api_key',
      credentials: { api_key: 'cs-key-abc' },
    },
    timeout: 30,
  };
}

function genericConfig(overrides: Record<string, unknown> = {}): AdapterConfig {
  return {
    name: 'edr-process-tree',
    type: 'edr',
    enabled: true,
    config: {
      base_url: 'https://edr.generic.example.com',
      vendor: 'generic',
      ...overrides,
    },
    credentials: {
      type: 'api_key',
      credentials: { api_key: 'gen-key-xyz' },
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

const sampleProcesses = [
  {
    pid: 1,
    name: 'systemd',
    parent_pid: 0,
    command_line: '/sbin/init',
    user: 'root',
    hash: 'aabbccdd',
    start_time: '2026-01-15T08:00:00Z',
  },
  {
    pid: 1234,
    name: 'bash',
    parent_pid: 1,
    command_line: '/bin/bash',
    user: 'analyst',
    hash: '11223344',
    start_time: '2026-02-10T10:30:00Z',
  },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ProcessTreeAdapter', () => {
  let adapter: ProcessTreeAdapter;

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  describe('Initialization', () => {
    it('stores base_url, api_key, and vendor from config', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      expect(adapter.name).toBe('edr-process-tree');
      expect(adapter.version).toBe('1.0.0');
      expect(adapter.supportedActions).toContain('retrieve_edr_data');
      expect(adapter.supportedActions).toContain('kill_process');
      expect(adapter.supportedActions).toContain('start_edr_scan');
    });

    it('accepts generic vendor', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());
      expect(adapter.name).toBe('edr-process-tree');
    });

    it('accepts wazuh vendor', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig({ vendor: 'wazuh' }));
      expect(adapter.name).toBe('edr-process-tree');
    });

    it('rejects unsupported vendor', async () => {
      adapter = new ProcessTreeAdapter();
      await expect(
        adapter.initialize(genericConfig({ vendor: 'invalid_vendor' })),
      ).rejects.toThrow('unsupported vendor');
    });

    it('throws if execute is called before initialize', async () => {
      adapter = new ProcessTreeAdapter();
      await expect(
        adapter.execute('retrieve_edr_data', { host_id: 'h1' }, 'production'),
      ).rejects.toThrow('not initialized');
    });
  });

  // -----------------------------------------------------------------------
  // execute() - simulation mode
  // -----------------------------------------------------------------------

  describe('execute() simulation mode', () => {
    beforeEach(async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('retrieve_edr_data returns simulated process tree', async () => {
      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'host-sim-01' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('retrieve_edr_data');
      expect(result.executor).toBe('edr-process-tree');

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.host).toBe('host-sim-01');
      expect(Array.isArray(output.process_tree)).toBe(true);

      const tree = output.process_tree as Array<Record<string, unknown>>;
      expect(tree.length).toBeGreaterThan(0);
      expect(tree[0]).toHaveProperty('pid');
      expect(tree[0]).toHaveProperty('name');
      expect(tree[0]).toHaveProperty('parent_pid');
      expect(tree[0]).toHaveProperty('command_line');

      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mode).toBe('simulation');
      expect(result.metadata!.vendor).toBe('crowdstrike');
    });

    it('kill_process returns simulated kill confirmation', async () => {
      const result = await adapter.execute(
        'kill_process',
        { host_id: 'host-sim-02', pid: 5678 },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('kill_process');

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.pid).toBe(5678);
      expect(output.killed).toBe(true);
      expect(output.message).toContain('5678');
    });

    it('start_edr_scan returns simulated scan initiation', async () => {
      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'host-sim-03', scan_type: 'full' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('start_edr_scan');

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.scan_type).toBe('full');
      expect(output.status).toBe('initiated');
      expect(typeof output.scan_id).toBe('string');
      expect((output.scan_id as string).startsWith('sim-scan-')).toBe(true);
    });

    it('start_edr_scan defaults to quick scan type', async () => {
      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'host-sim-04' },
        'simulation',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.scan_type).toBe('quick');
    });

    it('does not call fetch in simulation mode', async () => {
      await adapter.execute('retrieve_edr_data', { host_id: 'h1' }, 'simulation');
      await adapter.execute('kill_process', { host_id: 'h1', pid: 1 }, 'simulation');
      await adapter.execute('start_edr_scan', { host_id: 'h1' }, 'simulation');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // execute() - dry-run mode
  // -----------------------------------------------------------------------

  describe('execute() dry-run mode', () => {
    beforeEach(async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('retrieve_edr_data validates only', async () => {
      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'host-dry-01' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.action).toBe('retrieve_edr_data');
      expect(output.host).toBe('host-dry-01');
      expect(output.message).toContain('retrieve EDR process tree');

      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('kill_process validates only', async () => {
      const result = await adapter.execute(
        'kill_process',
        { host_id: 'host-dry-02', pid: 9999 },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.message).toContain('kill process');
      expect(output.message).toContain('9999');
    });

    it('start_edr_scan validates only', async () => {
      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'host-dry-03', scan_type: 'full' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.message).toContain('full');
      expect(output.message).toContain('EDR scan');
    });

    it('uses host param if host_id is not provided', async () => {
      const result = await adapter.execute(
        'retrieve_edr_data',
        { host: 'server-01' },
        'dry-run',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.host).toBe('server-01');
    });

    it('falls back to "unknown" when no host param', async () => {
      const result = await adapter.execute(
        'retrieve_edr_data',
        {},
        'dry-run',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.host).toBe('unknown');
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production mode: retrieve_edr_data
  // -----------------------------------------------------------------------

  describe('execute() production mode - retrieve_edr_data', () => {
    it('CrowdStrike: GETs process tree from correct URL', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: sampleProcesses }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'cs-host-01' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('retrieve_edr_data');

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('cs-host-01');
      expect(Array.isArray(output.process_tree)).toBe(true);
      expect((output.process_tree as unknown[]).length).toBe(2);

      expect(result.metadata).toBeDefined();
      expect(result.metadata!.mode).toBe('production');
      expect(result.metadata!.vendor).toBe('crowdstrike');
      expect(result.metadata!.status_code).toBe(200);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://api.crowdstrike.example.com/devices/entities/processes/v1?device_id=cs-host-01',
      );
      expect(options!.method).toBe('GET');

      const headers = options!.headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Bearer cs-key-abc');
    });

    it('CrowdStrike: includes pid filter in URL when provided', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: [sampleProcesses[1]] }),
      );

      await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'cs-host-02', pid: 1234 },
        'production',
      );

      const [url] = mockFetch.mock.calls[0]!;
      expect(String(url)).toContain('device_id=cs-host-02');
      expect(String(url)).toContain('pid=1234');
    });

    it('Generic: GETs from /api/processes endpoint', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ processes: sampleProcesses }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'gen-host-01' },
        'production',
      );

      expect(result.success).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://edr.generic.example.com/api/processes?host_id=gen-host-01',
      );
      expect(options!.method).toBe('GET');

      const headers = options!.headers as Record<string, string>;
      expect(headers['X-API-Key']).toBe('gen-key-xyz');
    });

    it('returns failure when API returns non-ok status', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Not Found', 404),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'cs-host-missing' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('API_ERROR');
      expect(result.error!.message).toContain('404');
      expect(result.error!.retryable).toBe(false);
    });

    it('resolves host by hostname lookup when host_id is not provided', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      // Lookup call
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: ['resolved-id-42'] }),
      );
      // Data retrieval call
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: sampleProcesses }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host: 'workstation-99' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('resolved-id-42');

      expect(mockFetch).toHaveBeenCalledTimes(2);

      const [lookupUrl, lookupOpts] = mockFetch.mock.calls[0]!;
      expect(lookupOpts!.method).toBe('GET');
      expect(String(lookupUrl)).toContain('/devices/queries/devices/v1');
      expect(String(lookupUrl)).toContain('workstation-99');
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production mode: kill_process
  // -----------------------------------------------------------------------

  describe('execute() production mode - kill_process', () => {
    it('CrowdStrike: POSTs kill command to RTR endpoint', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'killed', pid: 5678 }),
      );

      const result = await adapter.execute(
        'kill_process',
        { host_id: 'cs-host-kill', pid: 5678 },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('kill_process');

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('cs-host-kill');
      expect(output.pid).toBe(5678);
      expect(output.killed).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://api.crowdstrike.example.com/real-time-response/entities/command/v1',
      );
      expect(options!.method).toBe('POST');

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.device_id).toBe('cs-host-kill');
      expect(body.command_string).toBe('kill 5678');
      expect(body.base_command).toBe('kill');
    });

    it('Generic: POSTs to /api/processes/kill', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ status: 'killed' }),
      );

      const result = await adapter.execute(
        'kill_process',
        { host_id: 'gen-host-kill', pid: 4321 },
        'production',
      );

      expect(result.success).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://edr.generic.example.com/api/processes/kill',
      );

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.host_id).toBe('gen-host-kill');
      expect(body.pid).toBe(4321);
    });

    it('returns failure when kill API returns error', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Server Error', 500),
      );

      const result = await adapter.execute(
        'kill_process',
        { host_id: 'cs-host-err', pid: 1111 },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('API_ERROR');
      expect(result.error!.message).toContain('500');
      expect(result.error!.retryable).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production mode: start_edr_scan
  // -----------------------------------------------------------------------

  describe('execute() production mode - start_edr_scan', () => {
    it('CrowdStrike: POSTs to scanner endpoint', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ scan_id: 'scan-cs-001', status: 'initiated' }),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'cs-host-scan', scan_type: 'full' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('start_edr_scan');

      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('cs-host-scan');
      expect(output.scan_id).toBe('scan-cs-001');
      expect(output.scan_type).toBe('full');
      expect(output.status).toBe('initiated');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://api.crowdstrike.example.com/scanner/entities/scans/v1',
      );
      expect(options!.method).toBe('POST');

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.hosts).toEqual(['cs-host-scan']);
      expect(body.scan_type).toBe('full');
    });

    it('Generic: POSTs to /api/scans', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'scan-gen-001' }),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'gen-host-scan', scan_type: 'quick' },
        'production',
      );

      expect(result.success).toBe(true);

      const output = result.output as Record<string, unknown>;
      expect(output.scan_id).toBe('scan-gen-001');

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(
        'https://edr.generic.example.com/api/scans',
      );

      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.host_id).toBe('gen-host-scan');
      expect(body.scan_type).toBe('quick');
    });

    it('defaults scan_type to quick when not provided', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ scan_id: 'scan-default' }),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'cs-host-default' },
        'production',
      );

      expect(result.success).toBe(true);

      const output = result.output as Record<string, unknown>;
      expect(output.scan_type).toBe('quick');

      const [, options] = mockFetch.mock.calls[0]!;
      const body = JSON.parse(options!.body as string) as Record<string, unknown>;
      expect(body.scan_type).toBe('quick');
    });

    it('resolves host by hostname for start_edr_scan', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      // Lookup
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: ['resolved-scan-host'] }),
      );
      // Scan action
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ scan_id: 'scan-resolved' }),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host: 'server-scan.local' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('resolved-scan-host');

      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('returns failure when scan API returns error', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Forbidden', 403),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'cs-host-forbidden' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('API_ERROR');
      expect(result.error!.retryable).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // execute() - production failure (network)
  // -----------------------------------------------------------------------

  describe('execute() production failure - network', () => {
    beforeEach(async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('returns failure when fetch throws a network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'net-err-host' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain('ECONNREFUSED');
      expect(result.error!.retryable).toBe(true);
    });

    it('returns failure when host lookup fails for missing host', async () => {
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: [] }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host: 'nonexistent.local' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.message).toContain('Host not found');
    });

    it('returns failure when neither host nor host_id provided', async () => {
      const result = await adapter.execute(
        'retrieve_edr_data',
        {},
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('EXECUTION_ERROR');
      expect(result.error!.message).toContain("'host' or 'host_id' is required");
    });
  });

  // -----------------------------------------------------------------------
  // rollback()
  // -----------------------------------------------------------------------

  describe('rollback()', () => {
    beforeEach(async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    it('kill_process returns "cannot be fully rolled back" message', async () => {
      const result = await adapter.rollback(
        'kill_process',
        { host_id: 'h1', pid: 1234 },
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('ROLLBACK_NOT_POSSIBLE');
      expect(result.error!.message).toContain('cannot be fully rolled back');
      expect(result.error!.retryable).toBe(false);
    });

    it('retrieve_edr_data rollback is not supported', async () => {
      const result = await adapter.rollback(
        'retrieve_edr_data',
        { host_id: 'h1' },
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('ROLLBACK_NOT_SUPPORTED');
      expect(result.error!.message).toContain('does not support rollback');
    });

    it('start_edr_scan rollback is not supported', async () => {
      const result = await adapter.rollback(
        'start_edr_scan',
        { host_id: 'h1' },
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('ROLLBACK_NOT_SUPPORTED');
    });

    it('rollback does not call fetch', async () => {
      await adapter.rollback('kill_process', { host_id: 'h1', pid: 1 });
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // healthCheck()
  // -----------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy when API responds ok', async () => {
      adapter = new ProcessTreeAdapter();
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
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockTextResponse('Degraded', 503),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('degraded');
      expect(health.message).toContain('503');

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://edr.generic.example.com/health');
    });

    it('returns unhealthy when fetch throws', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockRejectedValueOnce(new Error('DNS resolution failed'));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('DNS resolution failed');
    });

    it('returns unknown when not initialized', async () => {
      adapter = new ProcessTreeAdapter();

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
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());
    });

    // retrieve_edr_data
    it('retrieve_edr_data: valid with host_id', async () => {
      const result = await adapter.validateParameters(
        'retrieve_edr_data',
        { host_id: 'abc' },
      );
      expect(result.valid).toBe(true);
    });

    it('retrieve_edr_data: valid with host', async () => {
      const result = await adapter.validateParameters(
        'retrieve_edr_data',
        { host: 'workstation-01' },
      );
      expect(result.valid).toBe(true);
    });

    it('retrieve_edr_data: invalid when no host or host_id', async () => {
      const result = await adapter.validateParameters(
        'retrieve_edr_data',
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('host_id');
    });

    // kill_process
    it('kill_process: valid with host_id and pid (number)', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { host_id: 'h1', pid: 1234 },
      );
      expect(result.valid).toBe(true);
    });

    it('kill_process: valid with host_id and pid (string)', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { host_id: 'h1', pid: '5678' },
      );
      expect(result.valid).toBe(true);
    });

    it('kill_process: invalid without host_id', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { pid: 1234 },
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes('host_id'))).toBe(true);
    });

    it('kill_process: invalid without pid', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { host_id: 'h1' },
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes('pid'))).toBe(true);
    });

    it('kill_process: invalid when pid is null', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { host_id: 'h1', pid: null },
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes('pid'))).toBe(true);
    });

    it('kill_process: invalid when pid is a boolean', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        { host_id: 'h1', pid: true },
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes('pid'))).toBe(true);
    });

    it('kill_process: invalid without both host_id and pid', async () => {
      const result = await adapter.validateParameters(
        'kill_process',
        {},
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.length).toBe(2);
    });

    // start_edr_scan
    it('start_edr_scan: valid with host_id', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        { host_id: 'h1' },
      );
      expect(result.valid).toBe(true);
    });

    it('start_edr_scan: valid with host', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        { host: 'ws-01' },
      );
      expect(result.valid).toBe(true);
    });

    it('start_edr_scan: valid with scan_type quick', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        { host_id: 'h1', scan_type: 'quick' },
      );
      expect(result.valid).toBe(true);
    });

    it('start_edr_scan: valid with scan_type full', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        { host_id: 'h1', scan_type: 'full' },
      );
      expect(result.valid).toBe(true);
    });

    it('start_edr_scan: invalid with bad scan_type', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        { host_id: 'h1', scan_type: 'deep' },
      );
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes('scan_type'))).toBe(true);
    });

    it('start_edr_scan: invalid without host or host_id', async () => {
      const result = await adapter.validateParameters(
        'start_edr_scan',
        {},
      );
      expect(result.valid).toBe(false);
    });

    // Unsupported action
    it('invalid for unsupported action', async () => {
      const result = await adapter.validateParameters(
        'block_ip' as never,
        { host_id: 'h1' },
      );
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain('Unsupported action');
    });
  });

  // -----------------------------------------------------------------------
  // getCapabilities()
  // -----------------------------------------------------------------------

  describe('getCapabilities()', () => {
    it('reports correct capabilities', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      const caps = adapter.getCapabilities();

      expect(caps.supportsRollback).toBe(false);
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(5);
      expect(caps.supportedActions).toContain('retrieve_edr_data');
      expect(caps.supportedActions).toContain('kill_process');
      expect(caps.supportedActions).toContain('start_edr_scan');
    });
  });

  // -----------------------------------------------------------------------
  // Edge cases
  // -----------------------------------------------------------------------

  describe('Edge cases', () => {
    it('strips trailing slashes from base_url', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig({ base_url: 'https://api.example.com///' }));

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ resources: sampleProcesses }),
      );

      await adapter.execute('retrieve_edr_data', { host_id: 'h1' }, 'production');

      const [url] = mockFetch.mock.calls[0]!;
      expect(String(url)).toContain('https://api.example.com/devices/');
      expect(String(url)).not.toContain('///');
    });

    it('throws for unsupported action in execute', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      await expect(
        adapter.execute('block_ip' as never, {}, 'production'),
      ).rejects.toThrow('does not support action');
    });

    it('generic host lookup falls back to body.id when host_id is absent', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      // Lookup returns { id: '...' } instead of { host_id: '...' }
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'fallback-id-77' }),
      );
      // Action
      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ processes: [] }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host: 'box-fallback' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.host_id).toBe('fallback-id-77');
    });

    it('generic host lookup throws when no host_id or id in response', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ other: 'data' }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host: 'mystery-host' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.message).toContain('Host not found');
    });

    it('scan_id falls back to response id field', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(crowdstrikeConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ id: 'alt-scan-id' }),
      );

      const result = await adapter.execute(
        'start_edr_scan',
        { host_id: 'h1' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.scan_id).toBe('alt-scan-id');
    });

    it('process tree data from response.data field is used', async () => {
      adapter = new ProcessTreeAdapter();
      await adapter.initialize(genericConfig());

      mockFetch.mockResolvedValueOnce(
        mockJsonResponse({ data: sampleProcesses }),
      );

      const result = await adapter.execute(
        'retrieve_edr_data',
        { host_id: 'data-field-host' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect((output.process_tree as unknown[]).length).toBe(2);
    });
  });
});
