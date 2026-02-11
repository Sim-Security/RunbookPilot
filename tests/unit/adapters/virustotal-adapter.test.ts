/**
 * Unit tests for VirusTotalAdapter
 *
 * All HTTP calls go through globalThis.fetch, which is mocked via vi.fn().
 * The calculate_hash action uses Node.js crypto locally and must NOT call fetch.
 *
 * @module tests/unit/adapters/virustotal-adapter
 */

import { createHash } from 'node:crypto';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { VirusTotalAdapter } from '../../../src/adapters/enrichment/virustotal-adapter.ts';
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

const BASE_URL = 'https://vt.test.local/api/v3';
const API_KEY = 'vt-test-key-abc123';

function defaultConfig(overrides: Partial<AdapterConfig> = {}): AdapterConfig {
  return {
    name: 'virustotal',
    type: 'enrichment',
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

/** Build a VT v3-style response for a file/domain/ip lookup. */
function vtAnalysisResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    data: {
      id: 'resource-id',
      type: 'file',
      attributes: {
        last_analysis_stats: {
          malicious: 10,
          undetected: 50,
          harmless: 5,
          suspicious: 2,
        },
        last_analysis_date: 1739260800, // 2025-02-11T00:00:00Z epoch
        reputation: -35,
        popular_threat_classification: {
          suggested_threat_label: 'trojan.agent/generic',
        },
        tags: ['trojan', 'windows'],
        ...overrides,
      },
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

describe('VirusTotalAdapter', () => {
  let adapter: VirusTotalAdapter;

  beforeEach(async () => {
    adapter = new VirusTotalAdapter();
    await adapter.initialize(defaultConfig());
    // Reset the rate limiter's internal clock so tests don't wait 15 s.
    // We access the private field via bracket notation for testing.
    (adapter as unknown as Record<string, unknown>)['lastRequestTime'] = 0;
  });

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  describe('Initialization', () => {
    it('stores base_url and api_key from config', () => {
      expect(adapter.name).toBe('virustotal');
      expect(adapter.version).toBe('1.0.0');
    });

    it('uses default VT base_url when not configured', async () => {
      const a = new VirusTotalAdapter();
      await a.initialize(
        defaultConfig({ config: {} }),
      );
      // The default should be the public VT API v3 URL.
      // Verify via a health check call.
      mockFetch.mockResolvedValueOnce(jsonResponse({}, 200));
      await a.healthCheck();

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe('https://www.virustotal.com/api/v3/metadata');
    });

    it('strips trailing slashes from base_url', async () => {
      const a = new VirusTotalAdapter();
      await a.initialize(
        defaultConfig({ config: { base_url: 'https://vt.local/api/v3///' } }),
      );
      (a as unknown as Record<string, unknown>)['lastRequestTime'] = 0;

      mockFetch.mockResolvedValueOnce(jsonResponse(vtAnalysisResponse()));

      await a.execute(
        'enrich_ioc',
        { ioc: 'abc123', ioc_type: 'hash' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toMatch(/^https:\/\/vt\.local\/api\/v3\/files\//);
      expect(calledUrl).not.toContain('///');
    });

    it('throws when executing before initialize()', async () => {
      const uninit = new VirusTotalAdapter();
      await expect(
        uninit.execute('enrich_ioc', { ioc: 'x', ioc_type: 'hash' }, 'production'),
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
      expect(caps.maxConcurrency).toBe(4);
      expect(caps.supportedActions).toContain('enrich_ioc');
      expect(caps.supportedActions).toContain('check_reputation');
      expect(caps.supportedActions).toContain('query_threat_feed');
      expect(caps.supportedActions).toContain('calculate_hash');
    });
  });

  // -----------------------------------------------------------------------
  // Simulation mode
  // -----------------------------------------------------------------------

  describe('execute() - simulation mode', () => {
    it('returns simulated enrichment for enrich_ioc', async () => {
      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'deadbeef', ioc_type: 'hash' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('enrich_ioc');
      expect(result.executor).toBe('virustotal');
      expect(result.metadata).toEqual({ mode: 'simulation' });

      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.ioc).toBe('deadbeef');
      expect(output.ioc_type).toBe('hash');
      expect(output.detections).toBe(12);
      expect(output.total_engines).toBe(70);
      expect(output.threat_label).toBe('trojan.generic/agent');
      expect(output.score).toBeCloseTo(12 / 70);
      expect(Array.isArray(output.tags)).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated reputation data for check_reputation', async () => {
      const result = await adapter.execute(
        'check_reputation',
        { ioc: 'evil.com', ioc_type: 'domain' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.reputation).toBe(-45);
      expect(output.malicious).toBe(12);
      expect(output.harmless).toBe(55);
      expect(output.suspicious).toBe(3);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns simulated threat feed for query_threat_feed', async () => {
      const result = await adapter.execute(
        'query_threat_feed',
        {},
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.simulated).toBe(true);
      expect(output.count).toBe(2);
      const notifications = output.notifications as Array<Record<string, unknown>>;
      expect(notifications.length).toBe(2);
      expect(notifications[0]!.rule_name).toBe('Cobalt Strike Beacon');
      expect(notifications[1]!.rule_name).toBe('Mimikatz Hash Match');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('actually computes a hash for calculate_hash even in simulation', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'hello world', algorithm: 'sha256' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      const expected = createHash('sha256').update('hello world').digest('hex');
      expect(output.hash).toBe(expected);
      expect(output.algorithm).toBe('sha256');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Dry-run mode
  // -----------------------------------------------------------------------

  describe('execute() - dry-run mode', () => {
    it('validates and returns dry-run result for enrich_ioc', async () => {
      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'abc123', ioc_type: 'hash' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
      expect(output.params_valid).toBe(true);
      expect(output.action).toBe('enrich_ioc');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns validation error when ioc is missing for enrich_ioc', async () => {
      const result = await adapter.execute(
        'enrich_ioc',
        { ioc_type: 'hash' },
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'ioc' is required");
    });

    it('returns validation error when ioc_type is missing for enrich_ioc', async () => {
      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'abc123' },
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'ioc_type' is required");
    });

    it('returns validation error when ioc_type is invalid', async () => {
      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'abc', ioc_type: 'banana' },
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("ioc_type 'banana'");
    });

    it('validates check_reputation params in dry-run', async () => {
      const result = await adapter.execute(
        'check_reputation',
        { ioc: '1.2.3.4', ioc_type: 'ip' },
        'dry-run',
      );
      expect(result.success).toBe(true);
    });

    it('returns validation error when data is missing for calculate_hash', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        {},
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("'data' is required");
    });

    it('returns validation error for invalid hash algorithm', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'test', algorithm: 'crc32' },
        'dry-run',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VALIDATION_ERROR');
      expect(result.error!.message).toContain("algorithm 'crc32'");
    });

    it('passes dry-run for query_threat_feed (no required params)', async () => {
      const result = await adapter.execute(
        'query_threat_feed',
        {},
        'dry-run',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.dry_run).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - enrich_ioc
  // -----------------------------------------------------------------------

  describe('execute() - production mode (enrich_ioc)', () => {
    it('sends GET to /files/{hash} for ioc_type=hash', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(vtAnalysisResponse()),
      );

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'deadbeef1234', ioc_type: 'hash' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.detections).toBe(10);
      expect(output.total_engines).toBe(67); // 10 + 50 + 5 + 2
      expect(output.threat_label).toBe('trojan.agent/generic');
      expect(output.score).toBeCloseTo(10 / 67);
      expect(Array.isArray(output.tags)).toBe(true);

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(String(url)).toBe(`${BASE_URL}/files/deadbeef1234`);
      expect(init!.method).toBe('GET');
      expect((init!.headers as Record<string, string>)['x-apikey']).toBe(API_KEY);
    });

    it('sends GET to /domains/{domain} for ioc_type=domain', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(vtAnalysisResponse()),
      );

      await adapter.execute(
        'enrich_ioc',
        { ioc: 'evil.example.com', ioc_type: 'domain' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/domains/evil.example.com`);
    });

    it('sends GET to /ip_addresses/{ip} for ioc_type=ip', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(vtAnalysisResponse()),
      );

      await adapter.execute(
        'enrich_ioc',
        { ioc: '203.0.113.50', ioc_type: 'ip' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/ip_addresses/203.0.113.50`);
    });

    it('sends GET to /urls/{base64url} for ioc_type=url', async () => {
      const targetUrl = 'https://evil.example.com/payload';
      const expectedUrlId = Buffer.from(targetUrl).toString('base64url');

      mockFetch.mockResolvedValueOnce(
        jsonResponse(vtAnalysisResponse()),
      );

      await adapter.execute(
        'enrich_ioc',
        { ioc: targetUrl, ioc_type: 'url' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/urls/${expectedUrlId}`);
    });

    it('returns threat_label "unknown" when classification is absent', async () => {
      const responseBody = vtAnalysisResponse();
      const attrs = ((responseBody.data as Record<string, unknown>).attributes as Record<string, unknown>);
      delete attrs.popular_threat_classification;

      mockFetch.mockResolvedValueOnce(jsonResponse(responseBody));

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'abc', ioc_type: 'hash' },
        'production',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.threat_label).toBe('unknown');
    });

    it('returns score 0 when total engines is 0', async () => {
      const responseBody = {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              undetected: 0,
              harmless: 0,
              suspicious: 0,
            },
            tags: [],
          },
        },
      };

      mockFetch.mockResolvedValueOnce(jsonResponse(responseBody));

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'clean-hash', ioc_type: 'hash' },
        'production',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.score).toBe(0);
      expect(output.total_engines).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - check_reputation
  // -----------------------------------------------------------------------

  describe('execute() - production mode (check_reputation)', () => {
    it('returns reputation data from VT response', async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(vtAnalysisResponse()),
      );

      const result = await adapter.execute(
        'check_reputation',
        { ioc: 'evil.com', ioc_type: 'domain' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.reputation).toBe(-35);
      expect(output.malicious).toBe(10);
      expect(output.harmless).toBe(5);
      expect(output.suspicious).toBe(2);
      expect(output.undetected).toBe(50);

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/domains/evil.com`);
    });

    it('defaults reputation fields to 0 when missing', async () => {
      const minimal = { data: { attributes: {} } };
      mockFetch.mockResolvedValueOnce(jsonResponse(minimal));

      const result = await adapter.execute(
        'check_reputation',
        { ioc: 'unknown.com', ioc_type: 'domain' },
        'production',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.reputation).toBe(0);
      expect(output.malicious).toBe(0);
      expect(output.harmless).toBe(0);
      expect(output.suspicious).toBe(0);
      expect(output.undetected).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - query_threat_feed
  // -----------------------------------------------------------------------

  describe('execute() - production mode (query_threat_feed)', () => {
    it('fetches hunting notifications without filter', async () => {
      const feedResponse = {
        data: [
          { id: 'notif-1', type: 'hunting_notification', attributes: { rule_name: 'rule-a' } },
          { id: 'notif-2', type: 'hunting_notification', attributes: { rule_name: 'rule-b' } },
        ],
      };

      mockFetch.mockResolvedValueOnce(jsonResponse(feedResponse));

      const result = await adapter.execute(
        'query_threat_feed',
        {},
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      expect(output.count).toBe(2);
      const notifications = output.notifications as Array<Record<string, unknown>>;
      expect(notifications[0]!.id).toBe('notif-1');
      expect(notifications[1]!.id).toBe('notif-2');

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/intelligence/hunting_notification_files`);
    });

    it('passes filter as query parameter', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: [] }));

      await adapter.execute(
        'query_threat_feed',
        { filter: 'tag:apt' },
        'production',
      );

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toContain('filter=tag%3Aapt');
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - calculate_hash
  // -----------------------------------------------------------------------

  describe('execute() - production mode (calculate_hash)', () => {
    it('computes sha256 hash locally without calling fetch', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'hello world' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      const expected = createHash('sha256').update('hello world').digest('hex');
      expect(output.hash).toBe(expected);
      expect(output.algorithm).toBe('sha256');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('computes md5 hash when algorithm=md5', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'test data', algorithm: 'md5' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      const expected = createHash('md5').update('test data').digest('hex');
      expect(output.hash).toBe(expected);
      expect(output.algorithm).toBe('md5');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('computes sha1 hash when algorithm=sha1', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'abc', algorithm: 'sha1' },
        'production',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      const expected = createHash('sha1').update('abc').digest('hex');
      expect(output.hash).toBe(expected);
      expect(output.algorithm).toBe('sha1');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('defaults to sha256 when algorithm is not specified', async () => {
      const result = await adapter.execute(
        'calculate_hash',
        { data: 'default algo' },
        'production',
      );

      const output = result.output as Record<string, unknown>;
      expect(output.algorithm).toBe('sha256');
    });
  });

  // -----------------------------------------------------------------------
  // Production mode - failure handling
  // -----------------------------------------------------------------------

  describe('execute() - production failure', () => {
    it('returns failure on HTTP 404 for enrich_ioc', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('NotFoundError', 404),
      );

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'unknown-hash', ioc_type: 'hash' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error!.code).toBe('VT_API_ERROR');
      expect(result.error!.message).toContain('HTTP 404');
      expect(result.error!.retryable).toBe(false);
    });

    it('returns retryable failure on HTTP 429 (rate limit)', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Rate limit exceeded', 429),
      );

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'hash-val', ioc_type: 'hash' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VT_API_ERROR');
      expect(result.error!.retryable).toBe(true);
    });

    it('returns failure on HTTP 404 for check_reputation', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Not found', 404),
      );

      const result = await adapter.execute(
        'check_reputation',
        { ioc: 'clean.example.com', ioc_type: 'domain' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VT_API_ERROR');
      expect(result.error!.message).toContain('HTTP 404');
    });

    it('returns failure on HTTP 500 for query_threat_feed', async () => {
      mockFetch.mockResolvedValueOnce(
        textResponse('Internal error', 500),
      );

      const result = await adapter.execute(
        'query_threat_feed',
        {},
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VT_API_ERROR');
      expect(result.error!.message).toContain('HTTP 500');
    });

    it('handles network/fetch errors gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ETIMEDOUT'));

      const result = await adapter.execute(
        'enrich_ioc',
        { ioc: 'hash123', ioc_type: 'hash' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('VT_ERROR');
      expect(result.error!.message).toContain('ETIMEDOUT');
      expect(result.error!.retryable).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Health Check
  // -----------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns healthy when /metadata returns 200', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ engines_count: 70 }));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toBe('VirusTotal API reachable');
      expect(health.latencyMs).toBeTypeOf('number');
      expect(health.checkedAt).toBeTruthy();

      const calledUrl = String(mockFetch.mock.calls[0]![0]);
      expect(calledUrl).toBe(`${BASE_URL}/metadata`);
      expect(mockFetch.mock.calls[0]![1]!.method).toBe('GET');
    });

    it('returns degraded on HTTP 429 (rate limit)', async () => {
      mockFetch.mockResolvedValueOnce(textResponse('Too many requests', 429));

      const health = await adapter.healthCheck();
      expect(health.status).toBe('degraded');
      expect(health.message).toContain('rate limit');
    });

    it('returns unhealthy on other HTTP errors', async () => {
      mockFetch.mockResolvedValueOnce(textResponse('Forbidden', 403));

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('HTTP 403');
    });

    it('returns unhealthy on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

      const health = await adapter.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('ECONNREFUSED');
    });

    it('returns unknown when adapter is not initialized', async () => {
      const uninit = new VirusTotalAdapter();
      const health = await uninit.healthCheck();
      expect(health.status).toBe('unknown');
      expect(health.message).toContain('not initialized');
    });

    it('returns unhealthy when api_key is empty', async () => {
      const a = new VirusTotalAdapter();
      await a.initialize(
        defaultConfig({
          credentials: { type: 'api_key', credentials: { api_key: '' } },
        }),
      );

      const health = await a.healthCheck();
      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('No API key');
    });

    it('includes x-apikey header in health check request', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({}));

      await adapter.healthCheck();

      const headers = mockFetch.mock.calls[0]![1]!.headers as Record<string, string>;
      expect(headers['x-apikey']).toBe(API_KEY);
    });
  });

  // -----------------------------------------------------------------------
  // validateParameters()
  // -----------------------------------------------------------------------

  describe('validateParameters()', () => {
    it('requires ioc and ioc_type for enrich_ioc', async () => {
      const result = await adapter.validateParameters('enrich_ioc', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Parameter 'ioc' is required for enrich_ioc");
      expect(result.errors).toContain("Parameter 'ioc_type' is required for enrich_ioc");
    });

    it('passes when ioc and ioc_type provided for enrich_ioc', async () => {
      const result = await adapter.validateParameters('enrich_ioc', {
        ioc: 'abc123',
        ioc_type: 'hash',
      });
      expect(result.valid).toBe(true);
    });

    it('rejects invalid ioc_type for enrich_ioc', async () => {
      const result = await adapter.validateParameters('enrich_ioc', {
        ioc: 'abc123',
        ioc_type: 'invalid',
      });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("Invalid ioc_type 'invalid'");
    });

    it('accepts all valid ioc_types: hash, domain, ip, url', async () => {
      for (const iocType of ['hash', 'domain', 'ip', 'url']) {
        const result = await adapter.validateParameters('enrich_ioc', {
          ioc: 'test',
          ioc_type: iocType,
        });
        expect(result.valid).toBe(true);
      }
    });

    it('requires ioc and ioc_type for check_reputation', async () => {
      const result = await adapter.validateParameters('check_reputation', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Parameter 'ioc' is required for check_reputation");
      expect(result.errors).toContain("Parameter 'ioc_type' is required for check_reputation");
    });

    it('rejects invalid ioc_type for check_reputation', async () => {
      const result = await adapter.validateParameters('check_reputation', {
        ioc: 'test',
        ioc_type: 'not_valid',
      });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("Invalid ioc_type 'not_valid'");
    });

    it('requires data for calculate_hash', async () => {
      const result = await adapter.validateParameters('calculate_hash', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Parameter 'data' is required for calculate_hash");
    });

    it('rejects invalid algorithm for calculate_hash', async () => {
      const result = await adapter.validateParameters('calculate_hash', {
        data: 'test',
        algorithm: 'crc32',
      });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("Invalid algorithm 'crc32'");
    });

    it('accepts valid algorithms: md5, sha1, sha256', async () => {
      for (const algorithm of ['md5', 'sha1', 'sha256']) {
        const result = await adapter.validateParameters('calculate_hash', {
          data: 'test',
          algorithm,
        });
        expect(result.valid).toBe(true);
      }
    });

    it('query_threat_feed has no required params', async () => {
      const result = await adapter.validateParameters('query_threat_feed', {});
      expect(result.valid).toBe(true);
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
      const result = await adapter.rollback('enrich_ioc', {});
      expect(result.success).toBe(false);
      expect(result.error!.code).toBe('ROLLBACK_NOT_SUPPORTED');
    });
  });
});
