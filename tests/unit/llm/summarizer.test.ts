import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  EnrichmentSummarizer,
  createSummarizer,
  type SummarizerOptions,
  type EnrichmentData,
} from '../../../src/llm/summarizer.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const DEFAULT_OPTIONS: SummarizerOptions = {
  baseUrl: 'https://openrouter.ai/api/v1',
  apiKey: 'test-api-key-123',
  model: 'openai/gpt-4o-mini',
  timeout: 5000,
  maxTokens: 512,
};

const TEST_ALERT: AlertEvent = {
  '@timestamp': '2026-02-11T10:00:00.000Z',
  event: {
    kind: 'alert',
    category: ['malware'],
    type: ['info'],
    severity: 80,
  },
  host: { hostname: 'workstation-42' },
  source: { ip: '10.0.0.50' },
  user: { name: 'jdoe' },
};

const TEST_ENRICHMENTS: EnrichmentData[] = [
  {
    source: 'virustotal',
    data: { malicious: 15, suspicious: 3, hash: 'abc123' },
  },
  {
    source: 'geoip',
    data: { country: 'US', city: 'New York' },
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a mock Response that mimics a successful OpenRouter chat completion.
 */
function mockOkResponse(content: string): Partial<Response> {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content } }],
    }),
    text: async () => JSON.stringify({ choices: [{ message: { content } }] }),
  };
}

/**
 * Build a mock Response that represents an HTTP error.
 */
function mockErrorResponse(status: number, body: string): Partial<Response> {
  return {
    ok: false,
    status,
    text: async () => body,
    json: async () => { throw new Error('Not JSON'); },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EnrichmentSummarizer', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Success path ────────────────────────────────────────────────────────

  it('should return a summary on successful LLM call', async () => {
    const llmText = 'The alert indicates malware on workstation-42.';
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.summary).toBe(llmText);
    expect(result.error).toBeUndefined();
  });

  it('should trim whitespace from the summary', async () => {
    const llmText = '  The alert indicates malware.  \n';
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.summary).toBe('The alert indicates malware.');
  });

  // ── Key findings extraction ─────────────────────────────────────────────

  it('should extract key findings from bullet points using "- " prefix', async () => {
    const llmText = [
      'Summary of the alert.',
      '- High VT detections (15 engines)',
      '- Source IP is internal',
      '- User jdoe has elevated privileges',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.key_findings).toEqual([
      'High VT detections (15 engines)',
      'Source IP is internal',
      'User jdoe has elevated privileges',
    ]);
  });

  it('should extract key findings from "* " bullet style', async () => {
    const llmText = [
      'Summary of the alert.',
      '* Finding one',
      '* Finding two',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.key_findings).toEqual(['Finding one', 'Finding two']);
  });

  it('should extract key findings from numbered items like "1. "', async () => {
    const llmText = [
      'Analysis complete.',
      '1. Malware detected',
      '2. Host is compromised',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.key_findings).toEqual([
      'Malware detected',
      'Host is compromised',
    ]);
  });

  it('should extract numbered items with ")" separator', async () => {
    const llmText = [
      'Summary line.',
      '1) First finding',
      '2) Second finding',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.key_findings).toEqual(['First finding', 'Second finding']);
  });

  it('should set key_findings to undefined when no bullets are present', async () => {
    const llmText = 'Simple summary with no bullet points at all.';
    mockFetch.mockResolvedValueOnce(mockOkResponse(llmText));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(true);
    expect(result.key_findings).toBeUndefined();
  });

  // ── Empty content ──────────────────────────────────────────────────────

  it('should handle LLM returning empty content (empty choices)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ choices: [] }),
    });

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  it('should handle LLM returning null message content', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{ message: { content: null } }],
      }),
    });

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  it('should handle LLM returning no message object at all', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{ finish_reason: 'stop' }],
      }),
    });

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  // ── HTTP errors ─────────────────────────────────────────────────────────

  it('should handle non-200 HTTP response gracefully', async () => {
    mockFetch.mockResolvedValueOnce(
      mockErrorResponse(429, 'Rate limit exceeded'),
    );

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM API returned HTTP 429: Rate limit exceeded');
  });

  it('should handle 500 server error', async () => {
    mockFetch.mockResolvedValueOnce(
      mockErrorResponse(500, 'Internal Server Error'),
    );

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('HTTP 500');
  });

  // ── Network / fetch errors ──────────────────────────────────────────────

  it('should handle network error gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Summarization failed');
    expect(result.error).toContain('ECONNREFUSED');
  });

  it('should handle fetch timeout via AbortController', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError');
    mockFetch.mockRejectedValueOnce(abortError);

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Summarization failed');
    expect(result.error).toContain('aborted');
  });

  // ── Invalid JSON ────────────────────────────────────────────────────────

  it('should handle invalid JSON response body', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => { throw new SyntaxError('Unexpected token'); },
    });

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Summarization failed');
  });

  // ── Duration tracking ──────────────────────────────────────────────────

  it('should record duration_ms on success', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse('Summary.'));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('should record duration_ms on failure', async () => {
    mockFetch.mockRejectedValueOnce(new Error('boom'));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(result.success).toBe(false);
    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  // ── Request format ──────────────────────────────────────────────────────

  it('should send correct headers and body to the LLM API', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse('Summary.'));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    expect(mockFetch).toHaveBeenCalledTimes(1);

    const [url, init] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers['Authorization']).toBe('Bearer test-api-key-123');

    const body = JSON.parse(init.body);
    expect(body.model).toBe('openai/gpt-4o-mini');
    expect(body.max_tokens).toBe(512);
    expect(body.messages).toHaveLength(2);
    expect(body.messages[0].role).toBe('system');
    expect(body.messages[1].role).toBe('user');
  });

  it('should strip trailing slashes from baseUrl', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse('Summary.'));

    const summarizer = new EnrichmentSummarizer({
      ...DEFAULT_OPTIONS,
      baseUrl: 'https://openrouter.ai/api/v1///',
    });
    await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    const [url] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
  });

  it('should pass an AbortController signal to fetch', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse('Summary.'));

    const summarizer = new EnrichmentSummarizer(DEFAULT_OPTIONS);
    await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);

    const [, init] = mockFetch.mock.calls[0]!;
    expect(init.signal).toBeDefined();
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });
});

// ---------------------------------------------------------------------------
// createSummarizer Factory
// ---------------------------------------------------------------------------

describe('createSummarizer', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return an EnrichmentSummarizer instance', () => {
    const summarizer = createSummarizer({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 512,
    });

    expect(summarizer).toBeInstanceOf(EnrichmentSummarizer);
  });

  it('should produce a working summarizer that calls fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      mockOkResponse('Factory summary.'),
    );
    vi.stubGlobal('fetch', mockFetch);

    const summarizer = createSummarizer({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 512,
    });

    const result = await summarizer.summarize(TEST_ALERT, TEST_ENRICHMENTS);
    expect(result.success).toBe(true);
    expect(result.summary).toBe('Factory summary.');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
