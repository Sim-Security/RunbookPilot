import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  PlaybookSuggester,
  createSuggester,
  type SuggesterOptions,
  type PlaybookDescriptor,
} from '../../../src/llm/playbook-suggester.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const DEFAULT_OPTIONS: SuggesterOptions = {
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
};

const TEST_PLAYBOOKS: PlaybookDescriptor[] = [
  {
    id: 'pb-malware-001',
    name: 'Malware Containment',
    description: 'Isolate and contain malware outbreaks',
    techniques: ['T1059', 'T1204'],
  },
  {
    id: 'pb-phishing-001',
    name: 'Phishing Response',
    description: 'Respond to phishing campaigns',
    techniques: ['T1566'],
  },
  {
    id: 'pb-lateral-001',
    name: 'Lateral Movement Investigation',
    description: 'Investigate lateral movement activity',
    techniques: ['T1021', 'T1076'],
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a mock Response with a valid OpenRouter JSON suggestion body.
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

function mockErrorResponse(status: number, body: string): Partial<Response> {
  return {
    ok: false,
    status,
    text: async () => body,
    json: async () => { throw new Error('Not JSON'); },
  };
}

/**
 * Standard valid JSON suggestion the LLM would return.
 */
function validSuggestionsJson(): string {
  return JSON.stringify({
    suggestions: [
      {
        playbook_id: 'pb-malware-001',
        confidence: 0.92,
        justification: 'Malware alert matches containment playbook',
      },
      {
        playbook_id: 'pb-lateral-001',
        confidence: 0.45,
        justification: 'Possible lateral movement from internal IP',
      },
    ],
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PlaybookSuggester', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Success path ────────────────────────────────────────────────────────

  it('should return suggestions on successful LLM call', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(validSuggestionsJson()));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions).toBeDefined();
    expect(result.suggestions!.length).toBe(2);
    expect(result.suggestions![0]!.playbook_id).toBe('pb-malware-001');
    expect(result.suggestions![0]!.confidence).toBe(0.92);
    expect(result.suggestions![0]!.justification).toBe(
      'Malware alert matches containment playbook',
    );
    expect(result.error).toBeUndefined();
  });

  it('should sort suggestions by confidence descending', async () => {
    const json = JSON.stringify({
      suggestions: [
        { playbook_id: 'pb-lateral-001', confidence: 0.45, justification: 'Low' },
        { playbook_id: 'pb-malware-001', confidence: 0.92, justification: 'High' },
      ],
    });
    mockFetch.mockResolvedValueOnce(mockOkResponse(json));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions![0]!.playbook_id).toBe('pb-malware-001');
    expect(result.suggestions![1]!.playbook_id).toBe('pb-lateral-001');
  });

  it('should return empty suggestions when no playbooks are provided', async () => {
    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, []);

    expect(result.success).toBe(true);
    expect(result.suggestions).toEqual([]);
    // fetch should NOT be called when there are no playbooks
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // ── JSON wrapped in markdown fences ────────────────────────────────────

  it('should handle JSON wrapped in ```json code fences', async () => {
    const fenced = '```json\n' + validSuggestionsJson() + '\n```';
    mockFetch.mockResolvedValueOnce(mockOkResponse(fenced));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions).toBeDefined();
    expect(result.suggestions!.length).toBe(2);
  });

  it('should handle JSON wrapped in plain ``` code fences', async () => {
    const fenced = '```\n' + validSuggestionsJson() + '\n```';
    mockFetch.mockResolvedValueOnce(mockOkResponse(fenced));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions).toBeDefined();
    expect(result.suggestions!.length).toBe(2);
  });

  it('should extract JSON from surrounding text', async () => {
    const surrounded =
      'Here is my analysis:\n' + validSuggestionsJson() + '\nHope this helps!';
    mockFetch.mockResolvedValueOnce(mockOkResponse(surrounded));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions!.length).toBe(2);
  });

  // ── Malformed JSON ─────────────────────────────────────────────────────

  it('should handle completely malformed JSON response', async () => {
    mockFetch.mockResolvedValueOnce(
      mockOkResponse('This is not JSON at all, sorry!'),
    );

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toBe(
      'Failed to parse LLM response as valid suggestion JSON',
    );
  });

  it('should handle JSON missing "suggestions" key', async () => {
    mockFetch.mockResolvedValueOnce(
      mockOkResponse(JSON.stringify({ results: [] })),
    );

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toBe(
      'Failed to parse LLM response as valid suggestion JSON',
    );
  });

  // ── Suggestion validation ──────────────────────────────────────────────

  it('should filter out suggestions with unknown playbook IDs', async () => {
    const json = JSON.stringify({
      suggestions: [
        {
          playbook_id: 'pb-malware-001',
          confidence: 0.9,
          justification: 'Valid',
        },
        {
          playbook_id: 'pb-nonexistent-999',
          confidence: 0.8,
          justification: 'Invalid ID',
        },
      ],
    });
    mockFetch.mockResolvedValueOnce(mockOkResponse(json));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions!.length).toBe(1);
    expect(result.suggestions![0]!.playbook_id).toBe('pb-malware-001');
  });

  it('should clamp confidence scores to [0, 1]', async () => {
    const json = JSON.stringify({
      suggestions: [
        { playbook_id: 'pb-malware-001', confidence: 1.5, justification: 'High' },
        { playbook_id: 'pb-phishing-001', confidence: -0.2, justification: 'Low' },
      ],
    });
    mockFetch.mockResolvedValueOnce(mockOkResponse(json));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions![0]!.confidence).toBe(1);
    expect(result.suggestions![1]!.confidence).toBe(0);
  });

  it('should filter out suggestions with non-numeric confidence', async () => {
    const json = JSON.stringify({
      suggestions: [
        { playbook_id: 'pb-malware-001', confidence: 'high', justification: 'Bad confidence' },
        { playbook_id: 'pb-phishing-001', confidence: 0.7, justification: 'Good' },
      ],
    });
    mockFetch.mockResolvedValueOnce(mockOkResponse(json));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    // "high" cannot be parsed to a number, so it should be filtered out
    expect(result.suggestions!.length).toBe(1);
    expect(result.suggestions![0]!.playbook_id).toBe('pb-phishing-001');
  });

  it('should default justification when missing from suggestion', async () => {
    const json = JSON.stringify({
      suggestions: [
        { playbook_id: 'pb-malware-001', confidence: 0.85 },
      ],
    });
    mockFetch.mockResolvedValueOnce(mockOkResponse(json));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(true);
    expect(result.suggestions![0]!.justification).toBe('No justification provided');
  });

  // ── Empty LLM content ──────────────────────────────────────────────────

  it('should handle LLM returning empty content', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ choices: [] }),
    });

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  // ── HTTP errors ─────────────────────────────────────────────────────────

  it('should handle non-200 HTTP response', async () => {
    mockFetch.mockResolvedValueOnce(
      mockErrorResponse(503, 'Service Unavailable'),
    );

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM API returned HTTP 503: Service Unavailable');
  });

  // ── Network errors ─────────────────────────────────────────────────────

  it('should handle network errors gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ENOTFOUND'));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Playbook suggestion failed');
    expect(result.error).toContain('ENOTFOUND');
  });

  it('should handle fetch timeout via AbortController', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError');
    mockFetch.mockRejectedValueOnce(abortError);

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Playbook suggestion failed');
    expect(result.error).toContain('aborted');
  });

  // ── Duration tracking ──────────────────────────────────────────────────

  it('should record duration_ms', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(validSuggestionsJson()));

    const suggester = new PlaybookSuggester(DEFAULT_OPTIONS);
    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);

    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// createSuggester Factory
// ---------------------------------------------------------------------------

describe('createSuggester', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return a PlaybookSuggester instance', () => {
    const suggester = createSuggester({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 512,
    });

    expect(suggester).toBeInstanceOf(PlaybookSuggester);
  });

  it('should produce a working suggester that calls fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      mockOkResponse(validSuggestionsJson()),
    );
    vi.stubGlobal('fetch', mockFetch);

    const suggester = createSuggester({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 512,
    });

    const result = await suggester.suggest(TEST_ALERT, TEST_PLAYBOOKS);
    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
