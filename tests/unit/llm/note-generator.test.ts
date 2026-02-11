import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  InvestigationNoteGenerator,
  createNoteGenerator,
  type NoteGeneratorOptions,
} from '../../../src/llm/note-generator.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';
import type { ExecutionResult } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Test Fixtures
// ---------------------------------------------------------------------------

const DEFAULT_OPTIONS: NoteGeneratorOptions = {
  baseUrl: 'https://openrouter.ai/api/v1',
  apiKey: 'test-api-key-123',
  model: 'openai/gpt-4o-mini',
  timeout: 5000,
  maxTokens: 1024,
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
  process: { name: 'powershell.exe', command_line: 'powershell -enc ...' },
  threat: {
    framework: 'MITRE ATT&CK',
    technique: { id: ['T1059.001'], name: ['PowerShell'] },
  },
  tags: ['malware', 'endpoint'],
};

const TEST_EXECUTION_RESULT: ExecutionResult = {
  execution_id: 'exec-001',
  runbook_id: 'rb-malware-001',
  success: true,
  state: 'completed',
  started_at: '2026-02-11T10:00:00.000Z',
  completed_at: '2026-02-11T10:02:30.000Z',
  duration_ms: 150000,
  steps_executed: [
    {
      step_id: 'step-01',
      step_name: 'Collect Logs',
      action: 'collect_logs',
      success: true,
      started_at: '2026-02-11T10:00:01.000Z',
      completed_at: '2026-02-11T10:00:30.000Z',
      duration_ms: 29000,
    },
    {
      step_id: 'step-02',
      step_name: 'Isolate Host',
      action: 'isolate_host',
      success: true,
      started_at: '2026-02-11T10:00:31.000Z',
      completed_at: '2026-02-11T10:01:00.000Z',
      duration_ms: 29000,
    },
    {
      step_id: 'step-03',
      step_name: 'Enrich IOCs',
      action: 'enrich_ioc',
      success: false,
      started_at: '2026-02-11T10:01:01.000Z',
      completed_at: '2026-02-11T10:01:15.000Z',
      duration_ms: 14000,
      error: { code: 'ADAPTER_TIMEOUT', message: 'VT lookup timed out' },
      rolled_back: false,
    },
  ],
  metrics: {
    total_steps: 3,
    successful_steps: 2,
    failed_steps: 1,
    skipped_steps: 0,
    rollbacks_triggered: 0,
    duration_ms: 150000,
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
 * Well-structured markdown investigation notes matching the expected format.
 */
const GOOD_NOTES = [
  '## Timeline',
  '- 10:00:00 - Alert triggered for malware on workstation-42',
  '- 10:00:01 - Logs collected from endpoint',
  '- 10:00:31 - Host isolated from network',
  '- 10:01:01 - IOC enrichment attempted but failed (timeout)',
  '',
  '## Actions Taken',
  'The runbook collected endpoint logs and isolated the host from the network.',
  'IOC enrichment was attempted but failed due to a timeout.',
  '',
  '## Findings',
  'PowerShell-based malware detected on workstation-42. The host was',
  'successfully isolated. IOC enrichment could not be completed.',
  '',
  '## Recommendations',
  '- Retry IOC enrichment for the identified hash values',
  '- Review PowerShell execution logs for additional artifacts',
  '- Consider expanding isolation to peer hosts on the same subnet',
].join('\n');

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('InvestigationNoteGenerator', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ── Success path ────────────────────────────────────────────────────────

  it('should return notes on successful LLM call', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(true);
    expect(result.notes).toBeDefined();
    expect(result.notes).toContain('## Timeline');
    expect(result.notes).toContain('## Recommendations');
    expect(result.error).toBeUndefined();
  });

  it('should trim whitespace from notes', async () => {
    const padded = '\n  ' + GOOD_NOTES + '  \n';
    mockFetch.mockResolvedValueOnce(mockOkResponse(padded));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(true);
    expect(result.notes!.startsWith('##')).toBe(true);
    expect(result.notes!.endsWith('subnet')).toBe(true);
  });

  it('should pass enrichmentSummary to the LLM when provided', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    await generator.generate(
      TEST_ALERT,
      TEST_EXECUTION_RESULT,
      'VT shows 15/70 detections for hash abc123.',
    );

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [, init] = mockFetch.mock.calls[0]!;
    const body = JSON.parse(init.body);
    const userContent = body.messages[1].content;
    expect(userContent).toContain('Enrichment Summary');
    expect(userContent).toContain('VT shows 15/70 detections');
  });

  // ── Timeline extraction ─────────────────────────────────────────────────

  it('should extract timeline items from the "## Timeline" section', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.timeline).toBeDefined();
    expect(result.timeline!.length).toBe(4);
    expect(result.timeline![0]).toContain('Alert triggered');
    expect(result.timeline![3]).toContain('IOC enrichment attempted');
  });

  it('should handle numbered timeline items', async () => {
    const numberedTimeline = [
      '## Timeline',
      '1. Alert fired at 10:00',
      '2. Host isolated at 10:01',
      '',
      '## Actions Taken',
      'Host was isolated.',
      '',
      '## Findings',
      'Malware confirmed.',
      '',
      '## Recommendations',
      '- Monitor host',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(numberedTimeline));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.timeline).toBeDefined();
    expect(result.timeline!.length).toBe(2);
    expect(result.timeline![0]).toContain('Alert fired at 10:00');
    expect(result.timeline![1]).toContain('Host isolated at 10:01');
  });

  it('should set timeline to undefined when no Timeline section exists', async () => {
    const noTimeline = [
      '## Actions Taken',
      'Some actions.',
      '',
      '## Findings',
      'Some findings.',
      '',
      '## Recommendations',
      '- Do something',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(noTimeline));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(true);
    expect(result.timeline).toBeUndefined();
  });

  // ── Recommendations extraction ──────────────────────────────────────────

  it('should extract recommendations from the "## Recommendations" section', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.recommendations).toBeDefined();
    expect(result.recommendations!.length).toBe(3);
    expect(result.recommendations![0]).toContain('Retry IOC enrichment');
    expect(result.recommendations![2]).toContain('expanding isolation');
  });

  it('should set recommendations to undefined when no Recommendations section', async () => {
    const noRecs = [
      '## Timeline',
      '- Event 1',
      '',
      '## Actions Taken',
      'Stuff happened.',
      '',
      '## Findings',
      'We found things.',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(noRecs));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(true);
    expect(result.recommendations).toBeUndefined();
  });

  it('should handle ### heading level for section extraction', async () => {
    const h3Notes = [
      '### Timeline',
      '- Event A',
      '- Event B',
      '',
      '### Recommendations',
      '- Action 1',
    ].join('\n');
    mockFetch.mockResolvedValueOnce(mockOkResponse(h3Notes));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.timeline).toEqual(['Event A', 'Event B']);
    expect(result.recommendations).toEqual(['Action 1']);
  });

  // ── Empty LLM content ──────────────────────────────────────────────────

  it('should handle LLM returning empty content', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ choices: [] }),
    });

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  it('should handle LLM returning non-string content', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        choices: [{ message: { content: 12345 } }],
      }),
    });

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM response did not contain message content');
  });

  // ── HTTP errors ─────────────────────────────────────────────────────────

  it('should handle non-200 HTTP response gracefully', async () => {
    mockFetch.mockResolvedValueOnce(
      mockErrorResponse(401, 'Unauthorized'),
    );

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.error).toBe('LLM API returned HTTP 401: Unauthorized');
  });

  // ── Network / timeout errors ───────────────────────────────────────────

  it('should handle network errors gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('DNS resolution failed'));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Note generation failed');
    expect(result.error).toContain('DNS resolution failed');
  });

  it('should handle fetch timeout via AbortController', async () => {
    const abortError = new DOMException('The operation was aborted.', 'AbortError');
    mockFetch.mockRejectedValueOnce(abortError);

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.error).toContain('Note generation failed');
    expect(result.error).toContain('aborted');
  });

  // ── Duration tracking ──────────────────────────────────────────────────

  it('should record duration_ms on success', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  it('should record duration_ms on failure', async () => {
    mockFetch.mockRejectedValueOnce(new Error('boom'));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(result.success).toBe(false);
    expect(result.duration_ms).toBeTypeOf('number');
    expect(result.duration_ms).toBeGreaterThanOrEqual(0);
  });

  // ── Request format ──────────────────────────────────────────────────────

  it('should send correct request to the LLM API', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    expect(mockFetch).toHaveBeenCalledTimes(1);

    const [url, init] = mockFetch.mock.calls[0]!;
    expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
    expect(init.method).toBe('POST');
    expect(init.headers['Authorization']).toBe('Bearer test-api-key-123');

    const body = JSON.parse(init.body);
    expect(body.model).toBe('openai/gpt-4o-mini');
    expect(body.max_tokens).toBe(1024);
    expect(body.messages).toHaveLength(2);
    expect(body.messages[0].role).toBe('system');
    expect(body.messages[1].role).toBe('user');

    // User prompt should include alert and execution data
    const userContent = body.messages[1].content;
    expect(userContent).toContain('workstation-42');
    expect(userContent).toContain('exec-001');
    expect(userContent).toContain('rb-malware-001');
    expect(userContent).toContain('Collect Logs');
    expect(userContent).toContain('Isolate Host');
  });

  it('should include step error details in the user prompt', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse(GOOD_NOTES));

    const generator = new InvestigationNoteGenerator(DEFAULT_OPTIONS);
    await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);

    const [, init] = mockFetch.mock.calls[0]!;
    const body = JSON.parse(init.body);
    const userContent = body.messages[1].content;
    expect(userContent).toContain('ADAPTER_TIMEOUT');
    expect(userContent).toContain('VT lookup timed out');
  });
});

// ---------------------------------------------------------------------------
// createNoteGenerator Factory
// ---------------------------------------------------------------------------

describe('createNoteGenerator', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return an InvestigationNoteGenerator instance', () => {
    const generator = createNoteGenerator({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 1024,
    });

    expect(generator).toBeInstanceOf(InvestigationNoteGenerator);
  });

  it('should produce a working generator that calls fetch', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce(
      mockOkResponse(GOOD_NOTES),
    );
    vi.stubGlobal('fetch', mockFetch);

    const generator = createNoteGenerator({
      baseUrl: 'https://openrouter.ai/api/v1',
      apiKey: 'test-key',
      model: 'openai/gpt-4o-mini',
      timeout: 5000,
      maxTokens: 1024,
    });

    const result = await generator.generate(TEST_ALERT, TEST_EXECUTION_RESULT);
    expect(result.success).toBe(true);
    expect(result.notes).toContain('## Timeline');
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
