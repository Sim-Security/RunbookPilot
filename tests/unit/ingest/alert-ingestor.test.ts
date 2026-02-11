import { describe, it, expect, afterEach } from 'vitest';
import {
  validateAlertEvent,
  ingestFromString,
  ingestFromFile,
} from '../../../src/ingest/alert-ingestor.ts';
import { writeFile, unlink } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeValidAlertJson(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@timestamp': '2026-02-11T10:00:00.000Z',
    event: {
      kind: 'alert',
      category: ['malware'],
      type: ['info'],
      severity: 80,
    },
    ...overrides,
  };
}

function alertToString(alert: Record<string, unknown>): string {
  return JSON.stringify(alert);
}

// Temp file management
const tempFiles: string[] = [];

async function writeTempFile(content: string, filename?: string): Promise<string> {
  const name = filename ?? `alert-ingestor-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.json`;
  const filePath = join(tmpdir(), name);
  await writeFile(filePath, content, 'utf-8');
  tempFiles.push(filePath);
  return filePath;
}

afterEach(async () => {
  // Clean up temp files
  for (const fp of tempFiles) {
    try {
      await unlink(fp);
    } catch {
      // Ignore if already deleted
    }
  }
  tempFiles.length = 0;
});

// ---------------------------------------------------------------------------
// validateAlertEvent
// ---------------------------------------------------------------------------

describe('validateAlertEvent', () => {
  it('accepts a valid alert with @timestamp and event', () => {
    const result = validateAlertEvent(makeValidAlertJson());

    expect(result.valid).toBe(true);
    expect(result.alert).toBeDefined();
    expect(result.error).toBeUndefined();
  });

  it('accepts a minimal alert with only @timestamp and event object', () => {
    const result = validateAlertEvent({
      '@timestamp': '2026-01-01T00:00:00.000Z',
      event: { kind: 'alert' },
    });

    expect(result.valid).toBe(true);
  });

  it('rejects null input', () => {
    const result = validateAlertEvent(null);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('non-null object');
  });

  it('rejects undefined input', () => {
    const result = validateAlertEvent(undefined);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('non-null object');
  });

  it('rejects primitive input (string)', () => {
    const result = validateAlertEvent('not an object');

    expect(result.valid).toBe(false);
    expect(result.error).toContain('non-null object');
  });

  it('rejects primitive input (number)', () => {
    const result = validateAlertEvent(42);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('non-null object');
  });

  it('rejects missing @timestamp', () => {
    const result = validateAlertEvent({
      event: { kind: 'alert' },
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('@timestamp');
  });

  it('rejects non-string @timestamp', () => {
    const result = validateAlertEvent({
      '@timestamp': 12345,
      event: { kind: 'alert' },
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('@timestamp');
  });

  it('rejects empty @timestamp string', () => {
    const result = validateAlertEvent({
      '@timestamp': '   ',
      event: { kind: 'alert' },
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('must not be empty');
  });

  it('rejects missing event field', () => {
    const result = validateAlertEvent({
      '@timestamp': '2026-02-11T10:00:00.000Z',
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('event');
  });

  it('rejects null event field', () => {
    const result = validateAlertEvent({
      '@timestamp': '2026-02-11T10:00:00.000Z',
      event: null,
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('event');
  });

  it('rejects non-object event field', () => {
    const result = validateAlertEvent({
      '@timestamp': '2026-02-11T10:00:00.000Z',
      event: 'not an object',
    });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('event');
  });

  it('accepts alert with extra ECS fields', () => {
    const result = validateAlertEvent({
      '@timestamp': '2026-02-11T10:00:00.000Z',
      event: { kind: 'alert', category: ['malware'], type: ['info'], severity: 80 },
      host: { hostname: 'ws-001' },
      source: { ip: '10.0.0.1' },
      tags: ['sigma'],
    });

    expect(result.valid).toBe(true);
    expect(result.alert).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// ingestFromString - single JSON object
// ---------------------------------------------------------------------------

describe('ingestFromString - single JSON object', () => {
  it('parses a single valid alert JSON object', () => {
    const json = alertToString(makeValidAlertJson());
    const result = ingestFromString(json);

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(1);
    expect(result.errors).toHaveLength(0);
    expect(result.source).toBe('string');
    expect(result.total_parsed).toBe(1);
    expect(result.total_valid).toBe(1);
    expect(result.total_invalid).toBe(0);
  });

  it('parses single alert with whitespace padding', () => {
    const json = `  ${alertToString(makeValidAlertJson())}  `;
    const result = ingestFromString(json);

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// ingestFromString - JSON array
// ---------------------------------------------------------------------------

describe('ingestFromString - JSON array', () => {
  it('parses a JSON array of valid alerts', () => {
    const alerts = [
      makeValidAlertJson({ '@timestamp': '2026-01-01T00:00:00.000Z' }),
      makeValidAlertJson({ '@timestamp': '2026-01-02T00:00:00.000Z' }),
      makeValidAlertJson({ '@timestamp': '2026-01-03T00:00:00.000Z' }),
    ];
    const json = JSON.stringify(alerts);
    const result = ingestFromString(json);

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(3);
    expect(result.total_parsed).toBe(3);
    expect(result.total_valid).toBe(3);
  });

  it('parses empty JSON array', () => {
    const result = ingestFromString('[]');

    // No alerts but no errors either. success is false because no valid alerts
    expect(result.alerts).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    expect(result.total_parsed).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// ingestFromString - NDJSON
// ---------------------------------------------------------------------------

describe('ingestFromString - NDJSON', () => {
  it('parses NDJSON (newline-delimited JSON)', () => {
    const lines = [
      alertToString(makeValidAlertJson({ '@timestamp': '2026-01-01T00:00:00.000Z' })),
      alertToString(makeValidAlertJson({ '@timestamp': '2026-01-02T00:00:00.000Z' })),
    ].join('\n');

    const result = ingestFromString(lines);

    expect(result.alerts).toHaveLength(2);
    expect(result.total_valid).toBe(2);
  });

  it('skips empty lines in NDJSON', () => {
    const lines = [
      alertToString(makeValidAlertJson()),
      '',
      alertToString(makeValidAlertJson()),
      '',
    ].join('\n');

    const result = ingestFromString(lines);

    expect(result.alerts).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// ingestFromString - error handling
// ---------------------------------------------------------------------------

describe('ingestFromString - error handling', () => {
  it('returns error for completely invalid JSON', () => {
    const result = ingestFromString('this is not JSON');

    expect(result.success).toBe(false);
    expect(result.alerts).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error for empty string', () => {
    const result = ingestFromString('');

    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns error for whitespace-only string', () => {
    const result = ingestFromString('   ');

    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('captures validation errors for individual items in array', () => {
    const alerts = [
      makeValidAlertJson(),
      { noTimestamp: true, event: { kind: 'alert' } }, // invalid: missing @timestamp
    ];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.success).toBe(false); // because one is invalid
    expect(result.alerts).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
    expect(result.total_valid).toBe(1);
    expect(result.total_invalid).toBe(1);
    expect(result.errors[0]!.message).toContain('@timestamp');
  });

  it('handles mixed valid and invalid in NDJSON', () => {
    const lines = [
      alertToString(makeValidAlertJson()),
      'not valid json',
      alertToString(makeValidAlertJson()),
    ].join('\n');

    const result = ingestFromString(lines);

    expect(result.alerts).toHaveLength(2);
    expect(result.errors).toHaveLength(1);
    expect(result.total_valid).toBe(2);
    expect(result.total_invalid).toBe(1);
  });

  it('errors include index of the invalid item', () => {
    const alerts = [
      makeValidAlertJson(),
      { noTimestamp: true }, // invalid at index 1
      makeValidAlertJson(),
    ];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]!.index).toBe(1);
  });

  it('errors include raw preview for invalid items', () => {
    const alerts = [
      { bad: 'data', noTimestamp: true, event: { kind: 'alert' } },
    ];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]!.raw).toBeDefined();
    expect(result.errors[0]!.raw!.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// ingestFromFile
// ---------------------------------------------------------------------------

describe('ingestFromFile', () => {
  it('loads and parses a valid alert from a temp file', async () => {
    const alert = makeValidAlertJson();
    const filePath = await writeTempFile(JSON.stringify(alert));

    const result = await ingestFromFile(filePath);

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(1);
    expect(result.source).toBe('file');
    expect(result.source_path).toBe(filePath);
    expect(result.total_valid).toBe(1);
  });

  it('loads and parses an array of alerts from a temp file', async () => {
    const alerts = [
      makeValidAlertJson({ '@timestamp': '2026-01-01T00:00:00.000Z' }),
      makeValidAlertJson({ '@timestamp': '2026-01-02T00:00:00.000Z' }),
    ];
    const filePath = await writeTempFile(JSON.stringify(alerts));

    const result = await ingestFromFile(filePath);

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(2);
    expect(result.total_valid).toBe(2);
  });

  it('handles missing file gracefully', async () => {
    const result = await ingestFromFile('/nonexistent/path/to/alerts.json');

    expect(result.success).toBe(false);
    expect(result.alerts).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]!.message).toContain('not found');
    expect(result.source).toBe('file');
    expect(result.total_parsed).toBe(0);
  });

  it('handles file with invalid JSON gracefully', async () => {
    const filePath = await writeTempFile('this is not JSON');

    const result = await ingestFromFile(filePath);

    expect(result.success).toBe(false);
    expect(result.alerts).toHaveLength(0);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('handles file with mixed valid/invalid alerts', async () => {
    const alerts = [
      makeValidAlertJson(),
      { missing_timestamp: true, event: {} },
    ];
    const filePath = await writeTempFile(JSON.stringify(alerts));

    const result = await ingestFromFile(filePath);

    expect(result.success).toBe(false);
    expect(result.alerts).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
    expect(result.total_valid).toBe(1);
    expect(result.total_invalid).toBe(1);
  });

  it('handles empty file', async () => {
    const filePath = await writeTempFile('');

    const result = await ingestFromFile(filePath);

    expect(result.success).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('loads NDJSON from file', async () => {
    const ndjson = [
      alertToString(makeValidAlertJson({ '@timestamp': '2026-01-01T00:00:00.000Z' })),
      alertToString(makeValidAlertJson({ '@timestamp': '2026-01-02T00:00:00.000Z' })),
    ].join('\n');
    const filePath = await writeTempFile(ndjson);

    const result = await ingestFromFile(filePath);

    expect(result.alerts).toHaveLength(2);
    expect(result.total_valid).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// IngestResult structure
// ---------------------------------------------------------------------------

describe('IngestResult structure', () => {
  it('has correct source field for string ingestion', () => {
    const result = ingestFromString(alertToString(makeValidAlertJson()));
    expect(result.source).toBe('string');
  });

  it('has no source_path for string ingestion', () => {
    const result = ingestFromString(alertToString(makeValidAlertJson()));
    expect(result.source_path).toBeUndefined();
  });

  it('success is true only when all items are valid', () => {
    // All valid
    const allValid = ingestFromString(JSON.stringify([
      makeValidAlertJson(),
      makeValidAlertJson(),
    ]));
    expect(allValid.success).toBe(true);

    // Mixed
    const mixed = ingestFromString(JSON.stringify([
      makeValidAlertJson(),
      { bad: true },
    ]));
    expect(mixed.success).toBe(false);
  });

  it('total_parsed counts all items including invalid', () => {
    const alerts = [
      makeValidAlertJson(),
      { bad: true, event: { kind: 'alert' } },
      makeValidAlertJson(),
    ];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.total_parsed).toBe(3);
    expect(result.total_valid).toBe(2);
    expect(result.total_invalid).toBe(1);
  });
});
