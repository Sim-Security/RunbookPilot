/**
 * Alert Ingestor for RunbookPilot
 *
 * Supports loading ECS-normalized alert events from:
 * - JSON files (single object or array)
 * - STDIN (JSON or NDJSON)
 * - Raw strings (JSON or NDJSON)
 *
 * Validation is lenient: alerts must have `@timestamp` and an `event` object
 * at minimum. Partial ECS fields are accepted.
 *
 * @module ingest/alert-ingestor
 */

import { readFile } from 'fs/promises';
import { logger } from '../logging/logger.ts';
import type { AlertEvent } from '../types/ecs.ts';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface IngestResult {
  success: boolean;
  alerts: AlertEvent[];
  errors: IngestError[];
  source: 'file' | 'stdin' | 'string';
  source_path?: string;
  total_parsed: number;
  total_valid: number;
  total_invalid: number;
}

export interface IngestError {
  index: number;
  message: string;
  raw?: string; // first 200 chars of invalid input
}

// ─── Internal Logger ────────────────────────────────────────────────────────

const log = logger.child({ module: 'alert-ingestor' });

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Validate that a value conforms to the minimum AlertEvent shape.
 *
 * Requirements (lenient):
 * - Must be a non-null object
 * - Must have a string `@timestamp`
 * - Must have an `event` object
 *
 * All other ECS fields are optional.
 */
export function validateAlertEvent(
  data: unknown,
): { valid: boolean; alert?: AlertEvent; error?: string } {
  if (data === null || data === undefined || typeof data !== 'object') {
    return { valid: false, error: 'Input must be a non-null object' };
  }

  const obj = data as Record<string, unknown>;

  // Check @timestamp
  if (!('@timestamp' in obj) || typeof obj['@timestamp'] !== 'string') {
    return {
      valid: false,
      error: 'Missing or invalid "@timestamp" field (must be a string)',
    };
  }

  const timestamp = obj['@timestamp'] as string;
  if (timestamp.trim().length === 0) {
    return { valid: false, error: '"@timestamp" must not be empty' };
  }

  // Check event
  if (
    !('event' in obj) ||
    obj['event'] === null ||
    typeof obj['event'] !== 'object'
  ) {
    return {
      valid: false,
      error: 'Missing or invalid "event" field (must be an object)',
    };
  }

  return { valid: true, alert: data as AlertEvent };
}

// ─── Internal Parsing ───────────────────────────────────────────────────────

/**
 * Detect whether an input string is NDJSON (newline-delimited JSON).
 *
 * Heuristic: the string contains at least one newline, and the first
 * non-empty line parses as a standalone JSON value (object or array element).
 */
function isNdjson(input: string): boolean {
  const trimmed = input.trim();
  if (!trimmed.includes('\n')) {
    return false;
  }

  // If the whole string starts with '[', it is likely a JSON array, not NDJSON
  if (trimmed.startsWith('[')) {
    return false;
  }

  // Try to parse the first non-empty line
  const firstLine = trimmed.split('\n').find((l) => l.trim().length > 0);
  if (!firstLine) {
    return false;
  }

  try {
    const parsed = JSON.parse(firstLine.trim());
    return typeof parsed === 'object' && parsed !== null;
  } catch {
    return false;
  }
}

/**
 * Parse a raw string into an array of unknown values, handling:
 * - Single JSON object
 * - JSON array
 * - NDJSON (newline-delimited JSON)
 */
function parseRawInput(input: string): {
  items: unknown[];
  parseError?: string;
} {
  const trimmed = input.trim();

  if (trimmed.length === 0) {
    return { items: [], parseError: 'Input is empty' };
  }

  // Try NDJSON first (before standard JSON) since a multi-line JSON object
  // starting with '{' could be confused with NDJSON. The isNdjson heuristic
  // checks that the first line alone parses as a complete JSON object.
  if (isNdjson(trimmed)) {
    const lines = trimmed.split('\n');
    const items: unknown[] = [];
    const errors: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!.trim();
      if (line.length === 0) {
        continue;
      }
      try {
        items.push(JSON.parse(line));
      } catch {
        errors.push(`NDJSON parse error on line ${i + 1}`);
        // Push the raw line as a string so the caller can capture it in IngestError
        items.push(line);
      }
    }

    return { items };
  }

  // Standard JSON parse
  try {
    const parsed = JSON.parse(trimmed);

    if (Array.isArray(parsed)) {
      return { items: parsed };
    }

    // Single object
    return { items: [parsed] };
  } catch (err) {
    return {
      items: [],
      parseError: `JSON parse error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Build an IngestResult from an array of parsed items.
 */
function buildIngestResult(
  items: unknown[],
  source: IngestResult['source'],
  sourcePath?: string,
  globalParseError?: string,
): IngestResult {
  const alerts: AlertEvent[] = [];
  const errors: IngestError[] = [];

  if (globalParseError) {
    errors.push({
      index: 0,
      message: globalParseError,
    });

    return {
      success: false,
      alerts,
      errors,
      source,
      source_path: sourcePath,
      total_parsed: 0,
      total_valid: 0,
      total_invalid: 0,
    };
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];

    // If the item is a raw string (from NDJSON parse failure), record it
    if (typeof item === 'string') {
      errors.push({
        index: i,
        message: `Failed to parse as JSON`,
        raw: item.slice(0, 200),
      });
      continue;
    }

    const result = validateAlertEvent(item);

    if (result.valid && result.alert) {
      alerts.push(result.alert);
    } else {
      let rawPreview: string | undefined;
      try {
        rawPreview = JSON.stringify(item).slice(0, 200);
      } catch {
        rawPreview = String(item).slice(0, 200);
      }

      errors.push({
        index: i,
        message: result.error ?? 'Unknown validation error',
        raw: rawPreview,
      });
    }
  }

  const totalParsed = items.length;
  const totalValid = alerts.length;
  const totalInvalid = errors.length;

  return {
    success: totalValid > 0 && totalInvalid === 0,
    alerts,
    errors,
    source,
    source_path: sourcePath,
    total_parsed: totalParsed,
    total_valid: totalValid,
    total_invalid: totalInvalid,
  };
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Ingest alerts from a JSON file.
 *
 * Supports single alert object or array of alerts.
 *
 * @param filePath - Path to a JSON file containing alert(s)
 * @returns IngestResult with parsed alerts and any errors
 */
export async function ingestFromFile(filePath: string): Promise<IngestResult> {
  log.info('Ingesting alerts from file', { filePath });

  let content: string;
  try {
    content = await readFile(filePath, 'utf-8');
  } catch (err) {
    const message =
      err instanceof Error && 'code' in err && (err as NodeJS.ErrnoException).code === 'ENOENT'
        ? `File not found: ${filePath}`
        : `Failed to read file: ${err instanceof Error ? err.message : String(err)}`;

    log.error('File read failed', { filePath, error: message });

    return {
      success: false,
      alerts: [],
      errors: [{ index: 0, message }],
      source: 'file',
      source_path: filePath,
      total_parsed: 0,
      total_valid: 0,
      total_invalid: 0,
    };
  }

  const { items, parseError } = parseRawInput(content);
  const result = buildIngestResult(items, 'file', filePath, parseError);

  log.info('File ingest complete', {
    filePath,
    total_parsed: result.total_parsed,
    total_valid: result.total_valid,
    total_invalid: result.total_invalid,
  });

  return result;
}

/**
 * Ingest alerts from STDIN.
 *
 * Reads all data from process.stdin, then parses as JSON or NDJSON.
 *
 * @returns IngestResult with parsed alerts and any errors
 */
export async function ingestFromStdin(): Promise<IngestResult> {
  log.info('Ingesting alerts from STDIN');

  const chunks: Buffer[] = [];

  const content = await new Promise<string>((resolve, reject) => {
    process.stdin.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    process.stdin.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf-8'));
    });

    process.stdin.on('error', (err: Error) => {
      reject(err);
    });

    // If stdin is already ended (e.g., piped and complete), resume it
    if (process.stdin.readable) {
      process.stdin.resume();
    }
  });

  const { items, parseError } = parseRawInput(content);
  const result = buildIngestResult(items, 'stdin', undefined, parseError);

  log.info('STDIN ingest complete', {
    total_parsed: result.total_parsed,
    total_valid: result.total_valid,
    total_invalid: result.total_invalid,
  });

  return result;
}

/**
 * Ingest alerts from a raw string.
 *
 * Supports JSON (single object or array) and NDJSON.
 * This is a synchronous operation.
 *
 * @param input - Raw JSON or NDJSON string
 * @returns IngestResult with parsed alerts and any errors
 */
export function ingestFromString(input: string): IngestResult {
  log.info('Ingesting alerts from string', {
    inputLength: input.length,
  });

  const { items, parseError } = parseRawInput(input);
  const result = buildIngestResult(items, 'string', undefined, parseError);

  log.info('String ingest complete', {
    total_parsed: result.total_parsed,
    total_valid: result.total_valid,
    total_invalid: result.total_invalid,
  });

  return result;
}
