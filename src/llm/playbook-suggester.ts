/**
 * Playbook Suggester
 *
 * Uses an OpenRouter-compatible LLM API to suggest relevant playbooks when
 * no direct MITRE ATT&CK technique match exists. The LLM evaluates the alert
 * context against available playbooks and returns ranked suggestions with
 * confidence scores and justifications.
 *
 * This module is enrichment-only: the LLM never makes decisions or controls
 * execution flow. All errors are caught and returned gracefully -- public
 * methods never throw.
 *
 * @module llm/playbook-suggester
 */

import type { AlertEvent } from '../types/ecs.ts';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Configuration for the playbook suggester.
 */
export interface SuggesterOptions {
  /** OpenRouter (or compatible) base URL, e.g. "https://openrouter.ai/api/v1" */
  baseUrl: string;
  /** OpenRouter API key */
  apiKey: string;
  /** Model identifier, e.g. "openai/gpt-4o-mini" */
  model: string;
  /** Request timeout in milliseconds */
  timeout: number;
  /** Maximum tokens for the LLM response */
  maxTokens: number;
}

/**
 * A playbook descriptor provided to the suggester for matching.
 */
export interface PlaybookDescriptor {
  id: string;
  name: string;
  description: string;
  techniques: string[];
}

/**
 * Result of a playbook suggestion request.
 */
export interface PlaybookSuggestion {
  /** Whether the LLM call succeeded */
  success: boolean;
  /** Ranked playbook suggestions (present on success) */
  suggestions?: Array<{
    /** ID of the suggested playbook */
    playbook_id: string;
    /** Confidence score from 0 to 1 */
    confidence: number;
    /** Explanation of why this playbook is relevant */
    justification: string;
  }>;
  /** Error message (present on failure) */
  error?: string;
  /** Wall-clock duration of the suggestion call in milliseconds */
  duration_ms: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT =
  'You are a SOC automation expert. Given an alert and a list of available ' +
  'playbooks, suggest which playbooks are most relevant to handle the alert. ' +
  'Respond ONLY with valid JSON in the following format (no markdown fences, ' +
  'no additional text):\n\n' +
  '{\n' +
  '  "suggestions": [\n' +
  '    {\n' +
  '      "playbook_id": "<id from the available playbooks>",\n' +
  '      "confidence": <number between 0 and 1>,\n' +
  '      "justification": "<brief explanation>"\n' +
  '    }\n' +
  '  ]\n' +
  '}\n\n' +
  'Order suggestions by confidence (highest first). Only include playbooks ' +
  'with confidence >= 0.3. If no playbook is relevant, return an empty ' +
  'suggestions array.';

// ---------------------------------------------------------------------------
// PlaybookSuggester
// ---------------------------------------------------------------------------

/**
 * Suggests relevant playbooks for an alert when no direct technique match
 * exists. Uses LLM inference to evaluate alert context against available
 * playbook descriptions and techniques.
 */
export class PlaybookSuggester {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeout: number;
  private readonly maxTokens: number;

  constructor(options: SuggesterOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.model = options.model;
    this.timeout = options.timeout;
    this.maxTokens = options.maxTokens;
  }

  /**
   * Suggest playbooks that may be relevant to the given alert.
   *
   * @param alert              - The ECS-normalized alert event
   * @param availablePlaybooks - Playbook descriptors to evaluate against
   * @returns A PlaybookSuggestion -- never throws
   */
  async suggest(
    alert: AlertEvent,
    availablePlaybooks: PlaybookDescriptor[],
  ): Promise<PlaybookSuggestion> {
    const start = performance.now();

    try {
      if (availablePlaybooks.length === 0) {
        return {
          success: true,
          suggestions: [],
          duration_ms: elapsed(start),
        };
      }

      const userContent = JSON.stringify(
        {
          alert: {
            timestamp: alert['@timestamp'],
            event: alert.event,
            host: alert.host,
            source: alert.source,
            destination: alert.destination,
            process: alert.process,
            file: alert.file,
            user: alert.user,
            threat: alert.threat,
            tags: alert.tags,
          },
          available_playbooks: availablePlaybooks.map((pb) => ({
            id: pb.id,
            name: pb.name,
            description: pb.description,
            techniques: pb.techniques,
          })),
        },
        null,
        2,
      );

      const body = JSON.stringify({
        model: this.model,
        max_tokens: this.maxTokens,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userContent },
        ],
      });

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      let response: Response;
      try {
        response = await fetch(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
          },
          body,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
      }

      if (!response.ok) {
        const errorBody = await response.text().catch(() => 'unknown');
        return {
          success: false,
          error: `LLM API returned HTTP ${response.status}: ${errorBody}`,
          duration_ms: elapsed(start),
        };
      }

      const json = (await response.json()) as Record<string, unknown>;
      const content = extractContent(json);

      if (!content) {
        return {
          success: false,
          error: 'LLM response did not contain message content',
          duration_ms: elapsed(start),
        };
      }

      // Parse the JSON response from the LLM
      const parsed = parseJsonResponse(content);

      if (!parsed) {
        return {
          success: false,
          error: 'Failed to parse LLM response as valid suggestion JSON',
          duration_ms: elapsed(start),
        };
      }

      // Validate and normalize each suggestion
      const validPlaybookIds = new Set(availablePlaybooks.map((pb) => pb.id));
      const suggestions = validateSuggestions(parsed, validPlaybookIds);

      return {
        success: true,
        suggestions,
        duration_ms: elapsed(start),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: `Playbook suggestion failed: ${message}`,
        duration_ms: elapsed(start),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a PlaybookSuggester from a flat configuration object.
 */
export function createSuggester(config: {
  baseUrl: string;
  apiKey: string;
  model: string;
  timeout: number;
  maxTokens: number;
}): PlaybookSuggester {
  return new PlaybookSuggester({
    baseUrl: config.baseUrl,
    apiKey: config.apiKey,
    model: config.model,
    timeout: config.timeout,
    maxTokens: config.maxTokens,
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the text content from an OpenAI-compatible chat completion response.
 */
function extractContent(json: Record<string, unknown>): string | null {
  const choices = json.choices as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(choices) || choices.length === 0) {
    return null;
  }

  const message = choices[0]!.message as Record<string, unknown> | undefined;
  if (!message || typeof message.content !== 'string') {
    return null;
  }

  return message.content;
}

/**
 * Parse a JSON response from the LLM. Handles cases where the LLM wraps
 * the JSON in markdown code fences or includes surrounding text.
 */
function parseJsonResponse(
  content: string,
): { suggestions: unknown[] } | null {
  // Try direct parse first
  try {
    const parsed = JSON.parse(content);
    if (isValidSuggestionShape(parsed)) {
      return parsed;
    }
  } catch {
    // Fall through to extraction attempts
  }

  // Try extracting JSON from markdown code fences: ```json ... ``` or ``` ... ```
  const fenceMatch = content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) {
    try {
      const parsed = JSON.parse(fenceMatch[1]!);
      if (isValidSuggestionShape(parsed)) {
        return parsed;
      }
    } catch {
      // Fall through
    }
  }

  // Try finding JSON object boundaries
  const firstBrace = content.indexOf('{');
  const lastBrace = content.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      const parsed = JSON.parse(content.slice(firstBrace, lastBrace + 1));
      if (isValidSuggestionShape(parsed)) {
        return parsed;
      }
    } catch {
      // Give up
    }
  }

  return null;
}

/**
 * Type guard: does the parsed object have a suggestions array?
 */
function isValidSuggestionShape(
  value: unknown,
): value is { suggestions: unknown[] } {
  if (typeof value !== 'object' || value === null) return false;
  const obj = value as Record<string, unknown>;
  return Array.isArray(obj.suggestions);
}

/**
 * Validate individual suggestions, filtering out malformed entries and
 * clamping confidence to [0, 1]. Only includes suggestions whose
 * playbook_id exists in the provided set.
 */
function validateSuggestions(
  parsed: { suggestions: unknown[] },
  validPlaybookIds: Set<string>,
): Array<{
  playbook_id: string;
  confidence: number;
  justification: string;
}> {
  const results: Array<{
    playbook_id: string;
    confidence: number;
    justification: string;
  }> = [];

  for (const item of parsed.suggestions) {
    if (typeof item !== 'object' || item === null) continue;

    const entry = item as Record<string, unknown>;

    const playbookId = typeof entry.playbook_id === 'string'
      ? entry.playbook_id
      : undefined;

    if (!playbookId || !validPlaybookIds.has(playbookId)) continue;

    const rawConfidence = typeof entry.confidence === 'number'
      ? entry.confidence
      : parseFloat(String(entry.confidence ?? ''));

    if (isNaN(rawConfidence)) continue;

    const confidence = Math.max(0, Math.min(1, rawConfidence));

    const justification = typeof entry.justification === 'string'
      ? entry.justification
      : 'No justification provided';

    results.push({ playbook_id: playbookId, confidence, justification });
  }

  // Sort by confidence descending
  results.sort((a, b) => b.confidence - a.confidence);

  return results;
}

/**
 * Compute elapsed milliseconds since a given start time (from performance.now()).
 */
function elapsed(start: number): number {
  return Math.round(performance.now() - start);
}
