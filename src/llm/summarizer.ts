/**
 * Enrichment Data Summarizer
 *
 * Uses an OpenRouter-compatible LLM API to produce concise 2-3 sentence
 * summaries of enrichment data associated with a given alert. Designed for
 * analyst review during L0/L1 runbook execution.
 *
 * This module is enrichment-only: the LLM never makes decisions or controls
 * execution flow. All errors are caught and returned gracefully -- public
 * methods never throw.
 *
 * @module llm/summarizer
 */

import type { AlertEvent } from '../types/ecs.ts';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Configuration for the enrichment summarizer.
 */
export interface SummarizerOptions {
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
 * A single enrichment payload from an external source.
 */
export interface EnrichmentData {
  /** Enrichment source identifier, e.g. "geoip", "virustotal", "asset_inventory" */
  source: string;
  /** Source-specific enrichment data */
  data: Record<string, unknown>;
}

/**
 * Result of an enrichment summarization request.
 */
export interface SummaryResult {
  /** Whether the LLM call succeeded */
  success: boolean;
  /** 2-3 sentence summary of enrichment data (present on success) */
  summary?: string;
  /** Bullet-point key findings extracted from the summary */
  key_findings?: string[];
  /** Error message (present on failure) */
  error?: string;
  /** Wall-clock duration of the summarization call in milliseconds */
  duration_ms: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT =
  'You are a SOC analyst assistant. Summarize the following enrichment data ' +
  'for the given alert in 2-3 concise sentences. Highlight key findings and ' +
  'anomalies. If there are important indicators of compromise or risk factors, ' +
  'call them out as bullet points prefixed with "- ".';

// ---------------------------------------------------------------------------
// EnrichmentSummarizer
// ---------------------------------------------------------------------------

/**
 * Produces concise LLM-generated summaries of enrichment data for a given
 * alert event. Intended to assist SOC analysts during manual or semi-automated
 * runbook execution.
 */
export class EnrichmentSummarizer {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeout: number;
  private readonly maxTokens: number;

  constructor(options: SummarizerOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.model = options.model;
    this.timeout = options.timeout;
    this.maxTokens = options.maxTokens;
  }

  /**
   * Summarize enrichment data in the context of the provided alert.
   *
   * @param alert     - The ECS-normalized alert event
   * @param enrichments - Array of enrichment payloads to summarize
   * @returns A SummaryResult -- never throws
   */
  async summarize(
    alert: AlertEvent,
    enrichments: EnrichmentData[],
  ): Promise<SummaryResult> {
    const start = performance.now();

    try {
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
          enrichments,
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

      const keyFindings = extractKeyFindings(content);

      return {
        success: true,
        summary: content.trim(),
        key_findings: keyFindings.length > 0 ? keyFindings : undefined,
        duration_ms: elapsed(start),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: `Summarization failed: ${message}`,
        duration_ms: elapsed(start),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an EnrichmentSummarizer from a flat configuration object.
 */
export function createSummarizer(config: {
  baseUrl: string;
  apiKey: string;
  model: string;
  timeout: number;
  maxTokens: number;
}): EnrichmentSummarizer {
  return new EnrichmentSummarizer({
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
 * Extract key findings from the LLM output by looking for bullet points
 * (lines starting with "- " or "* ") and numbered items (e.g., "1. ").
 */
function extractKeyFindings(content: string): string[] {
  const lines = content.split('\n');
  const findings: string[] = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Match "- item", "* item", or "1. item" / "2) item" patterns
    const bulletMatch = trimmed.match(/^[-*]\s+(.+)$/);
    const numberedMatch = trimmed.match(/^\d+[.)]\s+(.+)$/);

    if (bulletMatch?.[1]) {
      findings.push(bulletMatch[1].trim());
    } else if (numberedMatch?.[1]) {
      findings.push(numberedMatch[1].trim());
    }
  }

  return findings;
}

/**
 * Compute elapsed milliseconds since a given start time (from performance.now()).
 */
function elapsed(start: number): number {
  return Math.round(performance.now() - start);
}
