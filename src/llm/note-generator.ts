/**
 * Investigation Note Generator
 *
 * Uses an OpenRouter-compatible LLM API to auto-generate structured
 * investigation notes from runbook execution results. Produces markdown-
 * formatted notes with timeline, actions taken, findings, and
 * recommendations for analyst review.
 *
 * This module is enrichment-only: the LLM never makes decisions or controls
 * execution flow. All errors are caught and returned gracefully -- public
 * methods never throw.
 *
 * @module llm/note-generator
 */

import type { ExecutionResult, StepResult } from '../types/playbook.ts';
import type { AlertEvent } from '../types/ecs.ts';

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Configuration for the investigation note generator.
 */
export interface NoteGeneratorOptions {
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
 * Result of an investigation note generation request.
 */
export interface InvestigationNotes {
  /** Whether the LLM call succeeded */
  success: boolean;
  /** Markdown-formatted investigation notes (present on success) */
  notes?: string;
  /** Chronological timeline of events extracted from the notes */
  timeline?: string[];
  /** Recommended next steps extracted from the notes */
  recommendations?: string[];
  /** Error message (present on failure) */
  error?: string;
  /** Wall-clock duration of the generation call in milliseconds */
  duration_ms: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT =
  'You are a SOC analyst creating investigation notes. Generate concise, ' +
  'structured markdown notes from the execution results. The notes MUST ' +
  'include the following sections with exact headings:\n\n' +
  '## Timeline\n' +
  'A chronological list of events as bullet points (use "- " prefix).\n\n' +
  '## Actions Taken\n' +
  'Summary of what the runbook executed.\n\n' +
  '## Findings\n' +
  'Key observations and conclusions from the execution.\n\n' +
  '## Recommendations\n' +
  'Next steps as bullet points (use "- " prefix).\n\n' +
  'Be concise and factual. Do not speculate beyond what the data shows.';

// ---------------------------------------------------------------------------
// InvestigationNoteGenerator
// ---------------------------------------------------------------------------

/**
 * Generates structured markdown investigation notes from runbook execution
 * results. Intended to reduce analyst documentation burden during incident
 * response.
 */
export class InvestigationNoteGenerator {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeout: number;
  private readonly maxTokens: number;

  constructor(options: NoteGeneratorOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey;
    this.model = options.model;
    this.timeout = options.timeout;
    this.maxTokens = options.maxTokens;
  }

  /**
   * Generate investigation notes from an alert and its execution results.
   *
   * @param alert             - The ECS-normalized alert event
   * @param executionResult   - The runbook execution result
   * @param enrichmentSummary - Optional pre-generated enrichment summary
   * @returns An InvestigationNotes result -- never throws
   */
  async generate(
    alert: AlertEvent,
    executionResult: ExecutionResult,
    enrichmentSummary?: string,
  ): Promise<InvestigationNotes> {
    const start = performance.now();

    try {
      const userContent = formatUserPrompt(
        alert,
        executionResult,
        enrichmentSummary,
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

      const timeline = extractSection(content, 'Timeline');
      const recommendations = extractSection(content, 'Recommendations');

      return {
        success: true,
        notes: content.trim(),
        timeline: timeline.length > 0 ? timeline : undefined,
        recommendations: recommendations.length > 0
          ? recommendations
          : undefined,
        duration_ms: elapsed(start),
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        error: `Note generation failed: ${message}`,
        duration_ms: elapsed(start),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an InvestigationNoteGenerator from a flat configuration object.
 */
export function createNoteGenerator(config: {
  baseUrl: string;
  apiKey: string;
  model: string;
  timeout: number;
  maxTokens: number;
}): InvestigationNoteGenerator {
  return new InvestigationNoteGenerator({
    baseUrl: config.baseUrl,
    apiKey: config.apiKey,
    model: config.model,
    timeout: config.timeout,
    maxTokens: config.maxTokens,
  });
}

// ---------------------------------------------------------------------------
// Prompt Formatting
// ---------------------------------------------------------------------------

/**
 * Format the user prompt with structured alert and execution data for
 * the LLM to process into investigation notes.
 */
function formatUserPrompt(
  alert: AlertEvent,
  executionResult: ExecutionResult,
  enrichmentSummary?: string,
): string {
  const sections: string[] = [];

  // Alert context
  sections.push('### Alert');
  sections.push(`- Timestamp: ${alert['@timestamp']}`);
  sections.push(`- Severity: ${alert.event.severity}`);
  sections.push(`- Categories: ${alert.event.category.join(', ')}`);
  sections.push(`- Types: ${alert.event.type.join(', ')}`);

  if (alert.host?.hostname) {
    sections.push(`- Host: ${alert.host.hostname}`);
  }

  if (alert.source?.ip) {
    sections.push(`- Source IP: ${alert.source.ip}`);
  }

  if (alert.destination?.ip) {
    sections.push(`- Destination IP: ${alert.destination.ip}`);
  }

  if (alert.user?.name) {
    sections.push(`- User: ${alert.user.name}`);
  }

  if (alert.process?.name) {
    sections.push(`- Process: ${alert.process.name}`);
    if (alert.process.command_line) {
      sections.push(`- Command Line: ${alert.process.command_line}`);
    }
  }

  if (alert.threat?.technique?.id) {
    sections.push(
      `- MITRE Techniques: ${alert.threat.technique.id.join(', ')}`,
    );
  }

  if (alert.tags && alert.tags.length > 0) {
    sections.push(`- Tags: ${alert.tags.join(', ')}`);
  }

  // Execution result
  sections.push('');
  sections.push('### Execution Result');
  sections.push(`- Runbook ID: ${executionResult.runbook_id}`);
  sections.push(`- Execution ID: ${executionResult.execution_id}`);
  sections.push(`- Success: ${executionResult.success}`);
  sections.push(`- State: ${executionResult.state}`);
  sections.push(`- Started: ${executionResult.started_at}`);
  sections.push(`- Completed: ${executionResult.completed_at}`);
  sections.push(`- Duration: ${executionResult.duration_ms}ms`);
  sections.push(
    `- Steps: ${executionResult.metrics.successful_steps}/${executionResult.metrics.total_steps} successful`,
  );

  if (executionResult.metrics.rollbacks_triggered > 0) {
    sections.push(
      `- Rollbacks: ${executionResult.metrics.rollbacks_triggered}`,
    );
  }

  if (executionResult.error) {
    sections.push(`- Error: [${executionResult.error.code}] ${executionResult.error.message}`);
  }

  // Step details
  if (executionResult.steps_executed.length > 0) {
    sections.push('');
    sections.push('### Step Results');
    for (const step of executionResult.steps_executed) {
      sections.push(formatStepResult(step));
    }
  }

  // Enrichment summary (if provided)
  if (enrichmentSummary) {
    sections.push('');
    sections.push('### Enrichment Summary');
    sections.push(enrichmentSummary);
  }

  return sections.join('\n');
}

/**
 * Format a single step result for inclusion in the user prompt.
 */
function formatStepResult(step: StepResult): string {
  const status = step.success ? 'OK' : 'FAILED';
  const rolledBack = step.rolled_back ? ' [ROLLED BACK]' : '';
  const error = step.error
    ? ` - Error: [${step.error.code}] ${step.error.message}`
    : '';

  return `- [${status}] ${step.step_name} (${step.action}, ${step.duration_ms}ms)${rolledBack}${error}`;
}

// ---------------------------------------------------------------------------
// Response Parsing
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
 * Extract bullet-point items from a named markdown section.
 *
 * Looks for a heading like "## Timeline" or "## Recommendations" and
 * collects all subsequent bullet points until the next heading or EOF.
 */
function extractSection(markdown: string, sectionName: string): string[] {
  const lines = markdown.split('\n');
  const items: string[] = [];
  let inSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Check for section heading (## or ### with the target name)
    if (/^#{1,4}\s+/.test(trimmed)) {
      const headingText = trimmed.replace(/^#{1,4}\s+/, '').trim().toLowerCase();
      if (headingText === sectionName.toLowerCase()) {
        inSection = true;
        continue;
      } else if (inSection) {
        // Reached the next section heading -- stop collecting
        break;
      }
    }

    if (!inSection) continue;

    // Collect bullet points and numbered items
    const bulletMatch = trimmed.match(/^[-*]\s+(.+)$/);
    const numberedMatch = trimmed.match(/^\d+[.)]\s+(.+)$/);

    if (bulletMatch?.[1]) {
      items.push(bulletMatch[1].trim());
    } else if (numberedMatch?.[1]) {
      items.push(numberedMatch[1].trim());
    }
  }

  return items;
}

/**
 * Compute elapsed milliseconds since a given start time (from performance.now()).
 */
function elapsed(start: number): number {
  return Math.round(performance.now() - start);
}
