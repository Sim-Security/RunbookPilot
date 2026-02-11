/**
 * Confidence Scorer Module
 *
 * Calculates and displays confidence scores for simulation results.
 * Confidence is computed as a weighted sum of multiple factors:
 * parameter validation, adapter health, rollback availability,
 * historical success rate, and DetectForge detection confidence.
 *
 * Used by the L2 simulation engine to quantify how confident
 * RunbookPilot is that a simulated step will succeed in production.
 *
 * @module engine/confidence-scorer
 */

import type { AlertEvent } from '../types/ecs.ts';
import type {
  ConfidenceBreakdown,
  ConfidenceDisplay,
} from '../types/simulation.ts';
import type { HealthCheckResult } from '../adapters/adapter-interface.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Weights for each confidence factor. Must sum to 1.0. */
const WEIGHTS = {
  parameter_validation: 0.30,
  adapter_health: 0.25,
  rollback_available: 0.15,
  historical_success_rate: 0.15,
  detectforge_confidence: 0.15,
} as const;

/** Default value used when an optional score is not provided. */
const DEFAULT_OPTIONAL_SCORE = 0.5;

/** Threshold at or above which confidence is labeled 'high'. */
const HIGH_THRESHOLD = 0.7;

/** Threshold at or above which confidence is labeled 'medium'. */
const MEDIUM_THRESHOLD = 0.4;

/**
 * Mapping from DetectForge string confidence levels to numeric values.
 * The DetectForge metadata stores confidence as 'low' | 'medium' | 'high'.
 */
const DETECTFORGE_CONFIDENCE_MAP: Record<string, number> = {
  low: 0.3,
  medium: 0.6,
  high: 0.9,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Options for calculating step-level confidence.
 */
export interface StepConfidenceOptions {
  /** Whether parameter validation passed for this step. */
  parameterValidationPassed: boolean;

  /** Health check result from the adapter that will execute this step. */
  adapterHealth?: HealthCheckResult;

  /** Whether a rollback action is available for this step. */
  rollbackAvailable: boolean;

  /** Historical success rate for this step/action type (0.0 - 1.0). */
  historicalSuccessRate?: number;

  /** Confidence from DetectForge detection rule (0.0 - 1.0). */
  detectforgeConfidence?: number;
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/**
 * Calculate the confidence score breakdown for a single simulation step.
 *
 * Each factor is scored 0.0 - 1.0 and multiplied by its weight.
 * The overall score is the weighted sum of all factors.
 *
 * Factor weights:
 * - parameter_validation: 0.30 (1.0 if passed, 0.0 if not)
 * - adapter_health:       0.25 (1.0 if healthy, 0.5 if degraded, 0.0 otherwise)
 * - rollback_available:   0.15 (1.0 if available, 0.0 if not)
 * - historical_success_rate: 0.15 (provided value or 0.5 default)
 * - detectforge_confidence:  0.15 (provided value or 0.5 default)
 *
 * @param options - The scoring inputs for this step
 * @returns A full confidence breakdown including the weighted overall score
 */
export function calculateStepConfidence(
  options: StepConfidenceOptions,
): ConfidenceBreakdown {
  const parameterValidation = options.parameterValidationPassed ? 1.0 : 0.0;

  const adapterHealth = scoreAdapterHealth(options.adapterHealth);

  const rollbackAvailable = options.rollbackAvailable ? 1.0 : 0.0;

  const historicalSuccessRate =
    options.historicalSuccessRate ?? DEFAULT_OPTIONAL_SCORE;

  const detectforgeConfidence =
    options.detectforgeConfidence ?? DEFAULT_OPTIONAL_SCORE;

  const overall =
    parameterValidation * WEIGHTS.parameter_validation +
    adapterHealth * WEIGHTS.adapter_health +
    rollbackAvailable * WEIGHTS.rollback_available +
    historicalSuccessRate * WEIGHTS.historical_success_rate +
    detectforgeConfidence * WEIGHTS.detectforge_confidence;

  const breakdown: ConfidenceBreakdown = {
    parameter_validation: parameterValidation,
    adapter_health: adapterHealth,
    rollback_available: rollbackAvailable,
    overall: clamp(overall, 0.0, 1.0),
  };

  // Include optional fields only when explicitly provided
  if (options.historicalSuccessRate !== undefined) {
    breakdown.historical_success_rate = historicalSuccessRate;
  }

  if (options.detectforgeConfidence !== undefined) {
    breakdown.detectforge_confidence = detectforgeConfidence;
  }

  return breakdown;
}

/**
 * Calculate the overall confidence across multiple simulation steps.
 *
 * Returns the arithmetic mean of all step confidence scores (the `overall`
 * field from each breakdown). The result is clamped to [0.0, 1.0].
 *
 * @param stepConfidences - Array of per-step confidence breakdowns
 * @returns Overall confidence score (0.0 - 1.0), or 0.0 if the array is empty
 */
export function calculateOverallConfidence(
  stepConfidences: ConfidenceBreakdown[],
): number {
  if (stepConfidences.length === 0) {
    return 0.0;
  }

  const sum = stepConfidences.reduce(
    (acc, breakdown) => acc + breakdown.overall,
    0.0,
  );

  return clamp(sum / stepConfidences.length, 0.0, 1.0);
}

/**
 * Get a display-friendly representation of a confidence score.
 *
 * Score thresholds:
 * - >= 0.7 : label = 'high',   color = 'green'
 * - >= 0.4 : label = 'medium', color = 'yellow'
 * - <  0.4 : label = 'low',    color = 'red'
 *
 * @param score   - The confidence score (0.0 - 1.0)
 * @param source  - Where the score came from (defaults to 'combined')
 * @param ruleId  - Optional detection rule ID that triggered the alert
 * @returns A ConfidenceDisplay object for CLI rendering
 */
export function getConfidenceDisplay(
  score: number,
  source?: string,
  ruleId?: string,
): ConfidenceDisplay {
  let label: ConfidenceDisplay['label'];
  let color: ConfidenceDisplay['color'];

  if (score >= HIGH_THRESHOLD) {
    label = 'high';
    color = 'green';
  } else if (score >= MEDIUM_THRESHOLD) {
    label = 'medium';
    color = 'yellow';
  } else {
    label = 'low';
    color = 'red';
  }

  const display: ConfidenceDisplay = {
    score,
    label,
    color,
    source: source ?? 'combined',
  };

  if (ruleId !== undefined) {
    display.rule_id = ruleId;
  }

  return display;
}

/**
 * Extract the numeric DetectForge confidence from an alert event.
 *
 * DetectForge metadata is stored at `alert['x-detectforge']` in the ECS
 * AlertEvent type. The `confidence` field is a string ('low' | 'medium' | 'high')
 * which is mapped to a numeric value:
 * - 'low'    -> 0.3
 * - 'medium' -> 0.6
 * - 'high'   -> 0.9
 *
 * @param alert - The ECS alert event (optional)
 * @returns Numeric confidence (0.0 - 1.0), or undefined if metadata is absent
 */
export function extractDetectForgeConfidence(
  alert?: AlertEvent,
): number | undefined {
  const metadata = alert?.['x-detectforge'];

  if (!metadata) {
    return undefined;
  }

  const numericConfidence = DETECTFORGE_CONFIDENCE_MAP[metadata.confidence];

  return numericConfidence ?? undefined;
}

/**
 * Extract the DetectForge rule ID from an alert event.
 *
 * DetectForge metadata is stored at `alert['x-detectforge']` in the ECS
 * AlertEvent type. The `rule_id` field identifies the detection rule
 * that generated the alert.
 *
 * @param alert - The ECS alert event (optional)
 * @returns The rule ID string, or undefined if metadata is absent
 */
export function extractDetectForgeRuleId(
  alert?: AlertEvent,
): string | undefined {
  return alert?.['x-detectforge']?.rule_id;
}

/**
 * Format a ConfidenceDisplay object into a human-readable string.
 *
 * Output format:
 *   "Confidence: 85% (HIGH) [green] -- Source: detectforge (rule: sigma-1234)"
 *
 * When no rule_id is present, the rule portion is omitted:
 *   "Confidence: 50% (MEDIUM) [yellow] -- Source: combined"
 *
 * Note: No ANSI color codes are emitted; the color name appears as a label
 * in square brackets.
 *
 * @param display - The confidence display object to format
 * @returns A formatted string suitable for CLI output
 */
export function formatConfidenceForDisplay(display: ConfidenceDisplay): string {
  const percentage = Math.round(display.score * 100);
  const labelUpper = display.label.toUpperCase();

  let result = `Confidence: ${percentage}% (${labelUpper}) [${display.color}]`;
  result += ` \u2014 Source: ${display.source}`;

  if (display.rule_id) {
    result += ` (rule: ${display.rule_id})`;
  }

  return result;
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Score adapter health status as a numeric value.
 *
 * @param health - Health check result, or undefined if not available
 * @returns 1.0 for healthy, 0.5 for degraded, 0.0 for unhealthy/unknown/absent
 */
function scoreAdapterHealth(health?: HealthCheckResult): number {
  if (!health) {
    return 0.0;
  }

  switch (health.status) {
    case 'healthy':
      return 1.0;
    case 'degraded':
      return 0.5;
    case 'unhealthy':
    case 'unknown':
    default:
      return 0.0;
  }
}

/**
 * Clamp a numeric value to the range [min, max].
 *
 * @param value - The value to clamp
 * @param min   - Minimum allowed value
 * @param max   - Maximum allowed value
 * @returns The clamped value
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}
