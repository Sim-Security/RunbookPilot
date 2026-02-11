/**
 * Trigger Condition Evaluation Engine
 *
 * Evaluates playbook trigger conditions against incoming alert data.
 * Determines whether an alert matches a playbook's RunbookTrigger by
 * checking detection sources, MITRE techniques, platforms, severity,
 * and arbitrary user-defined conditions.
 *
 * Supports a rich condition DSL with:
 * - Dot-notation field access (including array indexing)
 * - Comparison operators (eq, ne, gt, lt, gte, lte)
 * - Collection operators (in, contains)
 * - Pattern matching (matches, exists)
 * - Logical combinators (and, or, not)
 *
 * @module engine/trigger-evaluator
 */

import type { AlertEvent } from '../types/ecs.ts';
import type { RunbookTrigger, DetectionSource, Severity } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Operators for comparing field values against expected values.
 */
export type TriggerOperator =
  | 'eq'
  | 'ne'
  | 'gt'
  | 'lt'
  | 'gte'
  | 'lte'
  | 'in'
  | 'contains'
  | 'matches'
  | 'exists';

/**
 * Logical combinators for composing conditions.
 */
export type TriggerLogic = 'and' | 'or' | 'not';

/**
 * A single condition or logical group of conditions.
 *
 * Leaf conditions specify a field, operator, and value.
 * Branch conditions specify a logic combinator and sub-conditions.
 */
export interface TriggerCondition {
  /** Dot-notation path to the field in the data (e.g., 'event.category') */
  field?: string;
  /** Comparison operator */
  operator?: TriggerOperator;
  /** Expected value for comparison */
  value?: unknown;
  /** Logical combinator for sub-conditions */
  logic?: TriggerLogic;
  /** Sub-conditions for and/or/not */
  conditions?: TriggerCondition[];
}

/**
 * Result of evaluating a trigger against an alert.
 */
export interface TriggerResult {
  /** Whether the alert matched the trigger */
  matched: boolean;
  /** The type of trigger evaluation performed */
  trigger_type: string;
  /** Total number of conditions evaluated */
  conditions_evaluated: number;
  /** Number of conditions that passed */
  conditions_passed: number;
  /** Explanation when the alert does not match */
  reason?: string;
}

// ---------------------------------------------------------------------------
// Field Access
// ---------------------------------------------------------------------------

/**
 * Regex to match array index notation: `fieldName[index]`.
 * Captures the field name and the numeric index.
 */
const ARRAY_INDEX_REGEX = /^([^[]+)\[(\d+)\]$/;

/**
 * Resolve a dot-notation field path against a data object.
 *
 * Supports:
 * - Simple dot-notation: `event.category` -> data.event.category
 * - Array indexing: `steps[0].name` -> data.steps[0].name
 * - Mixed: `threat.technique.id[0]` -> data.threat.technique.id[0]
 *
 * Returns `undefined` if any segment in the path does not exist.
 */
export function getFieldValue(data: Record<string, unknown>, path: string): unknown {
  const segments = path.split('.');
  let current: unknown = data;

  for (const segment of segments) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== 'object') return undefined;

    const arrayMatch = ARRAY_INDEX_REGEX.exec(segment);
    if (arrayMatch) {
      const fieldName = arrayMatch[1]!;
      const index = parseInt(arrayMatch[2]!, 10);

      // Access the field first, then the array index
      const fieldValue = (current as Record<string, unknown>)[fieldName];
      if (!Array.isArray(fieldValue)) return undefined;
      current = fieldValue[index];
    } else {
      current = (current as Record<string, unknown>)[segment];
    }
  }

  return current;
}

// ---------------------------------------------------------------------------
// Condition Evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a single condition against a data object.
 *
 * For leaf conditions (field + operator + value), resolves the field path
 * and applies the operator. For branch conditions (logic + conditions),
 * recursively evaluates sub-conditions with the specified logic.
 *
 * @param condition - The condition to evaluate
 * @param data - The data object to evaluate against
 * @returns Whether the condition is satisfied
 */
export function evaluateCondition(
  condition: TriggerCondition,
  data: Record<string, unknown>,
): boolean {
  // Branch: logical combinator with sub-conditions
  if (condition.logic && condition.conditions) {
    return evaluateLogic(condition.logic, condition.conditions, data);
  }

  // Leaf: field + operator comparison
  if (condition.field && condition.operator) {
    const fieldValue = getFieldValue(data, condition.field);
    return applyOperator(condition.operator, fieldValue, condition.value);
  }

  // Malformed condition: no logic and no field/operator -- treat as non-matching
  return false;
}

/**
 * Apply a logical combinator to sub-conditions.
 */
function evaluateLogic(
  logic: TriggerLogic,
  conditions: TriggerCondition[],
  data: Record<string, unknown>,
): boolean {
  switch (logic) {
    case 'and':
      return conditions.every((c) => evaluateCondition(c, data));
    case 'or':
      return conditions.some((c) => evaluateCondition(c, data));
    case 'not': {
      // 'not' applies to the first sub-condition
      const first = conditions[0];
      if (!first) return true; // no condition to negate -> vacuously true
      return !evaluateCondition(first, data);
    }
    default:
      return false;
  }
}

/**
 * Apply a comparison operator to a field value and expected value.
 */
function applyOperator(
  operator: TriggerOperator,
  fieldValue: unknown,
  expectedValue: unknown,
): boolean {
  switch (operator) {
    case 'eq':
      return fieldValue === expectedValue;

    case 'ne':
      return fieldValue !== expectedValue;

    case 'gt':
      return typeof fieldValue === 'number' && typeof expectedValue === 'number'
        && fieldValue > expectedValue;

    case 'lt':
      return typeof fieldValue === 'number' && typeof expectedValue === 'number'
        && fieldValue < expectedValue;

    case 'gte':
      return typeof fieldValue === 'number' && typeof expectedValue === 'number'
        && fieldValue >= expectedValue;

    case 'lte':
      return typeof fieldValue === 'number' && typeof expectedValue === 'number'
        && fieldValue <= expectedValue;

    case 'in':
      if (!Array.isArray(expectedValue)) return false;
      return expectedValue.includes(fieldValue);

    case 'contains':
      // String contains substring
      if (typeof fieldValue === 'string' && typeof expectedValue === 'string') {
        return fieldValue.includes(expectedValue);
      }
      // Array contains element
      if (Array.isArray(fieldValue)) {
        return fieldValue.includes(expectedValue);
      }
      return false;

    case 'matches':
      if (typeof fieldValue !== 'string' || typeof expectedValue !== 'string') {
        return false;
      }
      try {
        const regex = new RegExp(expectedValue);
        return regex.test(fieldValue);
      } catch {
        // Invalid regex pattern
        return false;
      }

    case 'exists':
      // Check if field exists and is not null/undefined
      // expectedValue can be true (field must exist) or false (field must not exist)
      if (expectedValue === false) {
        return fieldValue === null || fieldValue === undefined;
      }
      return fieldValue !== null && fieldValue !== undefined;

    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Severity Mapping
// ---------------------------------------------------------------------------

/**
 * Map a numeric ECS severity (0-100) to a RunbookPilot Severity label.
 *
 * Ranges:
 * - 0-24: low
 * - 25-49: medium
 * - 50-74: high
 * - 75-100: critical
 */
function mapSeverity(numericSeverity: number): Severity {
  if (numericSeverity >= 75) return 'critical';
  if (numericSeverity >= 50) return 'high';
  if (numericSeverity >= 25) return 'medium';
  return 'low';
}

// ---------------------------------------------------------------------------
// Alert-to-Trigger Matching
// ---------------------------------------------------------------------------

/**
 * Infer the detection source from an AlertEvent.
 *
 * Uses the presence of `x-detectforge` metadata, event dataset/module,
 * and tags to determine the likely detection source.
 */
function inferDetectionSource(alert: AlertEvent): DetectionSource | undefined {
  // DetectForge metadata present
  if (alert['x-detectforge']) {
    return 'detectforge';
  }

  // Check tags for known sources
  if (alert.tags) {
    const tagsLower = alert.tags.map((t) => t.toLowerCase());
    if (tagsLower.includes('sigma')) return 'sigma';
    if (tagsLower.includes('edr') || tagsLower.includes('edr_alert')) return 'edr_alert';
    if (tagsLower.includes('siem') || tagsLower.includes('siem_correlation')) return 'siem_correlation';
    if (tagsLower.includes('webhook')) return 'webhook';
    if (tagsLower.includes('manual')) return 'manual';
  }

  // Check event dataset/module as fallback
  if (alert.event.dataset) {
    const ds = alert.event.dataset.toLowerCase();
    if (ds.includes('sigma')) return 'sigma';
    if (ds.includes('edr')) return 'edr_alert';
    if (ds.includes('siem')) return 'siem_correlation';
  }

  return undefined;
}

/**
 * Extract the platform from an AlertEvent based on host OS fields.
 */
function inferPlatform(alert: AlertEvent): string | undefined {
  const osPlatform = alert.host?.os?.platform?.toLowerCase();
  if (osPlatform) return osPlatform;

  const osFamily = alert.host?.os?.family?.toLowerCase();
  if (osFamily) return osFamily;

  const osName = alert.host?.os?.name?.toLowerCase();
  if (!osName) return undefined;

  if (osName.includes('windows')) return 'windows';
  if (osName.includes('linux') || osName.includes('ubuntu') || osName.includes('centos') || osName.includes('debian')) return 'linux';
  if (osName.includes('macos') || osName.includes('mac os') || osName.includes('darwin')) return 'macos';

  return undefined;
}

/**
 * Extract MITRE ATT&CK technique IDs from an AlertEvent.
 */
function extractMitreTechniques(alert: AlertEvent): string[] {
  return alert.threat?.technique?.id ?? [];
}

// ---------------------------------------------------------------------------
// Main Entry Point
// ---------------------------------------------------------------------------

/**
 * Evaluate whether an incoming alert matches a playbook's trigger conditions.
 *
 * Evaluation order:
 * 1. Check event kind -- if the event is not an 'alert', it does not match
 *    alert-triggered playbooks (unless the trigger has no constraints).
 * 2. Check detection source overlap.
 * 3. Check MITRE technique overlap.
 * 4. Check platform overlap.
 * 5. Check severity filter.
 * 6. Evaluate any additional user-defined conditions (from trigger conditions
 *    field, if present).
 *
 * If the trigger has no constraints (empty arrays for all filter fields),
 * the trigger matches any alert.
 *
 * @param trigger - The playbook's RunbookTrigger definition
 * @param alert - The incoming ECS-normalized alert event
 * @param extraConditions - Optional additional TriggerCondition to evaluate
 * @returns TriggerResult with match status and details
 */
export function evaluateTrigger(
  trigger: RunbookTrigger,
  alert: AlertEvent,
  extraConditions?: TriggerCondition,
): TriggerResult {
  let conditionsEvaluated = 0;
  let conditionsPassed = 0;
  const reasons: string[] = [];

  // ---- 1. Event kind check ----
  // If the alert's event.kind is not 'alert', only match if the trigger
  // has no meaningful constraints (acts as a wildcard trigger).
  const hasConstraints =
    trigger.detection_sources.length > 0 ||
    trigger.mitre_techniques.length > 0 ||
    trigger.platforms.length > 0 ||
    (trigger.severity && trigger.severity.length > 0);

  if (alert.event.kind !== 'alert' && hasConstraints) {
    return {
      matched: false,
      trigger_type: 'alert',
      conditions_evaluated: 1,
      conditions_passed: 0,
      reason: `Event kind '${alert.event.kind}' is not 'alert'`,
    };
  }

  // ---- 2. Detection source check ----
  if (trigger.detection_sources.length > 0) {
    conditionsEvaluated++;
    const alertSource = inferDetectionSource(alert);
    if (alertSource && trigger.detection_sources.includes(alertSource)) {
      conditionsPassed++;
    } else {
      reasons.push(
        `Detection source '${alertSource ?? 'unknown'}' not in [${trigger.detection_sources.join(', ')}]`,
      );
    }
  }

  // ---- 3. MITRE technique check ----
  if (trigger.mitre_techniques.length > 0) {
    conditionsEvaluated++;
    const alertTechniques = extractMitreTechniques(alert);

    // Match if any alert technique matches any trigger technique.
    // Support parent technique matching: trigger T1059 matches alert T1059.001.
    const techniqueMatched = alertTechniques.some((alertTech) =>
      trigger.mitre_techniques.some((triggerTech) => {
        // Exact match
        if (alertTech === triggerTech) return true;
        // Parent match: alert T1059.001 matches trigger T1059
        if (alertTech.startsWith(triggerTech + '.')) return true;
        return false;
      }),
    );

    if (techniqueMatched) {
      conditionsPassed++;
    } else {
      reasons.push(
        `MITRE techniques [${alertTechniques.join(', ') || 'none'}] do not match [${trigger.mitre_techniques.join(', ')}]`,
      );
    }
  }

  // ---- 4. Platform check ----
  if (trigger.platforms.length > 0) {
    conditionsEvaluated++;
    const alertPlatform = inferPlatform(alert);

    if (alertPlatform && trigger.platforms.includes(alertPlatform as typeof trigger.platforms[number])) {
      conditionsPassed++;
    } else {
      reasons.push(
        `Platform '${alertPlatform ?? 'unknown'}' not in [${trigger.platforms.join(', ')}]`,
      );
    }
  }

  // ---- 5. Severity check ----
  if (trigger.severity && trigger.severity.length > 0) {
    conditionsEvaluated++;
    const alertSeverity = mapSeverity(alert.event.severity);

    if (trigger.severity.includes(alertSeverity)) {
      conditionsPassed++;
    } else {
      reasons.push(
        `Severity '${alertSeverity}' (numeric: ${alert.event.severity}) not in [${trigger.severity.join(', ')}]`,
      );
    }
  }

  // ---- 6. Extra conditions (user-defined) ----
  if (extraConditions) {
    const alertData = alert as unknown as Record<string, unknown>;
    const extraResult = evaluateConditionTree(extraConditions, alertData);
    conditionsEvaluated += extraResult.evaluated;
    conditionsPassed += extraResult.passed;

    if (extraResult.passed < extraResult.evaluated) {
      reasons.push('Extra conditions not fully satisfied');
    }
  }

  // ---- Determine overall match ----
  // If no conditions were evaluated (empty trigger), match everything
  if (conditionsEvaluated === 0) {
    return {
      matched: true,
      trigger_type: 'alert',
      conditions_evaluated: 0,
      conditions_passed: 0,
    };
  }

  // All conditions must pass (AND logic across the trigger fields)
  const matched = conditionsPassed === conditionsEvaluated;

  return {
    matched,
    trigger_type: 'alert',
    conditions_evaluated: conditionsEvaluated,
    conditions_passed: conditionsPassed,
    reason: matched ? undefined : reasons.join('; '),
  };
}

// ---------------------------------------------------------------------------
// Condition Tree Counter
// ---------------------------------------------------------------------------

/**
 * Evaluate a condition tree and return counts of evaluated and passed conditions.
 * This is used to integrate user-defined conditions into the TriggerResult counters.
 */
function evaluateConditionTree(
  condition: TriggerCondition,
  data: Record<string, unknown>,
): { evaluated: number; passed: number } {
  // Branch condition
  if (condition.logic && condition.conditions) {
    let totalEvaluated = 0;
    let totalPassed = 0;

    for (const sub of condition.conditions) {
      const result = evaluateConditionTree(sub, data);
      totalEvaluated += result.evaluated;
      totalPassed += result.passed;
    }

    // The overall branch result
    const branchResult = evaluateCondition(condition, data);
    // We count the branch itself as one evaluated condition
    return {
      evaluated: 1,
      passed: branchResult ? 1 : 0,
    };
  }

  // Leaf condition
  if (condition.field && condition.operator) {
    const result = evaluateCondition(condition, data);
    return {
      evaluated: 1,
      passed: result ? 1 : 0,
    };
  }

  // Malformed: count as evaluated but not passed
  return { evaluated: 1, passed: 0 };
}

// ---------------------------------------------------------------------------
// Utility Exports
// ---------------------------------------------------------------------------

/**
 * Convert an AlertEvent to a flat Record for condition evaluation.
 * Useful when calling evaluateCondition directly against alert data.
 */
export function alertToRecord(alert: AlertEvent): Record<string, unknown> {
  return alert as unknown as Record<string, unknown>;
}

/**
 * Build a TriggerCondition from a simple key-value map.
 * Each entry becomes an 'eq' condition, combined with 'and' logic.
 *
 * @example
 * ```typescript
 * const condition = buildSimpleConditions({
 *   'event.kind': 'alert',
 *   'event.severity': 80,
 * });
 * // => { logic: 'and', conditions: [
 * //   { field: 'event.kind', operator: 'eq', value: 'alert' },
 * //   { field: 'event.severity', operator: 'eq', value: 80 },
 * // ]}
 * ```
 */
export function buildSimpleConditions(
  fields: Record<string, unknown>,
): TriggerCondition {
  const conditions: TriggerCondition[] = Object.entries(fields).map(
    ([field, value]) => ({
      field,
      operator: 'eq' as TriggerOperator,
      value,
    }),
  );

  if (conditions.length === 1) {
    return conditions[0]!;
  }

  return {
    logic: 'and',
    conditions,
  };
}
