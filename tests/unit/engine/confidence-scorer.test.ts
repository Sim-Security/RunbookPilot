import { describe, it, expect } from 'vitest';
import {
  calculateStepConfidence,
  calculateOverallConfidence,
  getConfidenceDisplay,
  extractDetectForgeConfidence,
  extractDetectForgeRuleId,
  formatConfidenceForDisplay,
} from '../../../src/engine/confidence-scorer.ts';
import type { ConfidenceBreakdown, ConfidenceDisplay } from '../../../src/types/simulation.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';
import type { HealthCheckResult } from '../../../src/adapters/adapter-interface.ts';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeAlert(overrides: Partial<AlertEvent> = {}): AlertEvent {
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

// ---------------------------------------------------------------------------
// calculateStepConfidence
// ---------------------------------------------------------------------------

describe('calculateStepConfidence', () => {
  it('calculates with all factors provided', () => {
    const healthResult: HealthCheckResult = {
      status: 'healthy',
      checkedAt: new Date().toISOString(),
    };

    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: healthResult,
      rollbackAvailable: true,
      historicalSuccessRate: 0.9,
      detectforgeConfidence: 0.8,
    });

    // parameter_validation: 1.0 * 0.30 = 0.30
    // adapter_health: 1.0 * 0.25 = 0.25
    // rollback_available: 1.0 * 0.15 = 0.15
    // historical_success_rate: 0.9 * 0.15 = 0.135
    // detectforge_confidence: 0.8 * 0.15 = 0.12
    // total = 0.955
    expect(breakdown.overall).toBeCloseTo(0.955, 3);
    expect(breakdown.parameter_validation).toBe(1.0);
    expect(breakdown.adapter_health).toBe(1.0);
    expect(breakdown.rollback_available).toBe(1.0);
    expect(breakdown.historical_success_rate).toBe(0.9);
    expect(breakdown.detectforge_confidence).toBe(0.8);
  });

  it('uses defaults when optional fields omitted', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
    });

    // parameter_validation: 1.0 * 0.30 = 0.30
    // adapter_health: 0.0 * 0.25 = 0.00 (no health result -> 0.0)
    // rollback_available: 0.0 * 0.15 = 0.00
    // historical_success_rate: 0.5 * 0.15 = 0.075
    // detectforge_confidence: 0.5 * 0.15 = 0.075
    // total = 0.45
    expect(breakdown.overall).toBeCloseTo(0.45, 3);
    expect(breakdown.parameter_validation).toBe(1.0);
    expect(breakdown.adapter_health).toBe(0.0);
    expect(breakdown.rollback_available).toBe(0.0);
    expect(breakdown.historical_success_rate).toBeUndefined();
    expect(breakdown.detectforge_confidence).toBeUndefined();
  });

  it('scores parameter_validation as 0.0 when failed', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: false,
      rollbackAvailable: false,
    });

    expect(breakdown.parameter_validation).toBe(0.0);
    // overall will be lower
    expect(breakdown.overall).toBeLessThan(0.3);
  });

  it('scores adapter_health as 1.0 for healthy', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: { status: 'healthy', checkedAt: new Date().toISOString() },
      rollbackAvailable: false,
    });

    expect(breakdown.adapter_health).toBe(1.0);
  });

  it('scores adapter_health as 0.5 for degraded', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: { status: 'degraded', checkedAt: new Date().toISOString() },
      rollbackAvailable: false,
    });

    expect(breakdown.adapter_health).toBe(0.5);
  });

  it('scores adapter_health as 0.0 for unhealthy', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: { status: 'unhealthy', checkedAt: new Date().toISOString() },
      rollbackAvailable: false,
    });

    expect(breakdown.adapter_health).toBe(0.0);
  });

  it('scores adapter_health as 0.0 for unknown', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: { status: 'unknown', checkedAt: new Date().toISOString() },
      rollbackAvailable: false,
    });

    expect(breakdown.adapter_health).toBe(0.0);
  });

  it('scores adapter_health as 0.0 when no health result provided', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
    });

    expect(breakdown.adapter_health).toBe(0.0);
  });

  it('scores rollback_available as 1.0 when true', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: true,
    });

    expect(breakdown.rollback_available).toBe(1.0);
  });

  it('scores rollback_available as 0.0 when false', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
    });

    expect(breakdown.rollback_available).toBe(0.0);
  });

  it('includes historical_success_rate in breakdown when provided', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
      historicalSuccessRate: 0.75,
    });

    expect(breakdown.historical_success_rate).toBe(0.75);
  });

  it('omits historical_success_rate from breakdown when not provided', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
    });

    expect(breakdown.historical_success_rate).toBeUndefined();
  });

  it('includes detectforge_confidence in breakdown when provided', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
      detectforgeConfidence: 0.6,
    });

    expect(breakdown.detectforge_confidence).toBe(0.6);
  });

  it('omits detectforge_confidence from breakdown when not provided', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      rollbackAvailable: false,
    });

    expect(breakdown.detectforge_confidence).toBeUndefined();
  });

  it('clamps overall to [0.0, 1.0]', () => {
    // All maxed out factors
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: true,
      adapterHealth: { status: 'healthy', checkedAt: new Date().toISOString() },
      rollbackAvailable: true,
      historicalSuccessRate: 1.0,
      detectforgeConfidence: 1.0,
    });

    expect(breakdown.overall).toBeLessThanOrEqual(1.0);
    expect(breakdown.overall).toBeGreaterThanOrEqual(0.0);
  });

  it('returns lowest overall when all factors are worst case', () => {
    const breakdown = calculateStepConfidence({
      parameterValidationPassed: false,
      adapterHealth: { status: 'unhealthy', checkedAt: new Date().toISOString() },
      rollbackAvailable: false,
      historicalSuccessRate: 0.0,
      detectforgeConfidence: 0.0,
    });

    expect(breakdown.overall).toBe(0.0);
  });
});

// ---------------------------------------------------------------------------
// calculateOverallConfidence
// ---------------------------------------------------------------------------

describe('calculateOverallConfidence', () => {
  it('returns mean of breakdown overall scores', () => {
    const breakdowns: ConfidenceBreakdown[] = [
      { parameter_validation: 1.0, adapter_health: 1.0, rollback_available: 1.0, overall: 0.8 },
      { parameter_validation: 1.0, adapter_health: 0.5, rollback_available: 0.0, overall: 0.6 },
      { parameter_validation: 0.0, adapter_health: 0.0, rollback_available: 0.0, overall: 0.2 },
    ];

    const result = calculateOverallConfidence(breakdowns);

    // mean = (0.8 + 0.6 + 0.2) / 3 = 0.5333...
    expect(result).toBeCloseTo(0.5333, 3);
  });

  it('returns 0.0 for empty array', () => {
    const result = calculateOverallConfidence([]);
    expect(result).toBe(0.0);
  });

  it('returns the overall score for a single breakdown', () => {
    const breakdowns: ConfidenceBreakdown[] = [
      { parameter_validation: 1.0, adapter_health: 1.0, rollback_available: 1.0, overall: 0.75 },
    ];

    const result = calculateOverallConfidence(breakdowns);
    expect(result).toBeCloseTo(0.75, 3);
  });

  it('is clamped to [0.0, 1.0]', () => {
    const breakdowns: ConfidenceBreakdown[] = [
      { parameter_validation: 1.0, adapter_health: 1.0, rollback_available: 1.0, overall: 1.0 },
      { parameter_validation: 1.0, adapter_health: 1.0, rollback_available: 1.0, overall: 1.0 },
    ];

    const result = calculateOverallConfidence(breakdowns);
    expect(result).toBeLessThanOrEqual(1.0);
    expect(result).toBeGreaterThanOrEqual(0.0);
  });
});

// ---------------------------------------------------------------------------
// getConfidenceDisplay
// ---------------------------------------------------------------------------

describe('getConfidenceDisplay', () => {
  it('returns high/green for score >= 0.7', () => {
    const display = getConfidenceDisplay(0.85);

    expect(display.label).toBe('high');
    expect(display.color).toBe('green');
    expect(display.score).toBe(0.85);
  });

  it('returns high/green for score exactly 0.7', () => {
    const display = getConfidenceDisplay(0.7);

    expect(display.label).toBe('high');
    expect(display.color).toBe('green');
  });

  it('returns medium/yellow for score >= 0.4 and < 0.7', () => {
    const display = getConfidenceDisplay(0.55);

    expect(display.label).toBe('medium');
    expect(display.color).toBe('yellow');
  });

  it('returns medium/yellow for score exactly 0.4', () => {
    const display = getConfidenceDisplay(0.4);

    expect(display.label).toBe('medium');
    expect(display.color).toBe('yellow');
  });

  it('returns low/red for score < 0.4', () => {
    const display = getConfidenceDisplay(0.2);

    expect(display.label).toBe('low');
    expect(display.color).toBe('red');
  });

  it('returns low/red for score 0.0', () => {
    const display = getConfidenceDisplay(0.0);

    expect(display.label).toBe('low');
    expect(display.color).toBe('red');
  });

  it('returns high/green for score 1.0', () => {
    const display = getConfidenceDisplay(1.0);

    expect(display.label).toBe('high');
    expect(display.color).toBe('green');
  });

  it('defaults source to "combined"', () => {
    const display = getConfidenceDisplay(0.5);

    expect(display.source).toBe('combined');
  });

  it('uses provided source', () => {
    const display = getConfidenceDisplay(0.5, 'detectforge');

    expect(display.source).toBe('detectforge');
  });

  it('includes rule_id when provided', () => {
    const display = getConfidenceDisplay(0.8, 'detectforge', 'sigma-1234');

    expect(display.rule_id).toBe('sigma-1234');
  });

  it('omits rule_id when not provided', () => {
    const display = getConfidenceDisplay(0.8);

    expect(display.rule_id).toBeUndefined();
  });

  it('returns correct score in display object', () => {
    const display = getConfidenceDisplay(0.6789);

    expect(display.score).toBe(0.6789);
  });
});

// ---------------------------------------------------------------------------
// extractDetectForgeConfidence
// ---------------------------------------------------------------------------

describe('extractDetectForgeConfidence', () => {
  it('maps "low" to 0.3', () => {
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'df-001',
        rule_name: 'Test Rule',
        rule_version: '1.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'low',
      },
    });

    expect(extractDetectForgeConfidence(alert)).toBe(0.3);
  });

  it('maps "medium" to 0.6', () => {
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'df-002',
        rule_name: 'Test Rule',
        rule_version: '1.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'medium',
      },
    });

    expect(extractDetectForgeConfidence(alert)).toBe(0.6);
  });

  it('maps "high" to 0.9', () => {
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'df-003',
        rule_name: 'Test Rule',
        rule_version: '1.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'high',
      },
    });

    expect(extractDetectForgeConfidence(alert)).toBe(0.9);
  });

  it('returns undefined when alert is undefined', () => {
    expect(extractDetectForgeConfidence(undefined)).toBeUndefined();
  });

  it('returns undefined when x-detectforge metadata is absent', () => {
    const alert = makeAlert();
    expect(extractDetectForgeConfidence(alert)).toBeUndefined();
  });

  it('returns undefined for unknown confidence string', () => {
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'df-004',
        rule_name: 'Test Rule',
        rule_version: '1.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'unknown' as 'low',
      },
    });

    expect(extractDetectForgeConfidence(alert)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// extractDetectForgeRuleId
// ---------------------------------------------------------------------------

describe('extractDetectForgeRuleId', () => {
  it('extracts rule_id from alert with x-detectforge metadata', () => {
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'sigma-phish-001',
        rule_name: 'Phishing Detection',
        rule_version: '2.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'high',
      },
    });

    expect(extractDetectForgeRuleId(alert)).toBe('sigma-phish-001');
  });

  it('returns undefined when alert is undefined', () => {
    expect(extractDetectForgeRuleId(undefined)).toBeUndefined();
  });

  it('returns undefined when x-detectforge metadata is absent', () => {
    const alert = makeAlert();
    expect(extractDetectForgeRuleId(alert)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// formatConfidenceForDisplay
// ---------------------------------------------------------------------------

describe('formatConfidenceForDisplay', () => {
  it('formats high confidence correctly', () => {
    const display: ConfidenceDisplay = {
      score: 0.85,
      label: 'high',
      color: 'green',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 85%');
    expect(result).toContain('(HIGH)');
    expect(result).toContain('[green]');
    expect(result).toContain('Source: combined');
  });

  it('formats medium confidence correctly', () => {
    const display: ConfidenceDisplay = {
      score: 0.50,
      label: 'medium',
      color: 'yellow',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 50%');
    expect(result).toContain('(MEDIUM)');
    expect(result).toContain('[yellow]');
  });

  it('formats low confidence correctly', () => {
    const display: ConfidenceDisplay = {
      score: 0.20,
      label: 'low',
      color: 'red',
      source: 'parameter_validation',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 20%');
    expect(result).toContain('(LOW)');
    expect(result).toContain('[red]');
    expect(result).toContain('Source: parameter_validation');
  });

  it('includes rule_id when present', () => {
    const display: ConfidenceDisplay = {
      score: 0.85,
      label: 'high',
      color: 'green',
      source: 'detectforge',
      rule_id: 'sigma-1234',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Source: detectforge');
    expect(result).toContain('(rule: sigma-1234)');
  });

  it('omits rule portion when rule_id is not present', () => {
    const display: ConfidenceDisplay = {
      score: 0.50,
      label: 'medium',
      color: 'yellow',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).not.toContain('(rule:');
  });

  it('rounds percentage correctly', () => {
    const display: ConfidenceDisplay = {
      score: 0.6789,
      label: 'medium',
      color: 'yellow',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 68%');
  });

  it('formats 0% correctly', () => {
    const display: ConfidenceDisplay = {
      score: 0.0,
      label: 'low',
      color: 'red',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 0%');
  });

  it('formats 100% correctly', () => {
    const display: ConfidenceDisplay = {
      score: 1.0,
      label: 'high',
      color: 'green',
      source: 'combined',
    };

    const result = formatConfidenceForDisplay(display);

    expect(result).toContain('Confidence: 100%');
  });
});
