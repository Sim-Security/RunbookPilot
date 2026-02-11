import { describe, it, expect } from 'vitest';
import {
  evaluateTrigger,
  evaluateCondition,
  getFieldValue,
  alertToRecord,
  buildSimpleConditions,
} from '../../../src/engine/trigger-evaluator.ts';
import type { TriggerCondition } from '../../../src/engine/trigger-evaluator.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';
import type { RunbookTrigger } from '../../../src/types/playbook.ts';

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

function makeTrigger(overrides: Partial<RunbookTrigger> = {}): RunbookTrigger {
  return {
    detection_sources: [],
    mitre_techniques: [],
    platforms: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// getFieldValue
// ---------------------------------------------------------------------------

describe('getFieldValue', () => {
  it('resolves simple top-level field', () => {
    const data = { name: 'test' };
    expect(getFieldValue(data, 'name')).toBe('test');
  });

  it('resolves dot-notation nested field', () => {
    const data = { event: { kind: 'alert', category: ['malware'] } };
    expect(getFieldValue(data, 'event.kind')).toBe('alert');
  });

  it('resolves deeply nested fields', () => {
    const data = { a: { b: { c: { d: 42 } } } };
    expect(getFieldValue(data, 'a.b.c.d')).toBe(42);
  });

  it('resolves array indexing notation', () => {
    const data = { items: ['alpha', 'beta', 'gamma'] };
    expect(getFieldValue(data, 'items[0]')).toBe('alpha');
    expect(getFieldValue(data, 'items[1]')).toBe('beta');
    expect(getFieldValue(data, 'items[2]')).toBe('gamma');
  });

  it('resolves nested field after array index', () => {
    const data = { steps: [{ name: 'first' }, { name: 'second' }] };
    expect(getFieldValue(data, 'steps[0].name')).toBe('first');
    expect(getFieldValue(data, 'steps[1].name')).toBe('second');
  });

  it('returns undefined for missing top-level field', () => {
    const data = { name: 'test' };
    expect(getFieldValue(data, 'missing')).toBeUndefined();
  });

  it('returns undefined for missing nested field', () => {
    const data = { event: { kind: 'alert' } };
    expect(getFieldValue(data, 'event.missing.deep')).toBeUndefined();
  });

  it('returns undefined when accessing array index on non-array', () => {
    const data = { name: 'test' };
    expect(getFieldValue(data, 'name[0]')).toBeUndefined();
  });

  it('returns undefined when array index is out of bounds', () => {
    const data = { items: ['a', 'b'] };
    expect(getFieldValue(data, 'items[5]')).toBeUndefined();
  });

  it('returns undefined when traversing through null', () => {
    const data = { parent: null } as Record<string, unknown>;
    expect(getFieldValue(data, 'parent.child')).toBeUndefined();
  });

  it('returns undefined when traversing through a primitive', () => {
    const data = { count: 42 };
    expect(getFieldValue(data, 'count.nested')).toBeUndefined();
  });

  it('returns the whole nested object when path stops at object', () => {
    const data = { event: { kind: 'alert', severity: 80 } };
    const result = getFieldValue(data, 'event');
    expect(result).toEqual({ kind: 'alert', severity: 80 });
  });
});

// ---------------------------------------------------------------------------
// evaluateCondition -- operators
// ---------------------------------------------------------------------------

describe('evaluateCondition - operators', () => {
  const data = {
    event: { kind: 'alert', severity: 80 },
    name: 'test-alert',
    tags: ['sigma', 'edr', 'critical'],
    description: 'A suspicious process was detected on the host',
    count: 5,
    missing_field: null as unknown,
  };

  it('eq: matches equal values', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'eq', value: 'alert' };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('eq: fails on unequal values', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'eq', value: 'event' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('ne: matches unequal values', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'ne', value: 'metric' };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('ne: fails on equal values', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'ne', value: 'alert' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('gt: matches when field > value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'gt', value: 50 };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('gt: fails when field <= value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'gt', value: 80 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('gt: returns false for non-numeric field', () => {
    const cond: TriggerCondition = { field: 'name', operator: 'gt', value: 5 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('lt: matches when field < value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'lt', value: 100 };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('lt: fails when field >= value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'lt', value: 80 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('gte: matches when field >= value (equal)', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'gte', value: 80 };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('gte: matches when field >= value (greater)', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'gte', value: 50 };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('gte: fails when field < value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'gte', value: 90 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('lte: matches when field <= value (equal)', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'lte', value: 80 };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('lte: fails when field > value', () => {
    const cond: TriggerCondition = { field: 'event.severity', operator: 'lte', value: 70 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('in: matches when field value is in expected array', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'in', value: ['alert', 'event'] };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('in: fails when field value is not in expected array', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'in', value: ['metric', 'event'] };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('in: returns false when expected value is not an array', () => {
    const cond: TriggerCondition = { field: 'event.kind', operator: 'in', value: 'alert' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('contains: matches string contains substring', () => {
    const cond: TriggerCondition = { field: 'description', operator: 'contains', value: 'suspicious' };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('contains: fails when string does not contain substring', () => {
    const cond: TriggerCondition = { field: 'description', operator: 'contains', value: 'benign' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('contains: matches array contains element', () => {
    const cond: TriggerCondition = { field: 'tags', operator: 'contains', value: 'sigma' };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('contains: fails when array does not contain element', () => {
    const cond: TriggerCondition = { field: 'tags', operator: 'contains', value: 'yara' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('contains: returns false for non-string/non-array field', () => {
    const cond: TriggerCondition = { field: 'count', operator: 'contains', value: 5 };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('matches: matches regex pattern', () => {
    const cond: TriggerCondition = { field: 'description', operator: 'matches', value: '^A suspicious.*host$' };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('matches: fails when regex does not match', () => {
    const cond: TriggerCondition = { field: 'description', operator: 'matches', value: '^benign' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('matches: returns false for invalid regex', () => {
    const cond: TriggerCondition = { field: 'description', operator: 'matches', value: '[invalid(' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('matches: returns false for non-string field', () => {
    const cond: TriggerCondition = { field: 'count', operator: 'matches', value: '5' };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('exists: returns true when field exists (with expectedValue=true)', () => {
    const cond: TriggerCondition = { field: 'name', operator: 'exists', value: true };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('exists: returns false when field is null (with expectedValue=true)', () => {
    const cond: TriggerCondition = { field: 'missing_field', operator: 'exists', value: true };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('exists: returns false when field is missing (with expectedValue=true)', () => {
    const cond: TriggerCondition = { field: 'nonexistent', operator: 'exists', value: true };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('exists: returns true when field is missing (with expectedValue=false)', () => {
    const cond: TriggerCondition = { field: 'nonexistent', operator: 'exists', value: false };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('exists: returns true when field is null (with expectedValue=false)', () => {
    const cond: TriggerCondition = { field: 'missing_field', operator: 'exists', value: false };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('exists: defaults to checking existence when value is not false', () => {
    const cond: TriggerCondition = { field: 'name', operator: 'exists', value: undefined };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('returns false for malformed condition with no field/operator or logic', () => {
    const cond: TriggerCondition = {};
    expect(evaluateCondition(cond, data)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// evaluateCondition -- logical combinators
// ---------------------------------------------------------------------------

describe('evaluateCondition - logic', () => {
  const data = {
    event: { kind: 'alert', severity: 80 },
    name: 'test',
  };

  it('and: returns true when all sub-conditions pass', () => {
    const cond: TriggerCondition = {
      logic: 'and',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'alert' },
        { field: 'event.severity', operator: 'gte', value: 50 },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('and: returns false when any sub-condition fails', () => {
    const cond: TriggerCondition = {
      logic: 'and',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'alert' },
        { field: 'event.severity', operator: 'gte', value: 90 },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('or: returns true when at least one sub-condition passes', () => {
    const cond: TriggerCondition = {
      logic: 'or',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'metric' },
        { field: 'event.severity', operator: 'gte', value: 50 },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('or: returns false when no sub-conditions pass', () => {
    const cond: TriggerCondition = {
      logic: 'or',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'metric' },
        { field: 'event.severity', operator: 'gte', value: 90 },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('not: negates the first sub-condition (truthy becomes false)', () => {
    const cond: TriggerCondition = {
      logic: 'not',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'alert' },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(false);
  });

  it('not: negates the first sub-condition (falsy becomes true)', () => {
    const cond: TriggerCondition = {
      logic: 'not',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'metric' },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('not: returns true when no sub-conditions provided', () => {
    const cond: TriggerCondition = {
      logic: 'not',
      conditions: [],
    };
    expect(evaluateCondition(cond, data)).toBe(true);
  });

  it('nested logic: and containing or', () => {
    const cond: TriggerCondition = {
      logic: 'and',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'alert' },
        {
          logic: 'or',
          conditions: [
            { field: 'event.severity', operator: 'gte', value: 90 },
            { field: 'name', operator: 'eq', value: 'test' },
          ],
        },
      ],
    };
    expect(evaluateCondition(cond, data)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// evaluateTrigger
// ---------------------------------------------------------------------------

describe('evaluateTrigger', () => {
  it('empty trigger matches any alert', () => {
    const trigger = makeTrigger();
    const alert = makeAlert();
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
    expect(result.trigger_type).toBe('alert');
    expect(result.conditions_evaluated).toBe(0);
    expect(result.conditions_passed).toBe(0);
  });

  it('rejects non-alert events when trigger has constraints', () => {
    const trigger = makeTrigger({ detection_sources: ['sigma'] });
    const alert = makeAlert({ event: { kind: 'event', category: [], type: [], severity: 50 } });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain("not 'alert'");
  });

  it('allows non-alert events when trigger has no constraints', () => {
    const trigger = makeTrigger();
    const alert = makeAlert({ event: { kind: 'event', category: [], type: [], severity: 50 } });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('matches detection source: detectforge', () => {
    const trigger = makeTrigger({ detection_sources: ['detectforge'] });
    const alert = makeAlert({
      'x-detectforge': {
        rule_id: 'df-001',
        rule_name: 'Test',
        rule_version: '1.0',
        generated_at: '2026-02-11T10:00:00.000Z',
        confidence: 'high',
      },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
    expect(result.conditions_passed).toBe(1);
  });

  it('matches detection source: sigma (from tags)', () => {
    const trigger = makeTrigger({ detection_sources: ['sigma'] });
    const alert = makeAlert({ tags: ['sigma'] });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('fails detection source mismatch', () => {
    const trigger = makeTrigger({ detection_sources: ['sigma'] });
    const alert = makeAlert({ tags: ['edr'] });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain('Detection source');
  });

  it('matches MITRE technique: exact match', () => {
    const trigger = makeTrigger({ mitre_techniques: ['T1003.001'] });
    const alert = makeAlert({
      threat: {
        framework: 'MITRE ATT&CK',
        technique: { id: ['T1003.001'], name: ['LSASS Memory'] },
      },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('matches MITRE technique: parent match (T1059 matches T1059.001)', () => {
    const trigger = makeTrigger({ mitre_techniques: ['T1059'] });
    const alert = makeAlert({
      threat: {
        framework: 'MITRE ATT&CK',
        technique: { id: ['T1059.001'], name: ['PowerShell'] },
      },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('fails MITRE technique: no overlap', () => {
    const trigger = makeTrigger({ mitre_techniques: ['T1003.001'] });
    const alert = makeAlert({
      threat: {
        framework: 'MITRE ATT&CK',
        technique: { id: ['T1059.001'], name: ['PowerShell'] },
      },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain('MITRE techniques');
  });

  it('matches platform: windows (from host.os.platform)', () => {
    const trigger = makeTrigger({ platforms: ['windows'] });
    const alert = makeAlert({
      host: { os: { platform: 'windows' } },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('matches platform: linux (from host.os.name)', () => {
    const trigger = makeTrigger({ platforms: ['linux'] });
    const alert = makeAlert({
      host: { os: { name: 'Ubuntu 22.04' } },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('fails platform mismatch', () => {
    const trigger = makeTrigger({ platforms: ['linux'] });
    const alert = makeAlert({
      host: { os: { platform: 'windows' } },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain('Platform');
  });

  it('matches severity filter', () => {
    const trigger = makeTrigger({ severity: ['critical'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 80 } });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
  });

  it('fails severity filter mismatch', () => {
    const trigger = makeTrigger({ severity: ['low'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 80 } });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain('Severity');
  });

  it('matches all conditions together (detection_sources + mitre + platform + severity)', () => {
    const trigger = makeTrigger({
      detection_sources: ['sigma'],
      mitre_techniques: ['T1003.001'],
      platforms: ['windows'],
      severity: ['critical'],
    });
    const alert = makeAlert({
      event: { kind: 'alert', category: ['credential-access'], type: ['info'], severity: 80 },
      tags: ['sigma'],
      threat: {
        framework: 'MITRE ATT&CK',
        technique: { id: ['T1003.001'], name: ['LSASS Memory'] },
      },
      host: { os: { platform: 'windows' } },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(true);
    expect(result.conditions_evaluated).toBe(4);
    expect(result.conditions_passed).toBe(4);
  });

  it('fails when one condition of multiple fails', () => {
    const trigger = makeTrigger({
      detection_sources: ['sigma'],
      mitre_techniques: ['T1003.001'],
      platforms: ['linux'],  // <-- mismatch
    });
    const alert = makeAlert({
      tags: ['sigma'],
      threat: {
        framework: 'MITRE ATT&CK',
        technique: { id: ['T1003.001'], name: ['LSASS Memory'] },
      },
      host: { os: { platform: 'windows' } },
    });
    const result = evaluateTrigger(trigger, alert);

    expect(result.matched).toBe(false);
    expect(result.conditions_evaluated).toBe(3);
    expect(result.conditions_passed).toBe(2);
  });

  it('evaluates extra conditions when provided', () => {
    const trigger = makeTrigger();
    const alert = makeAlert();
    const extraConditions: TriggerCondition = {
      field: 'event.kind',
      operator: 'eq',
      value: 'alert',
    };
    const result = evaluateTrigger(trigger, alert, extraConditions);

    expect(result.matched).toBe(true);
    expect(result.conditions_evaluated).toBe(1);
    expect(result.conditions_passed).toBe(1);
  });

  it('fails extra conditions when they do not match', () => {
    const trigger = makeTrigger();
    const alert = makeAlert();
    const extraConditions: TriggerCondition = {
      field: 'event.kind',
      operator: 'eq',
      value: 'metric',
    };
    const result = evaluateTrigger(trigger, alert, extraConditions);

    expect(result.matched).toBe(false);
    expect(result.reason).toContain('Extra conditions');
  });

  it('severity mapping: 0-24 = low', () => {
    const trigger = makeTrigger({ severity: ['low'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 20 } });
    expect(evaluateTrigger(trigger, alert).matched).toBe(true);
  });

  it('severity mapping: 25-49 = medium', () => {
    const trigger = makeTrigger({ severity: ['medium'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 30 } });
    expect(evaluateTrigger(trigger, alert).matched).toBe(true);
  });

  it('severity mapping: 50-74 = high', () => {
    const trigger = makeTrigger({ severity: ['high'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 60 } });
    expect(evaluateTrigger(trigger, alert).matched).toBe(true);
  });

  it('severity mapping: 75-100 = critical', () => {
    const trigger = makeTrigger({ severity: ['critical'] });
    const alert = makeAlert({ event: { kind: 'alert', category: [], type: [], severity: 90 } });
    expect(evaluateTrigger(trigger, alert).matched).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// alertToRecord
// ---------------------------------------------------------------------------

describe('alertToRecord', () => {
  it('converts AlertEvent to a Record for condition evaluation', () => {
    const alert = makeAlert();
    const record = alertToRecord(alert);

    expect(record['@timestamp']).toBe('2026-02-11T10:00:00.000Z');
    expect((record['event'] as Record<string, unknown>)['kind']).toBe('alert');
  });
});

// ---------------------------------------------------------------------------
// buildSimpleConditions
// ---------------------------------------------------------------------------

describe('buildSimpleConditions', () => {
  it('returns a single eq condition for one entry', () => {
    const cond = buildSimpleConditions({ 'event.kind': 'alert' });

    expect(cond.field).toBe('event.kind');
    expect(cond.operator).toBe('eq');
    expect(cond.value).toBe('alert');
  });

  it('returns an and-combined condition for multiple entries', () => {
    const cond = buildSimpleConditions({
      'event.kind': 'alert',
      'event.severity': 80,
    });

    expect(cond.logic).toBe('and');
    expect(cond.conditions).toHaveLength(2);
    expect(cond.conditions![0]!.field).toBe('event.kind');
    expect(cond.conditions![1]!.field).toBe('event.severity');
  });
});
