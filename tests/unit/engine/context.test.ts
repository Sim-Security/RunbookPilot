/**
 * Tests for ExecutionContextManager
 *
 * Covers: creation, deep variable access, step output management,
 * step completion tracking, state transitions, error setting,
 * snapshot/restore roundtrip, and edge cases.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { ExecutionContextManager } from '../../../src/engine/context.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';
import type { ExecutionError, ExecutionState } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid alert for testing. */
function makeAlert(overrides?: Partial<AlertEvent>): AlertEvent {
  return {
    '@timestamp': '2026-02-11T10:00:00.000Z',
    event: {
      kind: 'alert',
      category: ['process'],
      type: ['start'],
      severity: 75,
    },
    host: {
      hostname: 'workstation-42',
      name: 'workstation-42',
      id: 'host-abc-123',
      ip: ['10.0.0.42'],
      os: {
        family: 'windows',
        name: 'Windows 11',
        platform: 'windows',
        version: '10.0.22631',
      },
    },
    source: {
      ip: '10.0.0.42',
      port: 49152,
    },
    destination: {
      ip: '198.51.100.23',
      port: 443,
      domain: 'evil.example.com',
    },
    process: {
      pid: 1234,
      name: 'powershell.exe',
      executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell -enc SGVsbG8=',
      parent: { pid: 500, name: 'explorer.exe' },
      hash: { sha256: 'abc123def456' },
    },
    user: {
      name: 'jdoe',
      domain: 'CORP',
      id: 'S-1-5-21-123',
    },
    threat: {
      framework: 'MITRE ATT&CK',
      technique: { id: ['T1059.001'], name: ['PowerShell'] },
      tactic: { id: ['TA0002'], name: ['Execution'] },
    },
    tags: ['suspicious', 'encoded-command'],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ExecutionContextManager', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // -------------------------------------------------------------------------
  // Creation
  // -------------------------------------------------------------------------

  describe('create()', () => {
    it('creates a context with all required fields', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-phishing-001',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      const ctx = mgr.context;
      expect(ctx.execution_id).toBeDefined();
      expect(ctx.execution_id.length).toBeGreaterThan(0);
      expect(ctx.runbook_id).toBe('rb-phishing-001');
      expect(ctx.runbook_version).toBe('1.0.0');
      expect(ctx.mode).toBe('production');
      expect(ctx.started_at).toBeDefined();
      expect(ctx.current_step).toBeUndefined();
      expect(ctx.completed_steps).toEqual([]);
      expect(ctx.variables).toEqual({});
      expect(ctx.state).toBe('idle');
      expect(ctx.error).toBeUndefined();
      expect(ctx.alert).toBeUndefined();
    });

    it('generates a valid UUID for execution_id', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'dry-run',
      });

      // UUID v4 format: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(mgr.executionId).toMatch(uuidRegex);
    });

    it('generates unique execution IDs for each context', () => {
      const mgr1 = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });
      const mgr2 = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr1.executionId).not.toBe(mgr2.executionId);
    });

    it('stores the ISO8601 started_at timestamp', () => {
      const before = new Date().toISOString();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'simulation',
      });
      const after = new Date().toISOString();

      expect(mgr.context.started_at >= before).toBe(true);
      expect(mgr.context.started_at <= after).toBe(true);
    });

    it('stores the alert when provided', () => {
      const alert = makeAlert();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-phishing-001',
        runbook_version: '1.0.0',
        mode: 'production',
        alert,
      });

      expect(mgr.context.alert).toBeDefined();
      expect(mgr.context.alert?.host?.hostname).toBe('workstation-42');
    });

    it('supports all execution modes', () => {
      const modes = ['production', 'simulation', 'dry-run'] as const;
      for (const mode of modes) {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode,
        });
        expect(mgr.context.mode).toBe(mode);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Deep variable access (getVariable)
  // -------------------------------------------------------------------------

  describe('getVariable()', () => {
    describe('alert namespace', () => {
      it('accesses top-level alert fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.@timestamp')).toBe('2026-02-11T10:00:00.000Z');
      });

      it('accesses nested alert host fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.host.hostname')).toBe('workstation-42');
        expect(mgr.getVariable('alert.host.id')).toBe('host-abc-123');
        expect(mgr.getVariable('alert.host.os.family')).toBe('windows');
        expect(mgr.getVariable('alert.host.os.name')).toBe('Windows 11');
      });

      it('accesses alert network fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.source.ip')).toBe('10.0.0.42');
        expect(mgr.getVariable('alert.destination.domain')).toBe('evil.example.com');
        expect(mgr.getVariable('alert.destination.port')).toBe(443);
      });

      it('accesses alert process fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.process.name')).toBe('powershell.exe');
        expect(mgr.getVariable('alert.process.pid')).toBe(1234);
        expect(mgr.getVariable('alert.process.parent.name')).toBe('explorer.exe');
        expect(mgr.getVariable('alert.process.hash.sha256')).toBe('abc123def456');
      });

      it('accesses alert user fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.user.name')).toBe('jdoe');
        expect(mgr.getVariable('alert.user.domain')).toBe('CORP');
      });

      it('accesses alert threat fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.threat.framework')).toBe('MITRE ATT&CK');
        expect(mgr.getVariable('alert.threat.technique.id')).toEqual(['T1059.001']);
      });

      it('accesses alert event severity', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.event.severity')).toBe(75);
        expect(mgr.getVariable('alert.event.kind')).toBe('alert');
      });

      it('accesses alert tags array', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.tags')).toEqual(['suspicious', 'encoded-command']);
      });

      it('returns undefined for missing alert fields', () => {
        const alert = makeAlert();
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          alert,
        });

        expect(mgr.getVariable('alert.file.path')).toBeUndefined();
        expect(mgr.getVariable('alert.host.nonexistent')).toBeUndefined();
      });

      it('returns undefined when no alert is set', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('alert.host.hostname')).toBeUndefined();
      });
    });

    describe('steps namespace', () => {
      it('accesses step output values', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', { score: 85, verdict: 'malicious' });

        expect(mgr.getVariable('steps.step-01.output.score')).toBe(85);
        expect(mgr.getVariable('steps.step-01.output.verdict')).toBe('malicious');
      });

      it('accesses deeply nested step output', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('enrich-ioc', {
          results: {
            virustotal: { positives: 42, total: 70 },
            abuseipdb: { confidence_score: 95 },
          },
        });

        expect(mgr.getVariable('steps.enrich-ioc.output.results.virustotal.positives')).toBe(42);
        expect(mgr.getVariable('steps.enrich-ioc.output.results.abuseipdb.confidence_score')).toBe(95);
      });

      it('returns undefined for non-existent step', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('steps.nonexistent.output')).toBeUndefined();
      });

      it('returns undefined for missing output field', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', { score: 85 });

        expect(mgr.getVariable('steps.step-01.output.nonexistent')).toBeUndefined();
      });

      it('handles primitive step output', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', 'blocked');

        expect(mgr.getVariable('steps.step-01.output')).toBe('blocked');
      });

      it('returns step wrapper object when accessing step-level path', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', { score: 85 });

        const result = mgr.getVariable('steps.step-01');
        expect(result).toEqual({ output: { score: 85 } });
      });

      it('returns undefined for non-output sub-path on step', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', { score: 85 });

        expect(mgr.getVariable('steps.step-01.status')).toBeUndefined();
      });
    });

    describe('context namespace', () => {
      it('accesses top-level context fields', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-phishing-001',
          runbook_version: '2.1.0',
          mode: 'simulation',
        });

        expect(mgr.getVariable('context.execution_id')).toBe(mgr.executionId);
        expect(mgr.getVariable('context.runbook_id')).toBe('rb-phishing-001');
        expect(mgr.getVariable('context.runbook_version')).toBe('2.1.0');
        expect(mgr.getVariable('context.mode')).toBe('simulation');
        expect(mgr.getVariable('context.state')).toBe('idle');
      });

      it('accesses completed_steps from context namespace', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.markStepCompleted('step-01');
        mgr.markStepCompleted('step-02');

        expect(mgr.getVariable('context.completed_steps')).toEqual(['step-01', 'step-02']);
      });

      it('returns undefined for non-existent context field', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('context.nonexistent')).toBeUndefined();
      });
    });

    describe('env namespace', () => {
      it('accesses environment variables', () => {
        vi.stubEnv('TEST_RUNBOOK_VAR', 'hello-runbook');

        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('env.TEST_RUNBOOK_VAR')).toBe('hello-runbook');
      });

      it('returns undefined for unset env var', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('env.DEFINITELY_NOT_SET_XYZ_12345')).toBeUndefined();
      });

      it('returns undefined for env with no key', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('env')).toBeUndefined();
      });
    });

    describe('unknown namespace', () => {
      it('returns undefined for unknown namespace', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        expect(mgr.getVariable('unknown.field')).toBeUndefined();
        expect(mgr.getVariable('foo.bar.baz')).toBeUndefined();
      });
    });

    describe('edge cases', () => {
      it('returns undefined for empty path segments beyond a primitive', () => {
        const mgr = ExecutionContextManager.create({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
        });

        mgr.setStepOutput('step-01', 42);

        // 42 is a primitive; drilling further returns undefined
        expect(mgr.getVariable('steps.step-01.output.deep.path')).toBeUndefined();
      });
    });
  });

  // -------------------------------------------------------------------------
  // Step output management
  // -------------------------------------------------------------------------

  describe('setStepOutput()', () => {
    it('stores an object output', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', { blocked: true, ip: '198.51.100.23' });

      expect(mgr.getVariable('steps.step-01.output.blocked')).toBe(true);
      expect(mgr.getVariable('steps.step-01.output.ip')).toBe('198.51.100.23');
    });

    it('stores a string output', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', 'success');

      expect(mgr.getVariable('steps.step-01.output')).toBe('success');
    });

    it('stores a null output', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', null);

      expect(mgr.getVariable('steps.step-01.output')).toBeNull();
    });

    it('overwrites previous step output', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', { score: 50 });
      mgr.setStepOutput('step-01', { score: 99 });

      expect(mgr.getVariable('steps.step-01.output.score')).toBe(99);
    });

    it('stores outputs for multiple steps independently', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', { action: 'enrich' });
      mgr.setStepOutput('step-02', { action: 'isolate' });
      mgr.setStepOutput('step-03', { action: 'notify' });

      expect(mgr.getVariable('steps.step-01.output.action')).toBe('enrich');
      expect(mgr.getVariable('steps.step-02.output.action')).toBe('isolate');
      expect(mgr.getVariable('steps.step-03.output.action')).toBe('notify');
    });
  });

  // -------------------------------------------------------------------------
  // Step completion tracking
  // -------------------------------------------------------------------------

  describe('step completion tracking', () => {
    it('marks a step as completed', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setCurrentStep('step-01');
      mgr.markStepCompleted('step-01');

      expect(mgr.completedSteps).toEqual(['step-01']);
      expect(mgr.currentStep).toBeUndefined();
    });

    it('tracks multiple completed steps in order', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setCurrentStep('step-01');
      mgr.markStepCompleted('step-01');
      mgr.setCurrentStep('step-02');
      mgr.markStepCompleted('step-02');
      mgr.setCurrentStep('step-03');
      mgr.markStepCompleted('step-03');

      expect(mgr.completedSteps).toEqual(['step-01', 'step-02', 'step-03']);
    });

    it('does not duplicate step in completed_steps', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.markStepCompleted('step-01');
      mgr.markStepCompleted('step-01');

      expect(mgr.completedSteps).toEqual(['step-01']);
    });

    it('clears current_step only if it matches the completed step', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setCurrentStep('step-02');
      mgr.markStepCompleted('step-01'); // different step

      expect(mgr.currentStep).toBe('step-02'); // should not be cleared
      expect(mgr.completedSteps).toContain('step-01');
    });

    it('setCurrentStep updates current_step', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.currentStep).toBeUndefined();

      mgr.setCurrentStep('step-01');
      expect(mgr.currentStep).toBe('step-01');

      mgr.setCurrentStep('step-02');
      expect(mgr.currentStep).toBe('step-02');
    });
  });

  // -------------------------------------------------------------------------
  // State transitions
  // -------------------------------------------------------------------------

  describe('state transitions', () => {
    it('starts in idle state', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.state).toBe('idle');
    });

    it('transitions through valid states', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      const states: ExecutionState[] = [
        'validating',
        'planning',
        'awaiting_approval',
        'executing',
        'completed',
      ];

      for (const state of states) {
        mgr.setState(state);
        expect(mgr.state).toBe(state);
        expect(mgr.context.state).toBe(state);
      }
    });

    it('can transition to failed state', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setState('executing');
      mgr.setState('failed');

      expect(mgr.state).toBe('failed');
    });

    it('can transition to rolling_back state', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setState('executing');
      mgr.setState('rolling_back');

      expect(mgr.state).toBe('rolling_back');
    });

    it('can transition to cancelled state', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setState('awaiting_approval');
      mgr.setState('cancelled');

      expect(mgr.state).toBe('cancelled');
    });
  });

  // -------------------------------------------------------------------------
  // Error setting
  // -------------------------------------------------------------------------

  describe('setError()', () => {
    it('sets an error on the context', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      const error: ExecutionError = {
        code: 'ADAPTER_TIMEOUT',
        message: 'EDR adapter timed out after 30s',
        step_id: 'step-03',
        details: { adapter: 'crowdstrike', timeout_ms: 30000 },
      };

      mgr.setError(error);

      expect(mgr.context.error).toEqual(error);
      expect(mgr.context.error?.code).toBe('ADAPTER_TIMEOUT');
      expect(mgr.context.error?.step_id).toBe('step-03');
    });

    it('error is initially undefined', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.context.error).toBeUndefined();
    });

    it('overwrites a previous error', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setError({ code: 'ERR_A', message: 'First error' });
      mgr.setError({ code: 'ERR_B', message: 'Second error' });

      expect(mgr.context.error?.code).toBe('ERR_B');
      expect(mgr.context.error?.message).toBe('Second error');
    });

    it('error with stack trace is preserved', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      const error: ExecutionError = {
        code: 'UNEXPECTED',
        message: 'Something broke',
        stack: 'Error: Something broke\n    at context.test.ts:123',
      };

      mgr.setError(error);
      expect(mgr.context.error?.stack).toContain('Something broke');
    });
  });

  // -------------------------------------------------------------------------
  // Snapshot and restore roundtrip
  // -------------------------------------------------------------------------

  describe('snapshot()', () => {
    it('returns a serializable copy of the context', () => {
      const alert = makeAlert();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-phishing-001',
        runbook_version: '1.2.0',
        mode: 'production',
        alert,
      });

      mgr.setState('executing');
      mgr.setCurrentStep('step-02');
      mgr.setStepOutput('step-01', { score: 85 });
      mgr.markStepCompleted('step-01');

      const snap = mgr.snapshot();

      expect(snap.execution_id).toBe(mgr.executionId);
      expect(snap.runbook_id).toBe('rb-phishing-001');
      expect(snap.runbook_version).toBe('1.2.0');
      expect(snap.mode).toBe('production');
      expect(snap.state).toBe('executing');
      expect(snap.current_step).toBe('step-02');
      expect(snap.completed_steps).toEqual(['step-01']);
      expect(snap.alert?.host?.hostname).toBe('workstation-42');
    });

    it('snapshot is a deep clone (mutations do not affect original)', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', { score: 50 });
      mgr.markStepCompleted('step-01');

      const snap = mgr.snapshot();

      // Mutate the snapshot
      snap.completed_steps.push('step-99');
      snap.state = 'failed';

      // Original should be unaffected
      expect(mgr.completedSteps).toEqual(['step-01']);
      expect(mgr.state).toBe('idle');
    });

    it('snapshot can be serialized to JSON and back', () => {
      const alert = makeAlert();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'simulation',
        alert,
      });

      mgr.setStepOutput('step-01', { data: [1, 2, 3] });
      mgr.markStepCompleted('step-01');
      mgr.setState('executing');

      const snap = mgr.snapshot();
      const json = JSON.stringify(snap);
      const parsed: unknown = JSON.parse(json);

      expect(parsed).toEqual(snap);
    });
  });

  describe('restore()', () => {
    it('restores a context from a snapshot', () => {
      const alert = makeAlert();
      const original = ExecutionContextManager.create({
        runbook_id: 'rb-phishing-001',
        runbook_version: '2.0.0',
        mode: 'production',
        alert,
      });

      original.setState('executing');
      original.setCurrentStep('step-03');
      original.setStepOutput('step-01', { score: 85 });
      original.setStepOutput('step-02', { blocked: true });
      original.markStepCompleted('step-01');
      original.markStepCompleted('step-02');

      const snap = original.snapshot();
      const restored = ExecutionContextManager.restore(snap);

      expect(restored.executionId).toBe(original.executionId);
      expect(restored.context.runbook_id).toBe('rb-phishing-001');
      expect(restored.context.runbook_version).toBe('2.0.0');
      expect(restored.context.mode).toBe('production');
      expect(restored.state).toBe('executing');
      expect(restored.currentStep).toBe('step-03');
      expect(restored.completedSteps).toEqual(['step-01', 'step-02']);
    });

    it('restored context has working getVariable for step outputs', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setStepOutput('step-01', { score: 85, verdict: 'malicious' });
      mgr.setStepOutput('step-02', { ip_blocked: '198.51.100.23' });

      const snap = mgr.snapshot();
      const restored = ExecutionContextManager.restore(snap);

      expect(restored.getVariable('steps.step-01.output.score')).toBe(85);
      expect(restored.getVariable('steps.step-01.output.verdict')).toBe('malicious');
      expect(restored.getVariable('steps.step-02.output.ip_blocked')).toBe('198.51.100.23');
    });

    it('restored context has working getVariable for alert fields', () => {
      const alert = makeAlert();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
        alert,
      });

      const snap = mgr.snapshot();
      const restored = ExecutionContextManager.restore(snap);

      expect(restored.getVariable('alert.host.hostname')).toBe('workstation-42');
      expect(restored.getVariable('alert.process.name')).toBe('powershell.exe');
    });

    it('restored context preserves error', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setState('failed');
      mgr.setError({
        code: 'ADAPTER_TIMEOUT',
        message: 'Timed out',
        step_id: 'step-05',
      });

      const snap = mgr.snapshot();
      const restored = ExecutionContextManager.restore(snap);

      expect(restored.context.error?.code).toBe('ADAPTER_TIMEOUT');
      expect(restored.context.error?.step_id).toBe('step-05');
    });

    it('roundtrip through JSON serialization works', () => {
      const alert = makeAlert();
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '3.1.0',
        mode: 'simulation',
        alert,
      });

      mgr.setState('completed');
      mgr.setStepOutput('step-01', { results: [1, 2, 3] });
      mgr.markStepCompleted('step-01');

      const json = JSON.stringify(mgr.snapshot());
      const restored = ExecutionContextManager.restore(JSON.parse(json) as unknown);

      expect(restored.executionId).toBe(mgr.executionId);
      expect(restored.state).toBe('completed');
      expect(restored.getVariable('steps.step-01.output.results')).toEqual([1, 2, 3]);
      expect(restored.getVariable('alert.host.hostname')).toBe('workstation-42');
    });

    it('throws when data is null', () => {
      expect(() => ExecutionContextManager.restore(null)).toThrowError(
        /data must be a non-null object/,
      );
    });

    it('throws when data is a primitive', () => {
      expect(() => ExecutionContextManager.restore('string')).toThrowError(
        /data must be a non-null object/,
      );
    });

    it('throws when required string field is missing', () => {
      expect(() =>
        ExecutionContextManager.restore({
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          state: 'idle',
          started_at: '2026-01-01T00:00:00Z',
          // missing execution_id
        }),
      ).toThrowError(/missing or invalid field "execution_id"/);
    });

    it('throws when mode is invalid', () => {
      expect(() =>
        ExecutionContextManager.restore({
          execution_id: 'abc-123',
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'invalid-mode',
          state: 'idle',
          started_at: '2026-01-01T00:00:00Z',
        }),
      ).toThrowError(/invalid mode "invalid-mode"/);
    });

    it('throws when state is invalid', () => {
      expect(() =>
        ExecutionContextManager.restore({
          execution_id: 'abc-123',
          runbook_id: 'rb-test',
          runbook_version: '1.0.0',
          mode: 'production',
          state: 'nonexistent-state',
          started_at: '2026-01-01T00:00:00Z',
        }),
      ).toThrowError(/invalid state "nonexistent-state"/);
    });

    it('handles missing completed_steps gracefully', () => {
      const restored = ExecutionContextManager.restore({
        execution_id: 'abc-123',
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
        state: 'idle',
        started_at: '2026-01-01T00:00:00Z',
        // no completed_steps
      });

      expect(restored.completedSteps).toEqual([]);
    });

    it('handles missing variables gracefully', () => {
      const restored = ExecutionContextManager.restore({
        execution_id: 'abc-123',
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
        state: 'idle',
        started_at: '2026-01-01T00:00:00Z',
        // no variables
      });

      expect(restored.context.variables).toEqual({});
    });
  });

  // -------------------------------------------------------------------------
  // Accessor properties
  // -------------------------------------------------------------------------

  describe('accessor properties', () => {
    it('executionId returns the context execution_id', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.executionId).toBe(mgr.context.execution_id);
    });

    it('state returns the current state', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      mgr.setState('executing');
      expect(mgr.state).toBe('executing');
    });

    it('currentStep returns undefined initially', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.currentStep).toBeUndefined();
    });

    it('completedSteps returns empty array initially', () => {
      const mgr = ExecutionContextManager.create({
        runbook_id: 'rb-test',
        runbook_version: '1.0.0',
        mode: 'production',
      });

      expect(mgr.completedSteps).toEqual([]);
    });
  });
});
