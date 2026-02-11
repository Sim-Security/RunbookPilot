import { describe, it, expect } from 'vitest';
import {
  ExecutionStateMachine,
  StateMachineError,
} from '../../../src/engine/state-machine.ts';
import type { StateTransition } from '../../../src/engine/state-machine.ts';

describe('ExecutionStateMachine', () => {
  describe('initialization', () => {
    it('starts in idle state', () => {
      const sm = new ExecutionStateMachine('exec-001');
      expect(sm.state).toBe('idle');
      expect(sm.executionId).toBe('exec-001');
      expect(sm.isTerminal).toBe(false);
      expect(sm.history).toEqual([]);
    });

    it('can start in a custom state', () => {
      const sm = new ExecutionStateMachine('exec-002', 'executing');
      expect(sm.state).toBe('executing');
    });
  });

  describe('happy path: L0/L1 (no approval)', () => {
    it('transitions idle → validating → planning → executing → completed', () => {
      const sm = new ExecutionStateMachine('exec-001');

      sm.transition('trigger');
      expect(sm.state).toBe('validating');

      sm.transition('validation_success');
      expect(sm.state).toBe('planning');

      sm.transition('plan_ready');
      expect(sm.state).toBe('executing');

      sm.transition('step_completed');
      expect(sm.state).toBe('executing');

      sm.transition('all_steps_completed');
      expect(sm.state).toBe('completed');
      expect(sm.isTerminal).toBe(true);
      expect(sm.history.length).toBe(5);
    });
  });

  describe('approval path: L2', () => {
    it('transitions through awaiting_approval when required', () => {
      const sm = new ExecutionStateMachine('exec-002');

      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('approval_required');
      expect(sm.state).toBe('awaiting_approval');

      sm.transition('approval_granted');
      expect(sm.state).toBe('executing');

      sm.transition('all_steps_completed');
      expect(sm.state).toBe('completed');
    });

    it('transitions to cancelled on approval denied', () => {
      const sm = new ExecutionStateMachine('exec-003');

      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('approval_required');
      sm.transition('approval_denied');

      expect(sm.state).toBe('cancelled');
      expect(sm.isTerminal).toBe(true);
    });

    it('transitions to cancelled on approval timeout', () => {
      const sm = new ExecutionStateMachine('exec-004');

      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('approval_required');
      sm.transition('approval_timeout');

      expect(sm.state).toBe('cancelled');
    });
  });

  describe('failure paths', () => {
    it('transitions to failed on validation failure', () => {
      const sm = new ExecutionStateMachine('exec-005');
      sm.transition('trigger');
      sm.transition('validation_failed');
      expect(sm.state).toBe('failed');
      expect(sm.isTerminal).toBe(true);
    });

    it('transitions to failed on step failure', () => {
      const sm = new ExecutionStateMachine('exec-006');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.transition('step_failed');
      expect(sm.state).toBe('failed');
    });
  });

  describe('rollback', () => {
    it('enters rolling_back state via startRollback()', () => {
      const sm = new ExecutionStateMachine('exec-007');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');

      const t = sm.startRollback();
      expect(sm.state).toBe('rolling_back');
      expect(t.from).toBe('executing');
      expect(t.to).toBe('rolling_back');
    });

    it('completes rollback successfully', () => {
      const sm = new ExecutionStateMachine('exec-008');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.startRollback();
      sm.transition('rollback_completed');
      expect(sm.state).toBe('completed');
    });

    it('handles rollback failure', () => {
      const sm = new ExecutionStateMachine('exec-009');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.startRollback();
      sm.transition('rollback_failed');
      expect(sm.state).toBe('failed');
    });

    it('throws if startRollback from non-executing state', () => {
      const sm = new ExecutionStateMachine('exec-010');
      expect(() => sm.startRollback()).toThrow(StateMachineError);
    });
  });

  describe('cancellation', () => {
    it('cancels from executing', () => {
      const sm = new ExecutionStateMachine('exec-011');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.transition('cancel');
      expect(sm.state).toBe('cancelled');
    });

    it('cancels from validating', () => {
      const sm = new ExecutionStateMachine('exec-012');
      sm.transition('trigger');
      sm.transition('cancel');
      expect(sm.state).toBe('cancelled');
    });

    it('cancels from planning', () => {
      const sm = new ExecutionStateMachine('exec-013');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('cancel');
      expect(sm.state).toBe('cancelled');
    });

    it('cancels from awaiting_approval', () => {
      const sm = new ExecutionStateMachine('exec-014');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('approval_required');
      sm.transition('cancel');
      expect(sm.state).toBe('cancelled');
    });
  });

  describe('invalid transitions', () => {
    it('throws on invalid event from current state', () => {
      const sm = new ExecutionStateMachine('exec-020');
      expect(() => sm.transition('all_steps_completed')).toThrow(StateMachineError);
    });

    it('throws when transitioning from terminal state', () => {
      const sm = new ExecutionStateMachine('exec-021');
      sm.transition('trigger');
      sm.transition('validation_failed');
      expect(() => sm.transition('trigger')).toThrow(StateMachineError);
    });

    it('provides error details in StateMachineError', () => {
      const sm = new ExecutionStateMachine('exec-022');
      try {
        sm.transition('all_steps_completed');
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(StateMachineError);
        const sme = err as StateMachineError;
        expect(sme.currentState).toBe('idle');
        expect(sme.event).toBe('all_steps_completed');
      }
    });
  });

  describe('canTransition', () => {
    it('returns true for valid transitions', () => {
      const sm = new ExecutionStateMachine('exec-030');
      expect(sm.canTransition('trigger')).toBe(true);
      expect(sm.canTransition('all_steps_completed')).toBe(false);
    });

    it('returns false from terminal states', () => {
      const sm = new ExecutionStateMachine('exec-031', 'completed');
      expect(sm.canTransition('trigger')).toBe(false);
    });
  });

  describe('getValidEvents', () => {
    it('returns valid events for idle', () => {
      const sm = new ExecutionStateMachine('exec-040');
      expect(sm.getValidEvents()).toEqual(['trigger']);
    });

    it('returns valid events for executing', () => {
      const sm = new ExecutionStateMachine('exec-041', 'executing');
      const events = sm.getValidEvents();
      expect(events).toContain('all_steps_completed');
      expect(events).toContain('step_failed');
      expect(events).toContain('step_completed');
      expect(events).toContain('cancel');
    });

    it('returns empty array for terminal states', () => {
      const sm = new ExecutionStateMachine('exec-042', 'completed');
      expect(sm.getValidEvents()).toEqual([]);
    });
  });

  describe('event listener', () => {
    it('notifies listeners on transition', () => {
      const sm = new ExecutionStateMachine('exec-050');
      const transitions: StateTransition[] = [];

      sm.onStateChange((t) => transitions.push(t));
      sm.transition('trigger');

      expect(transitions.length).toBe(1);
      expect(transitions[0]!.from).toBe('idle');
      expect(transitions[0]!.to).toBe('validating');
      expect(transitions[0]!.event).toBe('trigger');
      expect(transitions[0]!.timestamp).toBeDefined();
    });

    it('unsubscribes listener correctly', () => {
      const sm = new ExecutionStateMachine('exec-051');
      const transitions: StateTransition[] = [];

      const unsub = sm.onStateChange((t) => transitions.push(t));
      sm.transition('trigger');
      unsub();
      sm.transition('validation_success');

      expect(transitions.length).toBe(1);
    });
  });

  describe('serialization', () => {
    it('serializes to snapshot', () => {
      const sm = new ExecutionStateMachine('exec-060');
      sm.transition('trigger');
      sm.transition('validation_success');

      const snap = sm.serialize();
      expect(snap.executionId).toBe('exec-060');
      expect(snap.state).toBe('planning');
      expect(snap.history.length).toBe(2);
    });

    it('restores from snapshot', () => {
      const sm = new ExecutionStateMachine('exec-061');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');

      const snap = sm.serialize();
      const restored = ExecutionStateMachine.restore(snap);

      expect(restored.executionId).toBe('exec-061');
      expect(restored.state).toBe('executing');
      expect(restored.history.length).toBe(3);

      // Can continue transitioning
      restored.transition('all_steps_completed');
      expect(restored.state).toBe('completed');
    });
  });

  describe('history', () => {
    it('records all transitions', () => {
      const sm = new ExecutionStateMachine('exec-070');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.transition('all_steps_completed');

      expect(sm.history.length).toBe(4);
      expect(sm.history[0]!.from).toBe('idle');
      expect(sm.history[0]!.to).toBe('validating');
      expect(sm.history[3]!.from).toBe('executing');
      expect(sm.history[3]!.to).toBe('completed');
    });

    it('history is immutable from outside', () => {
      const sm = new ExecutionStateMachine('exec-071');
      sm.transition('trigger');
      const history = sm.history;
      expect(history.length).toBe(1);
      // readonly array prevents mutation
    });
  });
});
