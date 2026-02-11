/**
 * Deterministic Execution State Machine
 *
 * Manages the lifecycle of a playbook execution through defined states
 * with guarded transitions. NO LLM involvement — purely deterministic.
 *
 * States: idle → validating → planning → [awaiting_approval] → executing → completed/failed
 * See TECHNICAL_REFERENCE.md Section 4 for full state diagram.
 *
 * @module engine/state-machine
 */

import type { ExecutionState } from '../types/playbook.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type StateTransitionEvent =
  | 'trigger'
  | 'validation_success'
  | 'validation_failed'
  | 'plan_ready'
  | 'approval_required'
  | 'approval_granted'
  | 'approval_denied'
  | 'approval_timeout'
  | 'step_completed'
  | 'all_steps_completed'
  | 'step_failed'
  | 'rollback_completed'
  | 'rollback_failed'
  | 'cancel';

export interface StateTransition {
  from: ExecutionState;
  to: ExecutionState;
  event: StateTransitionEvent;
  timestamp: string;
}

export type StateChangeListener = (transition: StateTransition) => void;

// ---------------------------------------------------------------------------
// Transition Table
// ---------------------------------------------------------------------------

interface TransitionRule {
  from: ExecutionState;
  event: StateTransitionEvent;
  to: ExecutionState;
}

/**
 * All valid state transitions. Any transition not in this table is illegal.
 */
const TRANSITION_TABLE: readonly TransitionRule[] = [
  // idle → validating
  { from: 'idle', event: 'trigger', to: 'validating' },

  // validating → planning or failed
  { from: 'validating', event: 'validation_success', to: 'planning' },
  { from: 'validating', event: 'validation_failed', to: 'failed' },

  // planning → executing or awaiting_approval
  { from: 'planning', event: 'plan_ready', to: 'executing' },
  { from: 'planning', event: 'approval_required', to: 'awaiting_approval' },

  // awaiting_approval → executing or cancelled
  { from: 'awaiting_approval', event: 'approval_granted', to: 'executing' },
  { from: 'awaiting_approval', event: 'approval_denied', to: 'cancelled' },
  { from: 'awaiting_approval', event: 'approval_timeout', to: 'cancelled' },

  // executing → completed, failed, or rolling_back
  { from: 'executing', event: 'all_steps_completed', to: 'completed' },
  { from: 'executing', event: 'step_failed', to: 'failed' },
  { from: 'executing', event: 'step_completed', to: 'executing' }, // loop
  // step_failed with rollback enabled:
  // The orchestrator checks rollback_on_failure and sends either
  // 'step_failed' (→ failed) or triggers rollback transition below

  // rolling_back → completed or failed
  { from: 'rolling_back', event: 'rollback_completed', to: 'completed' },
  { from: 'rolling_back', event: 'rollback_failed', to: 'failed' },

  // executing → rolling_back (triggered by orchestrator)
  { from: 'executing', event: 'cancel', to: 'cancelled' },

  // Cancel from any non-terminal state
  { from: 'validating', event: 'cancel', to: 'cancelled' },
  { from: 'planning', event: 'cancel', to: 'cancelled' },
  { from: 'awaiting_approval', event: 'cancel', to: 'cancelled' },
] as const;

/**
 * Terminal states — no further transitions allowed.
 */
const TERMINAL_STATES: ReadonlySet<ExecutionState> = new Set([
  'completed',
  'failed',
  'cancelled',
]);

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

export class ExecutionStateMachine {
  private _state: ExecutionState;
  private _history: StateTransition[] = [];
  private _listeners: StateChangeListener[] = [];
  private readonly _executionId: string;

  constructor(executionId: string, initialState: ExecutionState = 'idle') {
    this._executionId = executionId;
    this._state = initialState;
  }

  /** Current state */
  get state(): ExecutionState {
    return this._state;
  }

  /** Execution ID this machine tracks */
  get executionId(): string {
    return this._executionId;
  }

  /** Full transition history */
  get history(): readonly StateTransition[] {
    return this._history;
  }

  /** Whether the machine is in a terminal state */
  get isTerminal(): boolean {
    return TERMINAL_STATES.has(this._state);
  }

  /**
   * Attempt a state transition. Throws if the transition is invalid.
   */
  transition(event: StateTransitionEvent): StateTransition {
    if (this.isTerminal) {
      throw new StateMachineError(
        `Cannot transition from terminal state '${this._state}'`,
        this._state,
        event,
      );
    }

    const rule = TRANSITION_TABLE.find(
      (r) => r.from === this._state && r.event === event,
    );

    if (!rule) {
      throw new StateMachineError(
        `Invalid transition: '${this._state}' + '${event}'`,
        this._state,
        event,
      );
    }

    const transition: StateTransition = {
      from: this._state,
      to: rule.to,
      event,
      timestamp: new Date().toISOString(),
    };

    this._state = rule.to;
    this._history.push(transition);

    // Notify listeners
    for (const listener of this._listeners) {
      listener(transition);
    }

    return transition;
  }

  /**
   * Transition to rolling_back state directly.
   * Only valid from 'executing' state.
   */
  startRollback(): StateTransition {
    if (this._state !== 'executing') {
      throw new StateMachineError(
        `Cannot start rollback from state '${this._state}' (must be 'executing')`,
        this._state,
        'step_failed',
      );
    }

    const transition: StateTransition = {
      from: 'executing',
      to: 'rolling_back',
      event: 'step_failed',
      timestamp: new Date().toISOString(),
    };

    this._state = 'rolling_back';
    this._history.push(transition);

    for (const listener of this._listeners) {
      listener(transition);
    }

    return transition;
  }

  /**
   * Check if a transition is valid without performing it.
   */
  canTransition(event: StateTransitionEvent): boolean {
    if (this.isTerminal) return false;
    return TRANSITION_TABLE.some(
      (r) => r.from === this._state && r.event === event,
    );
  }

  /**
   * Get valid events for the current state.
   */
  getValidEvents(): StateTransitionEvent[] {
    if (this.isTerminal) return [];
    return TRANSITION_TABLE
      .filter((r) => r.from === this._state)
      .map((r) => r.event);
  }

  /**
   * Register a listener for state changes.
   */
  onStateChange(listener: StateChangeListener): () => void {
    this._listeners.push(listener);
    return () => {
      const idx = this._listeners.indexOf(listener);
      if (idx >= 0) this._listeners.splice(idx, 1);
    };
  }

  /**
   * Serialize state machine for persistence.
   */
  serialize(): StateMachineSnapshot {
    return {
      executionId: this._executionId,
      state: this._state,
      history: [...this._history],
    };
  }

  /**
   * Restore state machine from snapshot.
   */
  static restore(snapshot: StateMachineSnapshot): ExecutionStateMachine {
    const sm = new ExecutionStateMachine(snapshot.executionId, snapshot.state);
    sm._history = [...snapshot.history];
    return sm;
  }
}

// ---------------------------------------------------------------------------
// Snapshot Type
// ---------------------------------------------------------------------------

export interface StateMachineSnapshot {
  executionId: string;
  state: ExecutionState;
  history: StateTransition[];
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export class StateMachineError extends Error {
  readonly currentState: ExecutionState;
  readonly event: StateTransitionEvent;

  constructor(message: string, currentState: ExecutionState, event: StateTransitionEvent) {
    super(message);
    this.name = 'StateMachineError';
    this.currentState = currentState;
    this.event = event;
  }
}
