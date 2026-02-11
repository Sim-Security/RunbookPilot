/**
 * Mock Adapter Framework
 *
 * Provides a configurable mock adapter for testing without real vendor APIs.
 * Supports latency simulation, configurable responses, and call recording.
 *
 * @module adapters/mock/mock-adapter
 */

import type {
  StepAction,
  ExecutionMode,
  AdapterResult,
  AdapterConfig,
} from '../../types/playbook.ts';
import {
  BaseAdapter,
  type AdapterCapabilities,
  type HealthCheckResult,
  type ValidationResult,
} from '../adapter-interface.ts';

// ---------------------------------------------------------------------------
// Call Recording
// ---------------------------------------------------------------------------

export interface RecordedCall {
  action: StepAction;
  params: Record<string, unknown>;
  mode: ExecutionMode;
  timestamp: string;
  result: AdapterResult;
}

// ---------------------------------------------------------------------------
// Mock Behavior Configuration
// ---------------------------------------------------------------------------

export interface MockBehavior {
  /** Whether the action should succeed. Default true. */
  success?: boolean;
  /** Simulated latency in ms. Default 10. */
  latencyMs?: number;
  /** Custom output to return on success. */
  output?: unknown;
  /** Custom error code on failure. */
  errorCode?: string;
  /** Custom error message on failure. */
  errorMessage?: string;
  /** Whether the error is retryable. Default false. */
  retryable?: boolean;
  /** Throw an actual error instead of returning a failure result. */
  throwError?: boolean;
}

export interface MockAdapterOptions {
  /** Adapter name override. Default 'mock'. */
  name?: string;
  /** Default latency for all actions in ms. Default 10. */
  defaultLatencyMs?: number;
  /** Per-action behavior overrides. */
  behaviors?: Partial<Record<StepAction, MockBehavior>>;
  /** Whether to simulate health check failures. Default false. */
  unhealthy?: boolean;
}

// ---------------------------------------------------------------------------
// All mockable actions
// ---------------------------------------------------------------------------

const ALL_ACTIONS: readonly StepAction[] = [
  // Network
  'isolate_host', 'restore_connectivity', 'block_ip', 'unblock_ip',
  'block_domain', 'unblock_domain',
  // Data collection
  'collect_logs', 'query_siem', 'collect_network_traffic',
  'snapshot_memory', 'collect_file_metadata',
  // Threat intel
  'enrich_ioc', 'check_reputation', 'query_threat_feed',
  // Ticketing / notifications
  'create_ticket', 'update_ticket', 'notify_analyst', 'notify_oncall', 'send_email',
  // Account management
  'disable_account', 'enable_account', 'reset_password', 'revoke_session',
  // File operations
  'quarantine_file', 'restore_file', 'delete_file', 'calculate_hash',
  // EDR/XDR
  'kill_process', 'start_edr_scan', 'retrieve_edr_data',
  // Custom
  'execute_script', 'http_request', 'wait',
] as const;

// ---------------------------------------------------------------------------
// Mock Adapter
// ---------------------------------------------------------------------------

export class MockAdapter extends BaseAdapter {
  readonly name: string;
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[];

  private defaultLatencyMs: number;
  private behaviors: Partial<Record<StepAction, MockBehavior>>;
  private isUnhealthy: boolean;
  private readonly calls: RecordedCall[] = [];

  constructor(options: MockAdapterOptions = {}) {
    super();
    this.name = options.name ?? 'mock';
    this.defaultLatencyMs = options.defaultLatencyMs ?? 10;
    this.behaviors = options.behaviors ?? {};
    this.isUnhealthy = options.unhealthy ?? false;
    this.supportedActions = ALL_ACTIONS;
  }

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);

    // Override defaults from config
    if (typeof config.config.latency === 'number') {
      this.defaultLatencyMs = config.config.latency;
    }
    if (typeof config.config.unhealthy === 'boolean') {
      this.isUnhealthy = config.config.unhealthy;
    }
  }

  override async execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    const behavior = this.behaviors[action];
    const latency = behavior?.latencyMs ?? this.defaultLatencyMs;
    const start = performance.now();

    // Simulate latency
    if (latency > 0) {
      await new Promise((resolve) => setTimeout(resolve, latency));
    }

    const durationMs = Math.round(performance.now() - start);

    // Check if should throw
    if (behavior?.throwError) {
      const err = new Error(behavior.errorMessage ?? `Mock error for '${action}'`);
      this.recordCall(action, params, mode, this.failureResult(
        action, durationMs, 'MOCK_THROWN', err.message,
      ));
      throw err;
    }

    // Build result
    const shouldSucceed = behavior?.success ?? true;
    let result: AdapterResult;

    if (shouldSucceed) {
      const output = behavior?.output ?? this.defaultOutput(action, params, mode);
      result = this.successResult(action, durationMs, output, {
        mock: true,
        mode,
      });
    } else {
      result = this.failureResult(
        action,
        durationMs,
        behavior?.errorCode ?? 'MOCK_FAILURE',
        behavior?.errorMessage ?? `Mock failure for action '${action}'`,
        behavior?.retryable ?? false,
      );
    }

    this.recordCall(action, params, mode, result);
    return result;
  }

  override async rollback(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    this.assertInitialized();

    const start = performance.now();
    await new Promise((resolve) => setTimeout(resolve, this.defaultLatencyMs));
    const durationMs = Math.round(performance.now() - start);

    const result = this.successResult(action, durationMs, {
      rolled_back: true,
      original_action: action,
      params,
    }, { mock: true });

    this.recordCall(action, params, 'production', result);
    return result;
  }

  override async healthCheck(): Promise<HealthCheckResult> {
    if (this.isUnhealthy) {
      return {
        status: 'unhealthy',
        message: 'Mock adapter configured as unhealthy',
        checkedAt: new Date().toISOString(),
      };
    }

    return {
      status: 'healthy',
      message: 'Mock adapter operational',
      latencyMs: 0,
      checkedAt: new Date().toISOString(),
    };
  }

  override getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: true,
      supportsValidation: true,
      maxConcurrency: 0,
    };
  }

  async validateParameters(
    action: StepAction,
    _params: Record<string, unknown>,
  ): Promise<ValidationResult> {
    if (!this.supportedActions.includes(action)) {
      return { valid: false, errors: [`Unsupported action: ${action}`] };
    }
    return { valid: true };
  }

  // -------------------------------------------------------------------------
  // Call Recording API
  // -------------------------------------------------------------------------

  /** Get all recorded calls. */
  getCalls(): readonly RecordedCall[] {
    return this.calls;
  }

  /** Get calls for a specific action. */
  getCallsForAction(action: StepAction): RecordedCall[] {
    return this.calls.filter((c) => c.action === action);
  }

  /** Get the last recorded call. */
  getLastCall(): RecordedCall | undefined {
    return this.calls[this.calls.length - 1];
  }

  /** Get total call count. */
  getCallCount(): number {
    return this.calls.length;
  }

  /** Clear recorded calls. */
  clearCalls(): void {
    this.calls.length = 0;
  }

  /** Check if a specific action was called. */
  wasCalled(action: StepAction): boolean {
    return this.calls.some((c) => c.action === action);
  }

  /** Check if a specific action was called N times. */
  wasCalledTimes(action: StepAction, times: number): boolean {
    return this.getCallsForAction(action).length === times;
  }

  // -------------------------------------------------------------------------
  // Behavior Configuration API
  // -------------------------------------------------------------------------

  /** Set behavior for a specific action at runtime. */
  setBehavior(action: StepAction, behavior: MockBehavior): void {
    this.behaviors[action] = behavior;
  }

  /** Remove behavior override for an action. */
  clearBehavior(action: StepAction): void {
    delete this.behaviors[action];
  }

  /** Set the adapter as healthy or unhealthy. */
  setHealthy(healthy: boolean): void {
    this.isUnhealthy = !healthy;
  }

  // -------------------------------------------------------------------------
  // Private
  // -------------------------------------------------------------------------

  private recordCall(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
    result: AdapterResult,
  ): void {
    this.calls.push({
      action,
      params,
      mode,
      timestamp: new Date().toISOString(),
      result,
    });
  }

  /**
   * Generate default mock output based on action type.
   */
  private defaultOutput(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Record<string, unknown> {
    const base = { mock: true, mode, action };

    switch (action) {
      case 'block_ip':
      case 'unblock_ip':
        return { ...base, ip: params.ip ?? '0.0.0.0', status: 'completed' };

      case 'isolate_host':
      case 'restore_connectivity':
        return { ...base, host: params.host ?? 'unknown', isolation_id: 'mock-iso-001' };

      case 'collect_logs':
      case 'query_siem':
        return { ...base, event_count: 42, events: [{ id: 'evt-001', message: 'Mock log event' }] };

      case 'enrich_ioc':
      case 'check_reputation':
        return { ...base, detections: 5, total_engines: 70, threat_label: 'trojan.generic', score: 7.2 };

      case 'retrieve_edr_data':
        return {
          ...base,
          process_tree: [
            { pid: 1234, name: 'cmd.exe', parent_pid: 5678, command_line: 'cmd.exe /c whoami' },
          ],
        };

      case 'create_ticket':
        return { ...base, ticket_id: 'INC-MOCK-001', url: 'https://mock.ticket/INC-MOCK-001' };

      case 'notify_analyst':
      case 'notify_oncall':
      case 'send_email':
        return { ...base, delivered: true, recipient: params.recipient ?? 'mock@example.com' };

      case 'disable_account':
      case 'enable_account':
        return { ...base, account: params.account ?? 'user@corp.com', status: 'completed' };

      case 'quarantine_file':
      case 'restore_file':
      case 'delete_file':
        return { ...base, path: params.path ?? '/tmp/mock', status: 'completed' };

      case 'kill_process':
        return { ...base, pid: params.pid ?? 1234, killed: true };

      default:
        return base;
    }
  }
}

// ---------------------------------------------------------------------------
// Factory Functions
// ---------------------------------------------------------------------------

/**
 * Create a mock adapter with default settings.
 */
export function createMockAdapter(options?: MockAdapterOptions): MockAdapter {
  return new MockAdapter(options);
}

/**
 * Create a mock adapter that always fails for specific actions.
 */
export function createFailingMockAdapter(
  failActions: StepAction[],
  errorMessage = 'Simulated failure',
): MockAdapter {
  const behaviors: Partial<Record<StepAction, MockBehavior>> = {};
  for (const action of failActions) {
    behaviors[action] = {
      success: false,
      errorCode: 'MOCK_FAILURE',
      errorMessage,
      retryable: false,
    };
  }
  return new MockAdapter({ behaviors });
}

/**
 * Create a mock adapter with simulated latency.
 */
export function createSlowMockAdapter(latencyMs: number): MockAdapter {
  return new MockAdapter({ defaultLatencyMs: latencyMs });
}
