/**
 * IP Block Adapter
 *
 * Handles firewall IP/domain blocking and unblocking actions.
 * Supports production (real HTTP calls), simulation (mock data),
 * and dry-run (validation only) execution modes.
 *
 * Supported actions: block_ip, unblock_ip, block_domain, unblock_domain
 *
 * @module adapters/firewall/ip-block-adapter
 */

import {
  BaseAdapter,
  type AdapterCapabilities,
  type HealthCheckResult,
  type ValidationResult,
} from '../adapter-interface.ts';

import type {
  StepAction,
  ExecutionMode,
  AdapterResult,
  AdapterConfig,
} from '../../types/playbook.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUPPORTED_ACTIONS: readonly StepAction[] = [
  'block_ip',
  'unblock_ip',
  'block_domain',
  'unblock_domain',
] as const;

/**
 * Maps each action to its rollback counterpart.
 */
const ROLLBACK_MAP: Record<string, StepAction> = {
  block_ip: 'unblock_ip',
  unblock_ip: 'block_ip',
  block_domain: 'unblock_domain',
  unblock_domain: 'block_domain',
};

// ---------------------------------------------------------------------------
// Validation Helpers
// ---------------------------------------------------------------------------

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;

/**
 * Validates an IPv6 address. Accepts full and compressed forms.
 */
function isValidIPv6(ip: string): boolean {
  // Handle :: shorthand and standard 8-group hex notation
  const IPV6_REGEX =
    /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)$/;
  return IPV6_REGEX.test(ip);
}

/**
 * Returns true if the given string is a valid IPv4 or IPv6 address.
 */
function isValidIP(ip: string): boolean {
  return IPV4_REGEX.test(ip) || isValidIPv6(ip);
}

// ---------------------------------------------------------------------------
// IP Block Adapter
// ---------------------------------------------------------------------------

export class IPBlockAdapter extends BaseAdapter {
  readonly name = 'ip-block-adapter';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = SUPPORTED_ACTIONS;

  // ---- Lifecycle -----------------------------------------------------------

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);
  }

  // ---- Execute -------------------------------------------------------------

  override async execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    const start = Date.now();

    // Validate parameters first regardless of mode
    const validation = await this.validateParameters(action, params);
    if (!validation.valid) {
      return this.failureResult(
        action,
        Date.now() - start,
        'VALIDATION_ERROR',
        `Parameter validation failed: ${validation.errors?.join('; ')}`,
      );
    }

    switch (mode) {
      case 'dry-run':
        return this.executeDryRun(action, params, start);
      case 'simulation':
        return this.executeSimulation(action, params, start);
      case 'production':
        return this.executeProduction(action, params, start);
      default:
        return this.failureResult(
          action,
          Date.now() - start,
          'INVALID_MODE',
          `Unknown execution mode: ${String(mode)}`,
        );
    }
  }

  // ---- Rollback ------------------------------------------------------------

  override async rollback(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    const start = Date.now();
    const rollbackAction = ROLLBACK_MAP[action];

    if (!rollbackAction) {
      return this.failureResult(
        action,
        Date.now() - start,
        'ROLLBACK_NOT_SUPPORTED',
        `No rollback action defined for '${action}'`,
      );
    }

    // Execute the inverse action in production mode
    return this.execute(rollbackAction, params, 'production');
  }

  // ---- Health Check --------------------------------------------------------

  override async healthCheck(): Promise<HealthCheckResult> {
    const checkedAt = new Date().toISOString();

    if (!this.initialized || !this.config) {
      return {
        status: 'unknown',
        message: 'Adapter not initialized',
        checkedAt,
      };
    }

    const baseUrl = this.config.config.base_url;

    // In simulation or if no base_url, return healthy
    if (!baseUrl || typeof baseUrl !== 'string') {
      return {
        status: 'healthy',
        message: 'No base_url configured; assuming simulation mode',
        checkedAt,
      };
    }

    const start = Date.now();
    try {
      const response = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      const latencyMs = Date.now() - start;

      if (response.ok) {
        return {
          status: 'healthy',
          message: `Firewall API reachable (HTTP ${response.status})`,
          latencyMs,
          checkedAt,
        };
      }

      return {
        status: 'degraded',
        message: `Firewall API returned HTTP ${response.status}`,
        latencyMs,
        checkedAt,
      };
    } catch (error: unknown) {
      const latencyMs = Date.now() - start;
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        status: 'unhealthy',
        message: `Firewall API unreachable: ${message}`,
        latencyMs,
        checkedAt,
      };
    }
  }

  // ---- Capabilities --------------------------------------------------------

  override getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: true,
      supportsValidation: true,
      maxConcurrency: 10,
    };
  }

  // ---- Validate Parameters -------------------------------------------------

  async validateParameters(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<ValidationResult> {
    const errors: string[] = [];

    if (action === 'block_ip' || action === 'unblock_ip') {
      if (!params.ip || typeof params.ip !== 'string') {
        errors.push(`Action '${action}' requires a string 'ip' parameter`);
      } else if (!isValidIP(params.ip)) {
        errors.push(
          `Invalid IP address '${params.ip}': must be a valid IPv4 or IPv6 address`,
        );
      }
    }

    if (action === 'block_domain' || action === 'unblock_domain') {
      if (!params.domain || typeof params.domain !== 'string') {
        errors.push(`Action '${action}' requires a string 'domain' parameter`);
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  // ---- Private: Mode-specific execution ------------------------------------

  private executeDryRun(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    return this.successResult(
      action,
      Date.now() - start,
      {
        mode: 'dry-run',
        action,
        params,
        message: `Dry-run validation passed for '${action}'`,
      },
      { mode: 'dry-run' },
    );
  }

  private executeSimulation(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    const target =
      action === 'block_ip' || action === 'unblock_ip'
        ? (params.ip as string)
        : (params.domain as string);

    return this.successResult(
      action,
      Date.now() - start,
      {
        mode: 'simulation',
        action,
        target,
        applied: false,
        simulated: true,
        rule_id: `sim-${crypto.randomUUID()}`,
        message: `Simulated '${action}' for target '${target}'`,
      },
      { mode: 'simulation' },
    );
  }

  private async executeProduction(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    if (!this.config) {
      return this.failureResult(
        action,
        Date.now() - start,
        'NOT_CONFIGURED',
        'Adapter config is not available',
      );
    }

    const baseUrl = this.config.config.base_url;
    if (!baseUrl || typeof baseUrl !== 'string') {
      return this.failureResult(
        action,
        Date.now() - start,
        'MISSING_CONFIG',
        "Production mode requires 'base_url' in adapter config",
      );
    }

    const apiKey = this.config.credentials?.credentials.api_key;
    if (!apiKey) {
      return this.failureResult(
        action,
        Date.now() - start,
        'MISSING_CREDENTIALS',
        "Production mode requires 'api_key' in adapter credentials",
      );
    }

    const endpoint = this.resolveEndpoint(action);
    const body = this.buildRequestBody(action, params);

    try {
      const timeoutMs = (this.config.timeout ?? 30) * 1000;
      const response = await fetch(`${baseUrl}${endpoint}`, {
        method: this.resolveHttpMethod(action),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });

      const durationMs = Date.now() - start;

      if (!response.ok) {
        const errorText = await response.text();
        return this.failureResult(
          action,
          durationMs,
          'API_ERROR',
          `Firewall API returned HTTP ${response.status}: ${errorText}`,
          response.status >= 500, // Server errors are retryable
        );
      }

      const responseData: unknown = await response.json();

      return this.successResult(
        action,
        durationMs,
        {
          mode: 'production',
          action,
          response: responseData,
        },
        { mode: 'production', httpStatus: response.status },
      );
    } catch (error: unknown) {
      const durationMs = Date.now() - start;
      const message = error instanceof Error ? error.message : 'Unknown error';
      return this.failureResult(
        action,
        durationMs,
        'NETWORK_ERROR',
        `Failed to reach firewall API: ${message}`,
        true, // Network errors are retryable
      );
    }
  }

  // ---- Private: Request helpers --------------------------------------------

  private resolveEndpoint(action: StepAction): string {
    switch (action) {
      case 'block_ip':
        return '/api/v1/rules/ip/block';
      case 'unblock_ip':
        return '/api/v1/rules/ip/unblock';
      case 'block_domain':
        return '/api/v1/rules/domain/block';
      case 'unblock_domain':
        return '/api/v1/rules/domain/unblock';
      default:
        return '/api/v1/rules';
    }
  }

  private resolveHttpMethod(action: StepAction): string {
    switch (action) {
      case 'block_ip':
      case 'block_domain':
        return 'POST';
      case 'unblock_ip':
      case 'unblock_domain':
        return 'DELETE';
      default:
        return 'POST';
    }
  }

  private buildRequestBody(
    action: StepAction,
    params: Record<string, unknown>,
  ): Record<string, unknown> {
    if (action === 'block_ip' || action === 'unblock_ip') {
      return {
        ip: params.ip,
        reason: params.reason ?? 'RunbookPilot automated action',
        duration: params.duration ?? null, // null = permanent
      };
    }

    return {
      domain: params.domain,
      reason: params.reason ?? 'RunbookPilot automated action',
      duration: params.duration ?? null,
    };
  }
}
