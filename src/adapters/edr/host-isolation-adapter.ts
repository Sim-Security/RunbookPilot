/**
 * Host Isolation Adapter
 *
 * Handles host isolation and connectivity restoration actions via EDR APIs.
 * Supports CrowdStrike, Wazuh, and generic EDR vendors.
 *
 * Actions: isolate_host, restore_connectivity
 *
 * @module adapters/edr/host-isolation-adapter
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
// Vendor Types
// ---------------------------------------------------------------------------

type EDRVendor = 'crowdstrike' | 'wazuh' | 'generic';

// ---------------------------------------------------------------------------
// Host Isolation Adapter
// ---------------------------------------------------------------------------

export class HostIsolationAdapter extends BaseAdapter {
  readonly name = 'edr-host-isolation';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = [
    'isolate_host',
    'restore_connectivity',
  ] as const;

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);

    const vendor = this.getVendor();
    const validVendors: EDRVendor[] = ['crowdstrike', 'wazuh', 'generic'];
    if (!validVendors.includes(vendor)) {
      throw new Error(
        `HostIsolationAdapter: unsupported vendor '${vendor}'. ` +
          `Valid vendors: ${validVendors.join(', ')}`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Execute
  // -------------------------------------------------------------------------

  override async execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    const start = performance.now();

    try {
      if (mode === 'dry-run') {
        return this.executeDryRun(action, params, start);
      }

      if (mode === 'simulation') {
        return this.executeSimulation(action, params, start);
      }

      return await this.executeProduction(action, params, start);
    } catch (err) {
      const durationMs = Math.round(performance.now() - start);
      const message = err instanceof Error ? err.message : String(err);
      return this.failureResult(action, durationMs, 'EXECUTION_ERROR', message, true);
    }
  }

  // -------------------------------------------------------------------------
  // Rollback
  // -------------------------------------------------------------------------

  override async rollback(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    this.assertInitialized();

    const reverseAction = this.getReverseAction(action);
    return this.execute(reverseAction, params, 'production');
  }

  // -------------------------------------------------------------------------
  // Health Check
  // -------------------------------------------------------------------------

  override async healthCheck(): Promise<HealthCheckResult> {
    if (!this.initialized || !this.config) {
      return {
        status: 'unknown',
        message: 'Adapter not initialized',
        checkedAt: new Date().toISOString(),
      };
    }

    const baseUrl = this.getBaseUrl();
    const start = performance.now();

    try {
      const response = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(10_000),
      });

      const latencyMs = Math.round(performance.now() - start);

      if (response.ok) {
        return {
          status: 'healthy',
          message: 'EDR API reachable',
          latencyMs,
          checkedAt: new Date().toISOString(),
        };
      }

      return {
        status: 'degraded',
        message: `EDR API returned status ${response.status}`,
        latencyMs,
        checkedAt: new Date().toISOString(),
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - start);
      const message = err instanceof Error ? err.message : String(err);
      return {
        status: 'unhealthy',
        message: `EDR API unreachable: ${message}`,
        latencyMs,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  // -------------------------------------------------------------------------
  // Capabilities
  // -------------------------------------------------------------------------

  override getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: true,
      supportsValidation: true,
      maxConcurrency: 5,
    };
  }

  // -------------------------------------------------------------------------
  // Validate Parameters
  // -------------------------------------------------------------------------

  async validateParameters(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<ValidationResult> {
    const errors: string[] = [];

    if (!this.supportedActions.includes(action)) {
      errors.push(`Unsupported action: '${action}'`);
      return { valid: false, errors };
    }

    const hasHost = typeof params.host === 'string' && params.host.length > 0;
    const hasHostId = typeof params.host_id === 'string' && params.host_id.length > 0;

    if (!hasHost && !hasHostId) {
      errors.push("Parameter 'host' (hostname) or 'host_id' (direct ID) is required");
    }

    return errors.length > 0 ? { valid: false, errors } : { valid: true };
  }

  // -------------------------------------------------------------------------
  // Private: Mode Handlers
  // -------------------------------------------------------------------------

  private executeDryRun(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    const durationMs = Math.round(performance.now() - start);
    const host = (params.host as string | undefined) ?? (params.host_id as string | undefined) ?? 'unknown';

    return this.successResult(action, durationMs, {
      dry_run: true,
      action,
      host,
      message: `Would ${action === 'isolate_host' ? 'isolate' : 'restore connectivity for'} host '${host}'`,
    });
  }

  private executeSimulation(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    const durationMs = Math.round(performance.now() - start);
    const host = (params.host as string | undefined) ?? (params.host_id as string | undefined) ?? 'unknown';

    return this.successResult(action, durationMs, {
      simulated: true,
      action,
      host,
      isolation_id: `sim-iso-${Date.now()}`,
      status: action === 'isolate_host' ? 'contained' : 'lifted',
      message: `Simulated ${action === 'isolate_host' ? 'isolation' : 'connectivity restoration'} for host '${host}'`,
    }, {
      mode: 'simulation',
      vendor: this.getVendor(),
    });
  }

  private async executeProduction(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const hostId = await this.resolveHostId(params);
    const vendor = this.getVendor();

    let response: Response;

    if (vendor === 'crowdstrike') {
      response = await this.executeCrowdStrike(action, hostId);
    } else {
      response = await this.executeGenericEDR(action, hostId);
    }

    const durationMs = Math.round(performance.now() - start);

    if (!response.ok) {
      const body = await response.text().catch(() => 'No response body');
      return this.failureResult(
        action,
        durationMs,
        'API_ERROR',
        `EDR API returned ${response.status}: ${body}`,
        response.status >= 500,
      );
    }

    const body: unknown = await response.json().catch(() => ({}));

    return this.successResult(action, durationMs, {
      host_id: hostId,
      status: action === 'isolate_host' ? 'contained' : 'lifted',
      api_response: body,
    }, {
      mode: 'production',
      vendor,
      status_code: response.status,
    });
  }

  // -------------------------------------------------------------------------
  // Private: Vendor-Specific API Calls
  // -------------------------------------------------------------------------

  private async executeCrowdStrike(
    action: StepAction,
    hostId: string,
  ): Promise<Response> {
    const baseUrl = this.getBaseUrl();
    const actionName = action === 'isolate_host' ? 'contain' : 'lift_containment';

    return fetch(
      `${baseUrl}/devices/entities/devices-actions/v2`,
      {
        method: 'POST',
        headers: this.buildHeaders(),
        body: JSON.stringify({
          action_name: actionName,
          ids: [hostId],
        }),
        signal: AbortSignal.timeout(this.getTimeoutMs()),
      },
    );
  }

  private async executeGenericEDR(
    action: StepAction,
    hostId: string,
  ): Promise<Response> {
    const baseUrl = this.getBaseUrl();
    const endpoint = action === 'isolate_host'
      ? `${baseUrl}/api/isolate`
      : `${baseUrl}/api/unisolate`;

    return fetch(endpoint, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify({ host_id: hostId }),
      signal: AbortSignal.timeout(this.getTimeoutMs()),
    });
  }

  // -------------------------------------------------------------------------
  // Private: Host ID Resolution
  // -------------------------------------------------------------------------

  /**
   * Resolve a host ID from params. If only a hostname is provided,
   * look it up via the EDR API.
   */
  private async resolveHostId(
    params: Record<string, unknown>,
  ): Promise<string> {
    if (typeof params.host_id === 'string' && params.host_id.length > 0) {
      return params.host_id;
    }

    const hostname = params.host as string | undefined;
    if (!hostname) {
      throw new Error("Parameter 'host' or 'host_id' is required");
    }

    return this.lookupHostId(hostname);
  }

  /**
   * Look up a host ID by hostname via the EDR API.
   * CrowdStrike: GET /devices/queries/devices/v1?filter=hostname:'<host>'
   * Generic/Wazuh: GET /api/hosts?hostname=<host>
   */
  private async lookupHostId(hostname: string): Promise<string> {
    const baseUrl = this.getBaseUrl();
    const vendor = this.getVendor();

    let url: string;
    if (vendor === 'crowdstrike') {
      url = `${baseUrl}/devices/queries/devices/v1?filter=hostname:'${encodeURIComponent(hostname)}'`;
    } else {
      url = `${baseUrl}/api/hosts?hostname=${encodeURIComponent(hostname)}`;
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(this.getTimeoutMs()),
    });

    if (!response.ok) {
      throw new Error(
        `Host lookup failed for '${hostname}': API returned ${response.status}`,
      );
    }

    const body = (await response.json()) as Record<string, unknown>;

    // CrowdStrike returns { resources: [id1, id2, ...] }
    if (vendor === 'crowdstrike') {
      const resources = body.resources as string[] | undefined;
      if (!resources || resources.length === 0) {
        throw new Error(`Host not found: '${hostname}'`);
      }
      return resources[0] as string;
    }

    // Generic/Wazuh returns { host_id: '...' } or { id: '...' }
    const hostId = (body.host_id ?? body.id) as string | undefined;
    if (!hostId) {
      throw new Error(`Host not found: '${hostname}'`);
    }
    return hostId;
  }

  // -------------------------------------------------------------------------
  // Private: Helpers
  // -------------------------------------------------------------------------

  private getVendor(): EDRVendor {
    return (this.config?.config.vendor as EDRVendor) ?? 'generic';
  }

  private getBaseUrl(): string {
    const url = this.config?.config.base_url as string | undefined;
    if (!url) {
      throw new Error('HostIsolationAdapter: base_url is not configured');
    }
    return url.replace(/\/+$/, '');
  }

  private getApiKey(): string | undefined {
    return this.config?.credentials?.credentials.api_key;
  }

  private getTimeoutMs(): number {
    return (this.config?.timeout ?? 30) * 1000;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    const apiKey = this.getApiKey();
    if (apiKey) {
      const vendor = this.getVendor();
      if (vendor === 'crowdstrike') {
        headers['Authorization'] = `Bearer ${apiKey}`;
      } else {
        headers['X-API-Key'] = apiKey;
      }
    }

    return headers;
  }

  private getReverseAction(action: StepAction): StepAction {
    switch (action) {
      case 'isolate_host':
        return 'restore_connectivity';
      case 'restore_connectivity':
        return 'isolate_host';
      default:
        throw new Error(`No reverse action defined for '${action}'`);
    }
  }
}
