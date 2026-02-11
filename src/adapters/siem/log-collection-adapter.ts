/**
 * SIEM Log Collection Adapter
 *
 * Handles log collection and querying against Elasticsearch/OpenSearch SIEM backends.
 * Supports actions: collect_logs, query_siem, collect_network_traffic,
 * snapshot_memory, collect_file_metadata.
 *
 * All actions are read-only; rollback is not applicable.
 *
 * @module adapters/siem/log-collection-adapter
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
// Constants
// ---------------------------------------------------------------------------

const SUPPORTED_ACTIONS: readonly StepAction[] = [
  'collect_logs',
  'query_siem',
  'collect_network_traffic',
  'snapshot_memory',
  'collect_file_metadata',
] as const;

// ---------------------------------------------------------------------------
// Log Collection Adapter
// ---------------------------------------------------------------------------

export class LogCollectionAdapter extends BaseAdapter {
  readonly name = 'siem-log-collection';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = SUPPORTED_ACTIONS;

  private baseUrl = '';
  private apiKey = '';

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);

    this.baseUrl = String(config.config.base_url ?? '').replace(/\/+$/, '');
    this.apiKey = config.credentials?.credentials.api_key ?? '';
  }

  // -----------------------------------------------------------------------
  // Execute
  // -----------------------------------------------------------------------

  override async execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    if (mode === 'dry-run') {
      return this.executeDryRun(action, params);
    }

    if (mode === 'simulation') {
      return this.executeSimulation(action, params);
    }

    // Production mode
    return this.executeProduction(action, params);
  }

  // -----------------------------------------------------------------------
  // Rollback — read-only; delegate to base class default
  // -----------------------------------------------------------------------

  override async rollback(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    return super.rollback(action, params);
  }

  // -----------------------------------------------------------------------
  // Health Check
  // -----------------------------------------------------------------------

  override async healthCheck(): Promise<HealthCheckResult> {
    if (!this.initialized || !this.baseUrl) {
      return {
        status: 'unknown',
        message: 'Adapter not initialized or base_url not configured',
        checkedAt: new Date().toISOString(),
      };
    }

    const start = performance.now();

    try {
      const response = await fetch(`${this.baseUrl}/_cluster/health`, {
        method: 'GET',
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(10_000),
      });

      const latencyMs = Math.round(performance.now() - start);

      if (!response.ok) {
        return {
          status: 'unhealthy',
          message: `Cluster health returned HTTP ${response.status}`,
          latencyMs,
          checkedAt: new Date().toISOString(),
        };
      }

      const body = (await response.json()) as Record<string, unknown>;
      const clusterStatus = String(body.status ?? 'unknown');

      const status =
        clusterStatus === 'green'
          ? 'healthy'
          : clusterStatus === 'yellow'
            ? 'degraded'
            : 'unhealthy';

      return {
        status,
        message: `Cluster status: ${clusterStatus}`,
        latencyMs,
        checkedAt: new Date().toISOString(),
      };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - start);
      const message = err instanceof Error ? err.message : String(err);
      return {
        status: 'unhealthy',
        message: `Health check failed: ${message}`,
        latencyMs,
        checkedAt: new Date().toISOString(),
      };
    }
  }

  // -----------------------------------------------------------------------
  // Capabilities
  // -----------------------------------------------------------------------

  override getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: false,
      supportsValidation: true,
      maxConcurrency: 10,
    };
  }

  // -----------------------------------------------------------------------
  // Parameter Validation
  // -----------------------------------------------------------------------

  async validateParameters(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<ValidationResult> {
    const errors: string[] = [];

    if (!this.supportedActions.includes(action)) {
      return { valid: false, errors: [`Unsupported action: ${action}`] };
    }

    switch (action) {
      case 'collect_logs':
      case 'query_siem':
        if (!params.query) {
          errors.push("Parameter 'query' is required for " + action);
        }
        break;

      case 'collect_network_traffic':
        if (!params.host && !params.ip) {
          errors.push("Parameter 'host' or 'ip' is required for collect_network_traffic");
        }
        break;

      case 'snapshot_memory':
        if (!params.host_id && !params.host) {
          errors.push("Parameter 'host_id' or 'host' is required for snapshot_memory");
        }
        break;

      case 'collect_file_metadata':
        if (!params.path && !params.hash) {
          errors.push("Parameter 'path' or 'hash' is required for collect_file_metadata");
        }
        break;
    }

    return errors.length > 0
      ? { valid: false, errors }
      : { valid: true };
  }

  // -----------------------------------------------------------------------
  // Private — Dry-run
  // -----------------------------------------------------------------------

  private executeDryRun(
    action: StepAction,
    params: Record<string, unknown>,
  ): AdapterResult {
    const validation = this.validateParamsSync(action, params);
    if (!validation.valid) {
      return this.failureResult(
        action,
        0,
        'VALIDATION_ERROR',
        `Dry-run validation failed: ${validation.errors!.join('; ')}`,
      );
    }

    return this.successResult(action, 0, {
      dry_run: true,
      action,
      params_valid: true,
      message: `Parameters validated for '${action}'. No execution performed.`,
    });
  }

  // -----------------------------------------------------------------------
  // Private — Simulation
  // -----------------------------------------------------------------------

  private executeSimulation(
    action: StepAction,
    params: Record<string, unknown>,
  ): AdapterResult {
    const start = performance.now();

    switch (action) {
      case 'collect_logs':
      case 'query_siem':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          event_count: 25,
          events: generateSampleLogEvents(5),
          query_time_ms: 42,
        }, { mode: 'simulation' });

      case 'collect_network_traffic':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          event_count: 10,
          events: generateSampleNetworkEvents(3, params),
          query_time_ms: 35,
        }, { mode: 'simulation' });

      case 'snapshot_memory':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          snapshot_id: 'sim-snap-001',
          host: params.host_id ?? params.host ?? 'unknown',
          initiated_at: new Date().toISOString(),
        }, { mode: 'simulation' });

      case 'collect_file_metadata':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          path: params.path ?? '/var/log/sample.log',
          hash: params.hash ?? 'abc123def456',
          size: 4096,
          modified_at: new Date().toISOString(),
          owner: 'root',
        }, { mode: 'simulation' });

      default:
        return this.failureResult(action, elapsed(start), 'UNSUPPORTED', `Unknown action: ${action}`);
    }
  }

  // -----------------------------------------------------------------------
  // Private — Production
  // -----------------------------------------------------------------------

  private async executeProduction(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    const start = performance.now();

    try {
      switch (action) {
        case 'collect_logs':
        case 'query_siem':
          return await this.executeLogQuery(action, params, start);

        case 'collect_network_traffic':
          return await this.executeNetworkQuery(action, params, start);

        case 'snapshot_memory':
          return await this.executeMemorySnapshot(action, params, start);

        case 'collect_file_metadata':
          return await this.executeFileMetadataQuery(action, params, start);

        default:
          return this.failureResult(action, elapsed(start), 'UNSUPPORTED', `Unknown action: ${action}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.failureResult(
        action,
        elapsed(start),
        'SIEM_ERROR',
        `SIEM query failed: ${message}`,
        true,
      );
    }
  }

  // -----------------------------------------------------------------------
  // Private — Log / SIEM query
  // -----------------------------------------------------------------------

  private async executeLogQuery(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const index = String(params.index ?? 'logs-*');
    const limit = Number(params.limit ?? 100);
    const query = params.query;
    const timeRange = params.time_range as { from?: string; to?: string } | undefined;

    const dslQuery = this.buildElasticsearchQuery(query, timeRange, limit);

    const response = await fetch(`${this.baseUrl}/${index}/_search`, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(dslQuery),
      signal: AbortSignal.timeout(this.config?.timeout ? this.config.timeout * 1000 : 30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'SIEM_QUERY_ERROR',
        `Elasticsearch returned HTTP ${response.status}: ${body}`,
        response.status >= 500,
      );
    }

    const result = (await response.json()) as Record<string, unknown>;
    const hits = result.hits as Record<string, unknown> | undefined;
    const hitsArray = (hits?.hits ?? []) as Array<Record<string, unknown>>;
    const took = Number(result.took ?? 0);

    return this.successResult(action, elapsed(start), {
      event_count: hitsArray.length,
      events: hitsArray.map((h) => h._source),
      query_time_ms: took,
    });
  }

  // -----------------------------------------------------------------------
  // Private — Network traffic query
  // -----------------------------------------------------------------------

  private async executeNetworkQuery(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const index = String(params.index ?? 'network-*');
    const limit = Number(params.limit ?? 100);
    const host = params.host ?? params.ip;
    const timeRange = params.time_range as { from?: string; to?: string } | undefined;

    const query = {
      bool: {
        should: [
          { match: { 'source.ip': host } },
          { match: { 'destination.ip': host } },
          { match: { 'host.name': host } },
        ],
        minimum_should_match: 1,
      },
    };

    const dslQuery = this.buildElasticsearchQuery(query, timeRange, limit);

    const response = await fetch(`${this.baseUrl}/${index}/_search`, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(dslQuery),
      signal: AbortSignal.timeout(this.config?.timeout ? this.config.timeout * 1000 : 30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'SIEM_QUERY_ERROR',
        `Network query returned HTTP ${response.status}: ${body}`,
        response.status >= 500,
      );
    }

    const result = (await response.json()) as Record<string, unknown>;
    const hits = result.hits as Record<string, unknown> | undefined;
    const hitsArray = (hits?.hits ?? []) as Array<Record<string, unknown>>;
    const took = Number(result.took ?? 0);

    return this.successResult(action, elapsed(start), {
      event_count: hitsArray.length,
      events: hitsArray.map((h) => h._source),
      query_time_ms: took,
    });
  }

  // -----------------------------------------------------------------------
  // Private — Memory snapshot
  // -----------------------------------------------------------------------

  private async executeMemorySnapshot(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const host = String(params.host_id ?? params.host ?? '');

    // Memory snapshot via a custom endpoint (vendor-specific)
    const snapshotUrl = `${this.baseUrl}/_snapshot/memory/${host}`;

    const response = await fetch(snapshotUrl, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify({ host, initiated_at: new Date().toISOString() }),
      signal: AbortSignal.timeout(this.config?.timeout ? this.config.timeout * 1000 : 60_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'SNAPSHOT_ERROR',
        `Memory snapshot request failed (HTTP ${response.status}): ${body}`,
        response.status >= 500,
      );
    }

    const result = (await response.json()) as Record<string, unknown>;

    return this.successResult(action, elapsed(start), {
      snapshot_id: result.snapshot_id ?? result.id ?? `snap-${Date.now()}`,
      host,
      initiated_at: result.initiated_at ?? new Date().toISOString(),
    });
  }

  // -----------------------------------------------------------------------
  // Private — File metadata query
  // -----------------------------------------------------------------------

  private async executeFileMetadataQuery(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const index = String(params.index ?? 'filebeat-*');
    const filePath = params.path as string | undefined;
    const fileHash = params.hash as string | undefined;
    const host = params.host as string | undefined;

    const mustClauses: Array<Record<string, unknown>> = [];
    if (filePath) {
      mustClauses.push({ match: { 'file.path': filePath } });
    }
    if (fileHash) {
      mustClauses.push({
        bool: {
          should: [
            { match: { 'file.hash.sha256': fileHash } },
            { match: { 'file.hash.sha1': fileHash } },
            { match: { 'file.hash.md5': fileHash } },
          ],
          minimum_should_match: 1,
        },
      });
    }
    if (host) {
      mustClauses.push({ match: { 'host.name': host } });
    }

    const dslQuery = {
      size: 1,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: { bool: { must: mustClauses } },
    };

    const response = await fetch(`${this.baseUrl}/${index}/_search`, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(dslQuery),
      signal: AbortSignal.timeout(this.config?.timeout ? this.config.timeout * 1000 : 30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'SIEM_QUERY_ERROR',
        `File metadata query returned HTTP ${response.status}: ${body}`,
        response.status >= 500,
      );
    }

    const result = (await response.json()) as Record<string, unknown>;
    const hits = result.hits as Record<string, unknown> | undefined;
    const hitsArray = (hits?.hits ?? []) as Array<Record<string, unknown>>;

    if (hitsArray.length === 0) {
      return this.successResult(action, elapsed(start), {
        found: false,
        message: 'No file metadata found matching the query',
      });
    }

    const hit = hitsArray[0] as Record<string, unknown>;
    const source = hit._source as Record<string, unknown>;
    const file = (source.file ?? {}) as Record<string, unknown>;
    const hashInfo = (file.hash ?? {}) as Record<string, unknown>;

    return this.successResult(action, elapsed(start), {
      found: true,
      path: file.path ?? filePath,
      hash: hashInfo.sha256 ?? hashInfo.sha1 ?? hashInfo.md5 ?? fileHash,
      size: file.size,
      modified_at: file.mtime ?? source['@timestamp'],
      owner: file.owner,
    });
  }

  // -----------------------------------------------------------------------
  // Private — Helpers
  // -----------------------------------------------------------------------

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['Authorization'] = `ApiKey ${this.apiKey}`;
    }

    return headers;
  }

  private buildElasticsearchQuery(
    query: unknown,
    timeRange: { from?: string; to?: string } | undefined,
    limit: number,
  ): Record<string, unknown> {
    // Accept either a raw DSL object or a simple string query
    const queryClause = typeof query === 'string'
      ? { query_string: { query } }
      : (query as Record<string, unknown>);

    const mustClauses: unknown[] = [queryClause];

    if (timeRange) {
      mustClauses.push({
        range: {
          '@timestamp': {
            ...(timeRange.from ? { gte: timeRange.from } : {}),
            ...(timeRange.to ? { lte: timeRange.to } : {}),
          },
        },
      });
    }

    return {
      size: limit,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: {
        bool: {
          must: mustClauses,
        },
      },
    };
  }

  /**
   * Synchronous validation helper for dry-run mode (avoids async overhead).
   */
  private validateParamsSync(
    action: StepAction,
    params: Record<string, unknown>,
  ): ValidationResult {
    const errors: string[] = [];

    switch (action) {
      case 'collect_logs':
      case 'query_siem':
        if (!params.query) {
          errors.push("Parameter 'query' is required");
        }
        break;

      case 'collect_network_traffic':
        if (!params.host && !params.ip) {
          errors.push("Parameter 'host' or 'ip' is required");
        }
        break;

      case 'snapshot_memory':
        if (!params.host_id && !params.host) {
          errors.push("Parameter 'host_id' or 'host' is required");
        }
        break;

      case 'collect_file_metadata':
        if (!params.path && !params.hash) {
          errors.push("Parameter 'path' or 'hash' is required");
        }
        break;
    }

    return errors.length > 0
      ? { valid: false, errors }
      : { valid: true };
  }
}

// ---------------------------------------------------------------------------
// Simulated ECS Log Events
// ---------------------------------------------------------------------------

function generateSampleLogEvents(count: number): Array<Record<string, unknown>> {
  const events: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i++) {
    events.push({
      '@timestamp': new Date(Date.now() - i * 60_000).toISOString(),
      'event.kind': 'event',
      'event.category': ['process'],
      'event.action': 'process_started',
      'host.name': `workstation-${i + 1}`,
      'host.os.family': 'windows',
      'process.name': 'powershell.exe',
      'process.pid': 1000 + i,
      'process.command_line': `powershell.exe -EncodedCommand ${Buffer.from(`sample-${i}`).toString('base64')}`,
      'user.name': `analyst${i + 1}`,
      'source.ip': `10.0.${i}.${100 + i}`,
      message: `Simulated log event ${i + 1}`,
    });
  }
  return events;
}

function generateSampleNetworkEvents(
  count: number,
  params: Record<string, unknown>,
): Array<Record<string, unknown>> {
  const host = String(params.host ?? params.ip ?? '10.0.0.1');
  const events: Array<Record<string, unknown>> = [];
  for (let i = 0; i < count; i++) {
    events.push({
      '@timestamp': new Date(Date.now() - i * 30_000).toISOString(),
      'event.kind': 'event',
      'event.category': ['network'],
      'event.action': 'network_flow',
      'source.ip': host,
      'source.port': 49152 + i,
      'destination.ip': `203.0.113.${10 + i}`,
      'destination.port': 443,
      'network.protocol': 'tcp',
      'network.bytes': 1024 * (i + 1),
      'network.direction': 'outbound',
    });
  }
  return events;
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function elapsed(start: number): number {
  return Math.round(performance.now() - start);
}
