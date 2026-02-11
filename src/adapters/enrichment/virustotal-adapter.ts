/**
 * VirusTotal Enrichment Adapter
 *
 * Provides threat intelligence enrichment via the VirusTotal API v3.
 * Supports actions: enrich_ioc, check_reputation, query_threat_feed, calculate_hash.
 *
 * Rate limiting is enforced for the free-tier API (4 requests/minute).
 * The calculate_hash action runs locally and does not consume API quota.
 *
 * All actions are read-only; rollback is not applicable.
 *
 * @module adapters/enrichment/virustotal-adapter
 */

import { createHash } from 'node:crypto';
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
  'enrich_ioc',
  'check_reputation',
  'query_threat_feed',
  'calculate_hash',
] as const;

const DEFAULT_VT_BASE_URL = 'https://www.virustotal.com/api/v3';

/** VT free-tier: 4 requests per minute (15 000 ms between requests to be safe). */
const RATE_LIMIT_INTERVAL_MS = 15_000;

type IocType = 'hash' | 'domain' | 'ip' | 'url';
type HashAlgorithm = 'md5' | 'sha1' | 'sha256';

// ---------------------------------------------------------------------------
// VirusTotal Adapter
// ---------------------------------------------------------------------------

export class VirusTotalAdapter extends BaseAdapter {
  readonly name = 'virustotal';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = SUPPORTED_ACTIONS;

  private baseUrl = DEFAULT_VT_BASE_URL;
  private apiKey = '';

  /** Timestamp of the last outbound API request (for rate limiting). */
  private lastRequestTime = 0;

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);

    this.apiKey = config.credentials?.credentials.api_key ?? '';
    if (config.config.base_url) {
      this.baseUrl = String(config.config.base_url).replace(/\/+$/, '');
    }
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
    if (!this.initialized) {
      return {
        status: 'unknown',
        message: 'Adapter not initialized',
        checkedAt: new Date().toISOString(),
      };
    }

    if (!this.apiKey) {
      return {
        status: 'unhealthy',
        message: 'No API key configured',
        checkedAt: new Date().toISOString(),
      };
    }

    const start = performance.now();

    try {
      // Lightweight check: request the API root or a minimal metadata endpoint
      const response = await fetch(`${this.baseUrl}/metadata`, {
        method: 'GET',
        headers: this.buildHeaders(),
        signal: AbortSignal.timeout(10_000),
      });

      const latencyMs = Math.round(performance.now() - start);

      if (response.status === 200) {
        return {
          status: 'healthy',
          message: 'VirusTotal API reachable',
          latencyMs,
          checkedAt: new Date().toISOString(),
        };
      }

      if (response.status === 429) {
        return {
          status: 'degraded',
          message: 'VirusTotal API rate limit reached',
          latencyMs,
          checkedAt: new Date().toISOString(),
        };
      }

      return {
        status: 'unhealthy',
        message: `VirusTotal API returned HTTP ${response.status}`,
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
      maxConcurrency: 4,
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
      case 'enrich_ioc':
        if (!params.ioc) {
          errors.push("Parameter 'ioc' is required for enrich_ioc");
        }
        if (!params.ioc_type) {
          errors.push("Parameter 'ioc_type' is required for enrich_ioc");
        } else if (!isValidIocType(params.ioc_type)) {
          errors.push(`Invalid ioc_type '${String(params.ioc_type)}'. Must be one of: hash, domain, ip, url`);
        }
        break;

      case 'check_reputation':
        if (!params.ioc) {
          errors.push("Parameter 'ioc' is required for check_reputation");
        }
        if (!params.ioc_type) {
          errors.push("Parameter 'ioc_type' is required for check_reputation");
        } else if (!isValidIocType(params.ioc_type)) {
          errors.push(`Invalid ioc_type '${String(params.ioc_type)}'. Must be one of: hash, domain, ip, url`);
        }
        break;

      case 'query_threat_feed':
        // filter is optional — no required params
        break;

      case 'calculate_hash':
        if (!params.data) {
          errors.push("Parameter 'data' is required for calculate_hash");
        }
        if (params.algorithm && !isValidHashAlgorithm(params.algorithm)) {
          errors.push(`Invalid algorithm '${String(params.algorithm)}'. Must be one of: md5, sha1, sha256`);
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
      case 'enrich_ioc':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          ioc: params.ioc,
          ioc_type: params.ioc_type,
          detections: 12,
          total_engines: 70,
          threat_label: 'trojan.generic/agent',
          score: 12 / 70,
          last_analysis_date: new Date().toISOString(),
          tags: ['trojan', 'agent', 'windows'],
        }, { mode: 'simulation' });

      case 'check_reputation':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          ioc: params.ioc,
          ioc_type: params.ioc_type,
          reputation: -45,
          harmless: 55,
          malicious: 12,
          suspicious: 3,
          undetected: 0,
        }, { mode: 'simulation' });

      case 'query_threat_feed':
        return this.successResult(action, elapsed(start), {
          simulated: true,
          notifications: [
            {
              id: 'sim-notif-001',
              rule_name: 'Cobalt Strike Beacon',
              date: new Date().toISOString(),
              tags: ['apt', 'cobalt-strike'],
            },
            {
              id: 'sim-notif-002',
              rule_name: 'Mimikatz Hash Match',
              date: new Date().toISOString(),
              tags: ['credential-theft', 'mimikatz'],
            },
          ],
          count: 2,
        }, { mode: 'simulation' });

      case 'calculate_hash': {
        // calculate_hash is local — run it even in simulation
        const data = String(params.data ?? '');
        const algorithm = (params.algorithm as HashAlgorithm) ?? 'sha256';
        const hash = createHash(algorithm).update(data).digest('hex');
        return this.successResult(action, elapsed(start), {
          hash,
          algorithm,
        });
      }

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
        case 'enrich_ioc':
          return await this.executeEnrichIoc(action, params, start);

        case 'check_reputation':
          return await this.executeCheckReputation(action, params, start);

        case 'query_threat_feed':
          return await this.executeQueryThreatFeed(action, params, start);

        case 'calculate_hash':
          return this.executeCalculateHash(action, params, start);

        default:
          return this.failureResult(action, elapsed(start), 'UNSUPPORTED', `Unknown action: ${action}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.failureResult(
        action,
        elapsed(start),
        'VT_ERROR',
        `VirusTotal request failed: ${message}`,
        true,
      );
    }
  }

  // -----------------------------------------------------------------------
  // Private — enrich_ioc
  // -----------------------------------------------------------------------

  private async executeEnrichIoc(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const ioc = String(params.ioc);
    const iocType = params.ioc_type as IocType;

    const endpoint = this.resolveIocEndpoint(ioc, iocType);
    await this.enforceRateLimit();

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'VT_API_ERROR',
        `VirusTotal returned HTTP ${response.status}: ${body}`,
        response.status === 429,
      );
    }

    const json = (await response.json()) as Record<string, unknown>;
    const data = (json.data ?? {}) as Record<string, unknown>;
    const attributes = (data.attributes ?? {}) as Record<string, unknown>;
    const lastAnalysis = (attributes.last_analysis_stats ?? {}) as Record<string, number>;
    const malicious = lastAnalysis.malicious ?? 0;
    const totalEngines =
      (lastAnalysis.malicious ?? 0) +
      (lastAnalysis.undetected ?? 0) +
      (lastAnalysis.harmless ?? 0) +
      (lastAnalysis.suspicious ?? 0);

    return this.successResult(action, elapsed(start), {
      detections: malicious,
      total_engines: totalEngines,
      threat_label: attributes.popular_threat_classification
        ? String(
            (
              (attributes.popular_threat_classification as Record<string, unknown>)
                .suggested_threat_label ?? 'unknown'
            ),
          )
        : 'unknown',
      score: totalEngines > 0 ? malicious / totalEngines : 0,
      last_analysis_date: attributes.last_analysis_date
        ? new Date(Number(attributes.last_analysis_date) * 1000).toISOString()
        : null,
      tags: attributes.tags ?? [],
    });
  }

  // -----------------------------------------------------------------------
  // Private — check_reputation
  // -----------------------------------------------------------------------

  private async executeCheckReputation(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const ioc = String(params.ioc);
    const iocType = params.ioc_type as IocType;

    const endpoint = this.resolveIocEndpoint(ioc, iocType);
    await this.enforceRateLimit();

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'VT_API_ERROR',
        `VirusTotal returned HTTP ${response.status}: ${body}`,
        response.status === 429,
      );
    }

    const json = (await response.json()) as Record<string, unknown>;
    const data = (json.data ?? {}) as Record<string, unknown>;
    const attributes = (data.attributes ?? {}) as Record<string, unknown>;
    const lastAnalysis = (attributes.last_analysis_stats ?? {}) as Record<string, number>;

    return this.successResult(action, elapsed(start), {
      reputation: attributes.reputation ?? 0,
      harmless: lastAnalysis.harmless ?? 0,
      malicious: lastAnalysis.malicious ?? 0,
      suspicious: lastAnalysis.suspicious ?? 0,
      undetected: lastAnalysis.undetected ?? 0,
    });
  }

  // -----------------------------------------------------------------------
  // Private — query_threat_feed
  // -----------------------------------------------------------------------

  private async executeQueryThreatFeed(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    const filter = params.filter as string | undefined;
    const url = filter
      ? `${this.baseUrl}/intelligence/hunting_notification_files?filter=${encodeURIComponent(filter)}`
      : `${this.baseUrl}/intelligence/hunting_notification_files`;

    await this.enforceRateLimit();

    const response = await fetch(url, {
      method: 'GET',
      headers: this.buildHeaders(),
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      const body = await response.text();
      return this.failureResult(
        action,
        elapsed(start),
        'VT_API_ERROR',
        `VirusTotal threat feed returned HTTP ${response.status}: ${body}`,
        response.status === 429,
      );
    }

    const json = (await response.json()) as Record<string, unknown>;
    const dataArray = (json.data ?? []) as Array<Record<string, unknown>>;

    return this.successResult(action, elapsed(start), {
      notifications: dataArray.map((item) => ({
        id: item.id,
        type: item.type,
        attributes: item.attributes,
      })),
      count: dataArray.length,
    });
  }

  // -----------------------------------------------------------------------
  // Private — calculate_hash (local, no API call)
  // -----------------------------------------------------------------------

  private executeCalculateHash(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    const data = String(params.data ?? '');
    const algorithm = (params.algorithm as HashAlgorithm) ?? 'sha256';

    const hash = createHash(algorithm).update(data).digest('hex');

    return this.successResult(action, elapsed(start), {
      hash,
      algorithm,
    });
  }

  // -----------------------------------------------------------------------
  // Private — Helpers
  // -----------------------------------------------------------------------

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };

    if (this.apiKey) {
      headers['x-apikey'] = this.apiKey;
    }

    return headers;
  }

  /**
   * Map IOC type to the VT v3 API endpoint path.
   * For URLs, the value must be base64url-encoded per VT docs.
   */
  private resolveIocEndpoint(ioc: string, iocType: IocType): string {
    switch (iocType) {
      case 'hash':
        return `/files/${encodeURIComponent(ioc)}`;
      case 'domain':
        return `/domains/${encodeURIComponent(ioc)}`;
      case 'ip':
        return `/ip_addresses/${encodeURIComponent(ioc)}`;
      case 'url': {
        // VT v3 expects the URL identifier as a base64url-encoded string (no padding)
        const urlId = Buffer.from(ioc).toString('base64url');
        return `/urls/${urlId}`;
      }
    }
  }

  /**
   * Enforce VT free-tier rate limit by sleeping if requests arrive too quickly.
   * Tracks time between API calls and waits the remainder of the interval.
   */
  private async enforceRateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLast = now - this.lastRequestTime;

    if (this.lastRequestTime > 0 && timeSinceLast < RATE_LIMIT_INTERVAL_MS) {
      const waitMs = RATE_LIMIT_INTERVAL_MS - timeSinceLast;
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }

    this.lastRequestTime = Date.now();
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
      case 'enrich_ioc':
        if (!params.ioc) errors.push("Parameter 'ioc' is required");
        if (!params.ioc_type) errors.push("Parameter 'ioc_type' is required");
        else if (!isValidIocType(params.ioc_type)) {
          errors.push(`Invalid ioc_type '${String(params.ioc_type)}'`);
        }
        break;

      case 'check_reputation':
        if (!params.ioc) errors.push("Parameter 'ioc' is required");
        if (!params.ioc_type) errors.push("Parameter 'ioc_type' is required");
        else if (!isValidIocType(params.ioc_type)) {
          errors.push(`Invalid ioc_type '${String(params.ioc_type)}'`);
        }
        break;

      case 'query_threat_feed':
        break;

      case 'calculate_hash':
        if (!params.data) errors.push("Parameter 'data' is required");
        if (params.algorithm && !isValidHashAlgorithm(params.algorithm)) {
          errors.push(`Invalid algorithm '${String(params.algorithm)}'`);
        }
        break;
    }

    return errors.length > 0
      ? { valid: false, errors }
      : { valid: true };
  }
}

// ---------------------------------------------------------------------------
// Type Guards
// ---------------------------------------------------------------------------

const VALID_IOC_TYPES: ReadonlySet<string> = new Set(['hash', 'domain', 'ip', 'url']);
const VALID_HASH_ALGORITHMS: ReadonlySet<string> = new Set(['md5', 'sha1', 'sha256']);

function isValidIocType(value: unknown): value is IocType {
  return typeof value === 'string' && VALID_IOC_TYPES.has(value);
}

function isValidHashAlgorithm(value: unknown): value is HashAlgorithm {
  return typeof value === 'string' && VALID_HASH_ALGORITHMS.has(value);
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function elapsed(start: number): number {
  return Math.round(performance.now() - start);
}
