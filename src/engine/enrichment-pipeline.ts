/**
 * Alert Context Enrichment Pipeline for RunbookPilot
 *
 * Enriches incoming ECS-normalized alerts with additional context before
 * playbook execution. Enrichment sources run in parallel via
 * Promise.allSettled -- individual source failures never block the pipeline.
 *
 * Each registered source has its own timeout. Results are aggregated into a
 * flat `enriched_context` map keyed by source name for downstream consumption
 * by the execution engine.
 *
 * Built-in stub enrichers (GeoIP, Asset Inventory, Threat Intel) return mock
 * data for demonstration purposes. In production these would call real APIs.
 *
 * @module engine/enrichment-pipeline
 */

import type { AlertEvent } from '../types/ecs.ts';
import type { Logger } from '../logging/logger.ts';
import { logger } from '../logging/logger.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Categories of enrichment data sources.
 */
export type EnrichmentType = 'geoip' | 'asset_inventory' | 'user_directory' | 'threat_intel' | 'custom';

/**
 * A registered enrichment source that can produce context for an alert.
 */
export interface EnrichmentSource {
  name: string;
  type: EnrichmentType;
  enabled: boolean;
  timeout_ms: number;
  enrich: (alert: AlertEvent) => Promise<EnrichmentResult>;
}

/**
 * Result from a single enrichment source execution.
 */
export interface EnrichmentResult {
  source: string;
  type: EnrichmentType;
  success: boolean;
  data: Record<string, unknown>;
  duration_ms: number;
  error?: string;
}

/**
 * Aggregated result of running the full enrichment pipeline for an alert.
 */
export interface EnrichmentPipelineResult {
  alert: AlertEvent;
  enrichments: EnrichmentResult[];
  total_duration_ms: number;
  success_count: number;
  failure_count: number;
  enriched_context: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Timeout helper
// ---------------------------------------------------------------------------

/**
 * Race a promise against a timeout. Returns the promise result if it
 * resolves in time, otherwise throws a timeout error.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Enrichment source "${label}" timed out after ${ms}ms`));
    }, ms);

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

// ---------------------------------------------------------------------------
// EnrichmentPipeline
// ---------------------------------------------------------------------------

/**
 * Orchestrates parallel enrichment of alerts from multiple sources.
 *
 * Sources are registered/unregistered dynamically. When `enrich()` is called,
 * all enabled sources run concurrently. Failures are captured -- never thrown.
 */
export class EnrichmentPipeline {
  private readonly _sources: Map<string, EnrichmentSource>;
  private readonly _log: Logger;

  constructor() {
    this._sources = new Map();
    this._log = logger.child({ component: 'enrichment-pipeline' });
  }

  // -----------------------------------------------------------------------
  // Source management
  // -----------------------------------------------------------------------

  /**
   * Register a new enrichment source.
   *
   * If a source with the same name already exists it will be replaced.
   */
  registerSource(source: EnrichmentSource): void {
    this._sources.set(source.name, source);
    this._log.info('Enrichment source registered', {
      source: source.name,
      type: source.type,
      enabled: source.enabled,
      timeout_ms: source.timeout_ms,
    });
  }

  /**
   * Unregister a source by name.
   *
   * @returns `true` if a source was removed, `false` if not found.
   */
  unregisterSource(name: string): boolean {
    const removed = this._sources.delete(name);
    if (removed) {
      this._log.info('Enrichment source unregistered', { source: name });
    }
    return removed;
  }

  /**
   * List all registered sources (both enabled and disabled).
   */
  listSources(): EnrichmentSource[] {
    return Array.from(this._sources.values());
  }

  // -----------------------------------------------------------------------
  // Pipeline execution
  // -----------------------------------------------------------------------

  /**
   * Enrich an alert by running all enabled sources in parallel.
   *
   * - Disabled sources are skipped.
   * - Each source is individually timed out per its `timeout_ms`.
   * - Failures (errors or timeouts) are captured in the result, never thrown.
   * - Results are aggregated into `enriched_context` keyed by source name.
   */
  async enrich(alert: AlertEvent): Promise<EnrichmentPipelineResult> {
    const pipelineStart = performance.now();

    const enabledSources = Array.from(this._sources.values()).filter((s) => s.enabled);

    this._log.info('Enrichment pipeline started', {
      total_sources: this._sources.size,
      enabled_sources: enabledSources.length,
    });

    if (enabledSources.length === 0) {
      this._log.info('No enabled enrichment sources, skipping enrichment');
      return {
        alert,
        enrichments: [],
        total_duration_ms: Math.round(performance.now() - pipelineStart),
        success_count: 0,
        failure_count: 0,
        enriched_context: {},
      };
    }

    // Run all enabled sources concurrently
    const settled = await Promise.allSettled(
      enabledSources.map((source) => this._runSource(source, alert)),
    );

    // Collect results
    const enrichments: EnrichmentResult[] = [];
    let successCount = 0;
    let failureCount = 0;
    const enrichedContext: Record<string, unknown> = {};

    for (let i = 0; i < settled.length; i++) {
      const outcome = settled[i]!;
      const source = enabledSources[i]!;

      if (outcome.status === 'fulfilled') {
        const result = outcome.value;
        enrichments.push(result);

        if (result.success) {
          successCount++;
          enrichedContext[source.name] = result.data;
        } else {
          failureCount++;
        }
      } else {
        // Promise.allSettled rejected -- should not happen because _runSource
        // catches everything, but handle defensively.
        failureCount++;
        enrichments.push({
          source: source.name,
          type: source.type,
          success: false,
          data: {},
          duration_ms: 0,
          error: outcome.reason instanceof Error
            ? outcome.reason.message
            : String(outcome.reason),
        });
      }
    }

    const totalDuration = Math.round(performance.now() - pipelineStart);

    this._log.info('Enrichment pipeline completed', {
      total_duration_ms: totalDuration,
      success_count: successCount,
      failure_count: failureCount,
    });

    return {
      alert,
      enrichments,
      total_duration_ms: totalDuration,
      success_count: successCount,
      failure_count: failureCount,
      enriched_context: enrichedContext,
    };
  }

  // -----------------------------------------------------------------------
  // Internal
  // -----------------------------------------------------------------------

  /**
   * Execute a single enrichment source with timeout and error handling.
   * Guaranteed to never throw.
   */
  private async _runSource(
    source: EnrichmentSource,
    alert: AlertEvent,
  ): Promise<EnrichmentResult> {
    const start = performance.now();

    this._log.debug('Running enrichment source', {
      source: source.name,
      type: source.type,
      timeout_ms: source.timeout_ms,
    });

    try {
      const result = await withTimeout(
        source.enrich(alert),
        source.timeout_ms,
        source.name,
      );

      const duration = Math.round(performance.now() - start);

      this._log.debug('Enrichment source completed', {
        source: source.name,
        success: result.success,
        duration_ms: duration,
      });

      // Ensure duration reflects actual measured time
      return { ...result, duration_ms: duration };
    } catch (err: unknown) {
      const duration = Math.round(performance.now() - start);
      const errorMessage = err instanceof Error ? err.message : String(err);

      this._log.warn('Enrichment source failed', {
        source: source.name,
        type: source.type,
        duration_ms: duration,
        error: errorMessage,
      });

      return {
        source: source.name,
        type: source.type,
        success: false,
        data: {},
        duration_ms: duration,
        error: errorMessage,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Built-in stub enrichment source factories
// ---------------------------------------------------------------------------

/**
 * Create a stub GeoIP enricher.
 *
 * Extracts the first available IP from the alert (source, destination, or
 * host) and returns mock geolocation data. In production this would call a
 * GeoIP service (e.g., MaxMind).
 */
export function createGeoIPEnricher(timeout_ms = 2000): EnrichmentSource {
  return {
    name: 'geoip',
    type: 'geoip',
    enabled: true,
    timeout_ms,
    async enrich(alert: AlertEvent): Promise<EnrichmentResult> {
      const ip = alert.source?.ip
        ?? alert.destination?.ip
        ?? alert.host?.ip?.[0];

      if (!ip) {
        return {
          source: 'geoip',
          type: 'geoip',
          success: true,
          data: { lookup_performed: false, reason: 'no_ip_found' },
          duration_ms: 0,
        };
      }

      // Stub data -- would be a real API call in production
      return {
        source: 'geoip',
        type: 'geoip',
        success: true,
        data: {
          ip,
          country_iso_code: 'US',
          country_name: 'United States',
          city_name: 'San Francisco',
          region_name: 'California',
          latitude: 37.7749,
          longitude: -122.4194,
          asn: 13335,
          as_org: 'Cloudflare Inc',
          lookup_performed: true,
        },
        duration_ms: 0,
      };
    },
  };
}

/**
 * Create a stub Asset Inventory enricher.
 *
 * Extracts the hostname from the alert and returns mock asset criticality
 * data. In production this would query a CMDB or asset management system.
 */
export function createAssetInventoryEnricher(timeout_ms = 3000): EnrichmentSource {
  return {
    name: 'asset_inventory',
    type: 'asset_inventory',
    enabled: true,
    timeout_ms,
    async enrich(alert: AlertEvent): Promise<EnrichmentResult> {
      const hostname = alert.host?.hostname ?? alert.host?.name;

      if (!hostname) {
        return {
          source: 'asset_inventory',
          type: 'asset_inventory',
          success: true,
          data: { lookup_performed: false, reason: 'no_hostname_found' },
          duration_ms: 0,
        };
      }

      // Stub data -- would query CMDB in production
      return {
        source: 'asset_inventory',
        type: 'asset_inventory',
        success: true,
        data: {
          hostname,
          asset_id: `ASSET-${hostname.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`,
          criticality: 'high',
          department: 'Engineering',
          owner: 'soc-team@example.com',
          os: alert.host?.os?.name ?? 'Unknown',
          last_seen: new Date().toISOString(),
          business_unit: 'Technology',
          environment: 'production',
          lookup_performed: true,
        },
        duration_ms: 0,
      };
    },
  };
}

/**
 * Create a stub Threat Intel enricher.
 *
 * Extracts IOCs (IPs, hashes, domains) from the alert and returns mock
 * threat intelligence data. In production this would query threat feeds
 * (VirusTotal, OTX, MISP, etc.).
 */
export function createThreatIntelEnricher(timeout_ms = 5000): EnrichmentSource {
  return {
    name: 'threat_intel',
    type: 'threat_intel',
    enabled: true,
    timeout_ms,
    async enrich(alert: AlertEvent): Promise<EnrichmentResult> {
      // Extract IOCs from the alert
      const iocs: Array<{ type: string; value: string }> = [];

      // IPs
      if (alert.source?.ip) {
        iocs.push({ type: 'ip', value: alert.source.ip });
      }
      if (alert.destination?.ip) {
        iocs.push({ type: 'ip', value: alert.destination.ip });
      }
      if (alert.host?.ip) {
        for (const ip of alert.host.ip) {
          iocs.push({ type: 'ip', value: ip });
        }
      }

      // Domains
      if (alert.source?.domain) {
        iocs.push({ type: 'domain', value: alert.source.domain });
      }
      if (alert.destination?.domain) {
        iocs.push({ type: 'domain', value: alert.destination.domain });
      }

      // File hashes
      if (alert.file?.hash) {
        if (alert.file.hash.sha256) {
          iocs.push({ type: 'sha256', value: alert.file.hash.sha256 });
        }
        if (alert.file.hash.sha1) {
          iocs.push({ type: 'sha1', value: alert.file.hash.sha1 });
        }
        if (alert.file.hash.md5) {
          iocs.push({ type: 'md5', value: alert.file.hash.md5 });
        }
      }

      // Process hashes
      if (alert.process?.hash) {
        if (alert.process.hash.sha256) {
          iocs.push({ type: 'sha256', value: alert.process.hash.sha256 });
        }
        if (alert.process.hash.sha1) {
          iocs.push({ type: 'sha1', value: alert.process.hash.sha1 });
        }
        if (alert.process.hash.md5) {
          iocs.push({ type: 'md5', value: alert.process.hash.md5 });
        }
      }

      // Threat indicator from ECS threat fields
      if (alert.threat?.indicator?.value) {
        iocs.push({
          type: alert.threat.indicator.type ?? 'unknown',
          value: alert.threat.indicator.value,
        });
      }

      if (iocs.length === 0) {
        return {
          source: 'threat_intel',
          type: 'threat_intel',
          success: true,
          data: { lookup_performed: false, reason: 'no_iocs_found', iocs_checked: 0 },
          duration_ms: 0,
        };
      }

      // Stub threat intel results -- would call real APIs in production
      const iocResults = iocs.map((ioc) => ({
        ...ioc,
        malicious: false,
        confidence: 0,
        first_seen: '2025-01-15T00:00:00.000Z',
        last_seen: new Date().toISOString(),
        sources: ['stub-feed'],
        tags: [] as string[],
      }));

      return {
        source: 'threat_intel',
        type: 'threat_intel',
        success: true,
        data: {
          iocs_checked: iocs.length,
          ioc_results: iocResults,
          overall_risk: 'low',
          lookup_performed: true,
        },
        duration_ms: 0,
      };
    },
  };
}
