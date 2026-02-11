import { describe, it, expect, beforeEach } from 'vitest';
import {
  EnrichmentPipeline,
  createGeoIPEnricher,
  createAssetInventoryEnricher,
  createThreatIntelEnricher,
} from '../../../src/engine/enrichment-pipeline.ts';
import type {
  EnrichmentSource,
  EnrichmentResult,
} from '../../../src/engine/enrichment-pipeline.ts';
import type { AlertEvent } from '../../../src/types/ecs.ts';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeAlert(overrides: Partial<AlertEvent> = {}): AlertEvent {
  return {
    '@timestamp': '2026-02-11T10:00:00.000Z',
    event: {
      kind: 'alert',
      category: ['malware'],
      type: ['info'],
      severity: 80,
    },
    ...overrides,
  };
}

function makeSource(overrides: Partial<EnrichmentSource> = {}): EnrichmentSource {
  const name = overrides.name ?? 'test-source';
  const type = overrides.type ?? 'custom';
  return {
    name,
    type,
    enabled: true,
    timeout_ms: 5000,
    async enrich(_alert: AlertEvent): Promise<EnrichmentResult> {
      return {
        source: name,
        type,
        success: true,
        data: { enriched: true },
        duration_ms: 10,
      };
    },
    ...overrides,
  };
}

function makeFailingSource(name = 'failing-source'): EnrichmentSource {
  return {
    name,
    type: 'custom',
    enabled: true,
    timeout_ms: 5000,
    async enrich(_alert: AlertEvent): Promise<EnrichmentResult> {
      throw new Error(`Source ${name} failed`);
    },
  };
}

function makeSlowSource(name = 'slow-source', delayMs = 10000): EnrichmentSource {
  return {
    name,
    type: 'custom',
    enabled: true,
    timeout_ms: 100, // very short timeout
    async enrich(_alert: AlertEvent): Promise<EnrichmentResult> {
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve({
            source: name,
            type: 'custom',
            success: true,
            data: { slow: true },
            duration_ms: delayMs,
          });
        }, delayMs);
      });
    },
  };
}

// ---------------------------------------------------------------------------
// Source management: registerSource / unregisterSource / listSources
// ---------------------------------------------------------------------------

describe('EnrichmentPipeline - source management', () => {
  let pipeline: EnrichmentPipeline;

  beforeEach(() => {
    pipeline = new EnrichmentPipeline();
  });

  it('starts with no sources', () => {
    expect(pipeline.listSources()).toEqual([]);
  });

  it('registers a source', () => {
    const source = makeSource();
    pipeline.registerSource(source);

    const sources = pipeline.listSources();
    expect(sources).toHaveLength(1);
    expect(sources[0]!.name).toBe('test-source');
  });

  it('registers multiple sources', () => {
    pipeline.registerSource(makeSource({ name: 'source-a' }));
    pipeline.registerSource(makeSource({ name: 'source-b' }));
    pipeline.registerSource(makeSource({ name: 'source-c' }));

    expect(pipeline.listSources()).toHaveLength(3);
  });

  it('replaces existing source with same name', () => {
    const source1 = makeSource({ name: 'geoip', timeout_ms: 1000 });
    const source2 = makeSource({ name: 'geoip', timeout_ms: 5000 });

    pipeline.registerSource(source1);
    pipeline.registerSource(source2);

    const sources = pipeline.listSources();
    expect(sources).toHaveLength(1);
    expect(sources[0]!.timeout_ms).toBe(5000);
  });

  it('unregisters a source by name', () => {
    pipeline.registerSource(makeSource({ name: 'to-remove' }));
    expect(pipeline.listSources()).toHaveLength(1);

    const removed = pipeline.unregisterSource('to-remove');
    expect(removed).toBe(true);
    expect(pipeline.listSources()).toHaveLength(0);
  });

  it('returns false when unregistering nonexistent source', () => {
    const removed = pipeline.unregisterSource('does-not-exist');
    expect(removed).toBe(false);
  });

  it('listSources returns both enabled and disabled sources', () => {
    pipeline.registerSource(makeSource({ name: 'enabled-src', enabled: true }));
    pipeline.registerSource(makeSource({ name: 'disabled-src', enabled: false }));

    const sources = pipeline.listSources();
    expect(sources).toHaveLength(2);
    expect(sources.find((s) => s.name === 'disabled-src')!.enabled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// enrich() - basic execution
// ---------------------------------------------------------------------------

describe('EnrichmentPipeline - enrich', () => {
  let pipeline: EnrichmentPipeline;

  beforeEach(() => {
    pipeline = new EnrichmentPipeline();
  });

  it('runs all enabled sources and aggregates results', async () => {
    pipeline.registerSource(makeSource({ name: 'source-a' }));
    pipeline.registerSource(makeSource({ name: 'source-b' }));

    const alert = makeAlert();
    const result = await pipeline.enrich(alert);

    expect(result.success_count).toBe(2);
    expect(result.failure_count).toBe(0);
    expect(result.enrichments).toHaveLength(2);
    expect(result.alert).toBe(alert);
  });

  it('returns empty result when no sources registered', async () => {
    const alert = makeAlert();
    const result = await pipeline.enrich(alert);

    expect(result.success_count).toBe(0);
    expect(result.failure_count).toBe(0);
    expect(result.enrichments).toEqual([]);
    expect(result.enriched_context).toEqual({});
  });

  it('skips disabled sources', async () => {
    pipeline.registerSource(makeSource({ name: 'enabled-src', enabled: true }));
    pipeline.registerSource(makeSource({ name: 'disabled-src', enabled: false }));

    const result = await pipeline.enrich(makeAlert());

    expect(result.success_count).toBe(1);
    expect(result.enrichments).toHaveLength(1);
    expect(result.enrichments[0]!.source).toBe('enabled-src');
  });

  it('returns empty result when all sources are disabled', async () => {
    pipeline.registerSource(makeSource({ name: 'disabled-a', enabled: false }));
    pipeline.registerSource(makeSource({ name: 'disabled-b', enabled: false }));

    const result = await pipeline.enrich(makeAlert());

    expect(result.success_count).toBe(0);
    expect(result.enrichments).toEqual([]);
    expect(result.enriched_context).toEqual({});
  });

  it('aggregates into enriched_context keyed by source name', async () => {
    pipeline.registerSource(makeSource({
      name: 'geo',
      async enrich(): Promise<EnrichmentResult> {
        return {
          source: 'geo',
          type: 'geoip',
          success: true,
          data: { country: 'US' },
          duration_ms: 5,
        };
      },
    }));
    pipeline.registerSource(makeSource({
      name: 'asset',
      async enrich(): Promise<EnrichmentResult> {
        return {
          source: 'asset',
          type: 'asset_inventory',
          success: true,
          data: { criticality: 'high' },
          duration_ms: 5,
        };
      },
    }));

    const result = await pipeline.enrich(makeAlert());

    expect(result.enriched_context['geo']).toEqual({ country: 'US' });
    expect(result.enriched_context['asset']).toEqual({ criticality: 'high' });
  });

  it('records total_duration_ms', async () => {
    pipeline.registerSource(makeSource());

    const result = await pipeline.enrich(makeAlert());

    expect(typeof result.total_duration_ms).toBe('number');
    expect(result.total_duration_ms).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// enrich() - failure handling
// ---------------------------------------------------------------------------

describe('EnrichmentPipeline - failure handling', () => {
  let pipeline: EnrichmentPipeline;

  beforeEach(() => {
    pipeline = new EnrichmentPipeline();
  });

  it('handles source failures gracefully (does not throw)', async () => {
    pipeline.registerSource(makeFailingSource('bad-source'));

    const result = await pipeline.enrich(makeAlert());

    expect(result.failure_count).toBe(1);
    expect(result.success_count).toBe(0);
    expect(result.enrichments).toHaveLength(1);
    expect(result.enrichments[0]!.success).toBe(false);
    expect(result.enrichments[0]!.error).toContain('bad-source failed');
  });

  it('continues processing other sources when one fails', async () => {
    pipeline.registerSource(makeSource({ name: 'good-source' }));
    pipeline.registerSource(makeFailingSource('bad-source'));

    const result = await pipeline.enrich(makeAlert());

    expect(result.success_count).toBe(1);
    expect(result.failure_count).toBe(1);
    expect(result.enrichments).toHaveLength(2);
  });

  it('does not include failed source data in enriched_context', async () => {
    pipeline.registerSource(makeFailingSource('bad-source'));

    const result = await pipeline.enrich(makeAlert());

    expect(result.enriched_context['bad-source']).toBeUndefined();
  });

  it('handles source returning success: false without throwing', async () => {
    pipeline.registerSource(makeSource({
      name: 'soft-fail',
      async enrich(): Promise<EnrichmentResult> {
        return {
          source: 'soft-fail',
          type: 'custom',
          success: false,
          data: {},
          duration_ms: 5,
          error: 'Data unavailable',
        };
      },
    }));

    const result = await pipeline.enrich(makeAlert());

    expect(result.failure_count).toBe(1);
    expect(result.success_count).toBe(0);
    expect(result.enriched_context['soft-fail']).toBeUndefined();
  });

  it('mixed success and failure sources report correct counts', async () => {
    pipeline.registerSource(makeSource({ name: 'ok-1' }));
    pipeline.registerSource(makeSource({ name: 'ok-2' }));
    pipeline.registerSource(makeFailingSource('fail-1'));
    pipeline.registerSource(makeFailingSource('fail-2'));

    const result = await pipeline.enrich(makeAlert());

    expect(result.success_count).toBe(2);
    expect(result.failure_count).toBe(2);
    expect(result.enrichments).toHaveLength(4);
  });
});

// ---------------------------------------------------------------------------
// enrich() - timeout handling
// ---------------------------------------------------------------------------

describe('EnrichmentPipeline - timeout handling', () => {
  let pipeline: EnrichmentPipeline;

  beforeEach(() => {
    pipeline = new EnrichmentPipeline();
  });

  it('respects per-source timeout and records timeout error', async () => {
    // Source with 100ms timeout but 10s delay
    pipeline.registerSource(makeSlowSource('slow', 10000));

    const result = await pipeline.enrich(makeAlert());

    expect(result.failure_count).toBe(1);
    expect(result.success_count).toBe(0);
    expect(result.enrichments).toHaveLength(1);
    expect(result.enrichments[0]!.success).toBe(false);
    expect(result.enrichments[0]!.error).toContain('timed out');
  }, 15000);

  it('fast sources complete while slow sources timeout', async () => {
    pipeline.registerSource(makeSource({ name: 'fast', timeout_ms: 5000 }));
    pipeline.registerSource(makeSlowSource('slow', 10000));

    const result = await pipeline.enrich(makeAlert());

    expect(result.success_count).toBe(1);
    expect(result.failure_count).toBe(1);
  }, 15000);
});

// ---------------------------------------------------------------------------
// Built-in enricher factories
// ---------------------------------------------------------------------------

describe('Built-in enricher factories', () => {
  it('createGeoIPEnricher returns an enabled source with geoip type', () => {
    const enricher = createGeoIPEnricher();

    expect(enricher.name).toBe('geoip');
    expect(enricher.type).toBe('geoip');
    expect(enricher.enabled).toBe(true);
    expect(enricher.timeout_ms).toBe(2000);
  });

  it('createGeoIPEnricher respects custom timeout', () => {
    const enricher = createGeoIPEnricher(500);
    expect(enricher.timeout_ms).toBe(500);
  });

  it('createGeoIPEnricher enriches alert with source IP', async () => {
    const enricher = createGeoIPEnricher();
    const alert = makeAlert({ source: { ip: '1.2.3.4' } });
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['ip']).toBe('1.2.3.4');
    expect(result.data['lookup_performed']).toBe(true);
    expect(result.data['country_iso_code']).toBe('US');
  });

  it('createGeoIPEnricher returns no-lookup result when no IP found', async () => {
    const enricher = createGeoIPEnricher();
    const alert = makeAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['lookup_performed']).toBe(false);
    expect(result.data['reason']).toBe('no_ip_found');
  });

  it('createAssetInventoryEnricher returns an enabled source', () => {
    const enricher = createAssetInventoryEnricher();

    expect(enricher.name).toBe('asset_inventory');
    expect(enricher.type).toBe('asset_inventory');
    expect(enricher.enabled).toBe(true);
    expect(enricher.timeout_ms).toBe(3000);
  });

  it('createAssetInventoryEnricher enriches alert with hostname', async () => {
    const enricher = createAssetInventoryEnricher();
    const alert = makeAlert({ host: { hostname: 'ws-001' } });
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['hostname']).toBe('ws-001');
    expect(result.data['lookup_performed']).toBe(true);
    expect(result.data['criticality']).toBe('high');
  });

  it('createAssetInventoryEnricher returns no-lookup when no hostname', async () => {
    const enricher = createAssetInventoryEnricher();
    const alert = makeAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['lookup_performed']).toBe(false);
  });

  it('createThreatIntelEnricher returns an enabled source', () => {
    const enricher = createThreatIntelEnricher();

    expect(enricher.name).toBe('threat_intel');
    expect(enricher.type).toBe('threat_intel');
    expect(enricher.enabled).toBe(true);
    expect(enricher.timeout_ms).toBe(5000);
  });

  it('createThreatIntelEnricher enriches alert with IOCs', async () => {
    const enricher = createThreatIntelEnricher();
    const alert = makeAlert({
      source: { ip: '10.0.0.1' },
      destination: { ip: '192.168.1.1' },
    });
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['lookup_performed']).toBe(true);
    expect(result.data['iocs_checked']).toBe(2);
  });

  it('createThreatIntelEnricher returns no-lookup when no IOCs', async () => {
    const enricher = createThreatIntelEnricher();
    const alert = makeAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['lookup_performed']).toBe(false);
    expect(result.data['iocs_checked']).toBe(0);
  });

  it('built-in enrichers work end-to-end in pipeline', async () => {
    const pipeline = new EnrichmentPipeline();
    pipeline.registerSource(createGeoIPEnricher());
    pipeline.registerSource(createAssetInventoryEnricher());
    pipeline.registerSource(createThreatIntelEnricher());

    const alert = makeAlert({
      source: { ip: '10.0.0.1' },
      host: { hostname: 'ws-001' },
    });

    const result = await pipeline.enrich(alert);

    expect(result.success_count).toBe(3);
    expect(result.failure_count).toBe(0);
    expect(result.enriched_context['geoip']).toBeDefined();
    expect(result.enriched_context['asset_inventory']).toBeDefined();
    expect(result.enriched_context['threat_intel']).toBeDefined();
  });
});
