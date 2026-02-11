/**
 * Integration Tests: End-to-End Alert Processing Pipeline
 *
 * Tests the full flow: alert ingestion → trigger evaluation →
 * playbook matching → enrichment → execution controller lifecycle.
 *
 * Uses real modules with in-memory DB (no mocks).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'path';
import { initDatabase, closeDatabase } from '../../src/db/index.ts';
import { ingestFromString, validateAlertEvent } from '../../src/ingest/alert-ingestor.ts';
import { PlaybookMatcher } from '../../src/engine/playbook-matcher.ts';
import { evaluateTrigger } from '../../src/engine/trigger-evaluator.ts';
import type { RunbookTrigger } from '../../src/types/playbook.ts';
import {
  EnrichmentPipeline,
  createGeoIPEnricher,
  createAssetInventoryEnricher,
  createThreatIntelEnricher,
} from '../../src/engine/enrichment-pipeline.ts';
import { ExecutionController } from '../../src/engine/execution-controller.ts';
import { AuditLogger } from '../../src/engine/audit-logger.ts';
import { ExecutionRepository } from '../../src/db/execution-repository.ts';
import type { AlertEvent } from '../../src/types/ecs.ts';
import type Database from 'better-sqlite3';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFIG_PATH = resolve(process.cwd(), 'config/technique-playbook-map.yml');

function makeLsassAlert(): AlertEvent {
  return {
    '@timestamp': new Date().toISOString(),
    event: {
      kind: 'alert',
      category: ['malware'],
      type: ['info'],
      severity: 85,
    },
    host: { hostname: 'ws-001', os: { family: 'windows', platform: 'windows' } },
    source: { ip: '10.0.0.50' },
    process: {
      name: 'mimikatz.exe',
      pid: 1234,
      parent: { name: 'cmd.exe', pid: 100 },
      hash: { sha256: 'abc123def456' },
    },
    threat: {
      framework: 'MITRE ATT&CK',
      technique: { id: ['T1003.001'], name: ['LSASS Memory'] },
      tactic: { id: ['TA0006'], name: ['Credential Access'] },
    },
    'x-detectforge': {
      rule_id: 'df-sigma-001',
      rule_name: 'LSASS Memory Access',
      rule_version: '1.0.0',
      generated_at: new Date().toISOString(),
      confidence: 'high',
      suggested_runbook: 'lsass-credential-dumping-l0',
    },
  };
}

function makeWmiAlert(): AlertEvent {
  return {
    '@timestamp': new Date().toISOString(),
    event: {
      kind: 'alert',
      category: ['process'],
      type: ['start'],
      severity: 70,
    },
    host: { hostname: 'srv-db-001' },
    source: { ip: '192.168.1.100' },
    destination: { ip: '192.168.1.50' },
    process: {
      name: 'wmic.exe',
      command_line: 'wmic /node:192.168.1.50 process call create "cmd.exe"',
    },
    threat: {
      framework: 'MITRE ATT&CK',
      technique: { id: ['T1047'], name: ['Windows Management Instrumentation'] },
      tactic: { id: ['TA0002'], name: ['Execution'] },
    },
  };
}

function makeUnknownAlert(): AlertEvent {
  return {
    '@timestamp': new Date().toISOString(),
    event: {
      kind: 'alert',
      category: ['network'],
      type: ['connection'],
      severity: 40,
    },
    source: { ip: '10.0.0.1' },
    destination: { ip: '8.8.8.8', port: 53 },
  };
}

// ---------------------------------------------------------------------------
// Test Suite
// ---------------------------------------------------------------------------

let db: Database.Database;

beforeEach(() => {
  db = initDatabase({ path: ':memory:', inMemory: true });
});

afterEach(() => {
  closeDatabase();
});

// ---------------------------------------------------------------------------
// Alert Ingestion → Validation
// ---------------------------------------------------------------------------

describe('Pipeline: Alert Ingestion', () => {
  it('ingests a valid LSASS alert from JSON string', () => {
    const result = ingestFromString(JSON.stringify(makeLsassAlert()));

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(1);
    expect(result.total_valid).toBe(1);
  });

  it('ingests multiple alerts from JSON array', () => {
    const alerts = [makeLsassAlert(), makeWmiAlert(), makeUnknownAlert()];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.success).toBe(true);
    expect(result.alerts).toHaveLength(3);
    expect(result.total_valid).toBe(3);
  });

  it('ingests NDJSON format', () => {
    const ndjson = [
      JSON.stringify(makeLsassAlert()),
      JSON.stringify(makeWmiAlert()),
    ].join('\n');
    const result = ingestFromString(ndjson);

    expect(result.alerts).toHaveLength(2);
  });

  it('validates alert has required ECS fields', () => {
    const result = validateAlertEvent(makeLsassAlert());
    expect(result.valid).toBe(true);
    expect(result.alert).toBeDefined();
  });

  it('validates DetectForge metadata is preserved', () => {
    const alert = makeLsassAlert();
    const result = validateAlertEvent(alert);

    expect(result.valid).toBe(true);
    expect(result.alert!['x-detectforge']).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Playbook Matching
// ---------------------------------------------------------------------------

describe('Pipeline: Playbook Matching', () => {
  it('matches LSASS alert to LSASS playbook via technique ID', () => {
    const matcher = new PlaybookMatcher(CONFIG_PATH);
    const match = matcher.match('T1003.001');

    expect(match).toBeDefined();
    expect(match!.technique_id).toBe('T1003.001');
    expect(match!.matched_playbooks).toContain('playbooks/lsass-credential-dumping-l0.yml');
  });

  it('matches WMI alert to WMI playbook', () => {
    const matcher = new PlaybookMatcher(CONFIG_PATH);
    const match = matcher.match('T1047');

    expect(match).toBeDefined();
    expect(match!.matched_playbooks).toContain('playbooks/wmi-lateral-movement-l1.yml');
  });

  it('returns global default for unknown technique', () => {
    const matcher = new PlaybookMatcher(CONFIG_PATH);
    const playbook = matcher.getDefaultPlaybook('T9999.999');

    expect(playbook).toBe('playbooks/generic-triage-l0.yml');
  });

  it('finds all execution-tactic playbooks', () => {
    const matcher = new PlaybookMatcher(CONFIG_PATH);
    const results = matcher.matchByTactic('execution');

    expect(results.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Trigger Evaluation
// ---------------------------------------------------------------------------

describe('Pipeline: Trigger Evaluation', () => {
  const lsassTrigger: RunbookTrigger = {
    detection_sources: ['detectforge'],
    mitre_techniques: ['T1003.001'],
    platforms: ['windows'],
    severity: ['high', 'critical'],
  };

  it('evaluates simple equality condition on alert field', () => {
    const alert = makeLsassAlert();
    const result = evaluateTrigger(lsassTrigger, alert, {
      operator: 'eq',
      field: 'event.kind',
      value: 'alert',
    });

    expect(result.matched).toBe(true);
  });

  it('evaluates severity threshold condition', () => {
    const alert = makeLsassAlert();
    const result = evaluateTrigger(lsassTrigger, alert, {
      operator: 'gte',
      field: 'event.severity',
      value: 80,
    });

    expect(result.matched).toBe(true);
  });

  it('evaluates compound AND condition', () => {
    const alert = makeLsassAlert();
    const result = evaluateTrigger(lsassTrigger, alert, {
      logic: 'and',
      conditions: [
        { field: 'event.kind', operator: 'eq', value: 'alert' },
        { field: 'event.severity', operator: 'gte', value: 80 },
      ],
    });

    expect(result.matched).toBe(true);
  });

  it('rejects alert that does not meet conditions', () => {
    const unknownTrigger: RunbookTrigger = {
      detection_sources: ['manual'],
      mitre_techniques: ['T9999'],
      platforms: ['network'],
    };
    const alert = makeUnknownAlert(); // severity 40
    const result = evaluateTrigger(unknownTrigger, alert, {
      operator: 'gte',
      field: 'event.severity',
      value: 80,
    });

    expect(result.matched).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Enrichment Pipeline
// ---------------------------------------------------------------------------

describe('Pipeline: Enrichment', () => {
  it('enriches alert with all built-in sources', async () => {
    const pipeline = new EnrichmentPipeline();
    pipeline.registerSource(createGeoIPEnricher());
    pipeline.registerSource(createAssetInventoryEnricher());
    pipeline.registerSource(createThreatIntelEnricher());

    const alert = makeLsassAlert();
    const result = await pipeline.enrich(alert);

    expect(result.success_count).toBe(3);
    expect(result.failure_count).toBe(0);
    expect(result.enriched_context['geoip']).toBeDefined();
    expect(result.enriched_context['asset_inventory']).toBeDefined();
    expect(result.enriched_context['threat_intel']).toBeDefined();
  });

  it('GeoIP enricher finds source IP', async () => {
    const enricher = createGeoIPEnricher();
    const alert = makeLsassAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['ip']).toBe('10.0.0.50');
    expect(result.data['lookup_performed']).toBe(true);
  });

  it('Asset inventory enricher finds hostname', async () => {
    const enricher = createAssetInventoryEnricher();
    const alert = makeLsassAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['hostname']).toBe('ws-001');
  });

  it('Threat intel enricher checks IOCs', async () => {
    const enricher = createThreatIntelEnricher();
    const alert = makeLsassAlert();
    const result = await enricher.enrich(alert);

    expect(result.success).toBe(true);
    expect(result.data['lookup_performed']).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Execution Controller Lifecycle
// ---------------------------------------------------------------------------

describe('Pipeline: Execution Lifecycle', () => {
  it('tracks execution from start to completion', () => {
    const controller = new ExecutionController();

    const handle = controller.startExecution({
      execution_id: 'int-exec-001',
      timeout_ms: 0,
    });
    expect(handle.status).toBe('running');

    const completed = controller.completeExecution('int-exec-001');
    expect(completed.status).toBe('completed');
    expect(completed.completed_at).toBeDefined();
  });

  it('tracks execution from start to cancellation', () => {
    const controller = new ExecutionController();

    controller.startExecution({
      execution_id: 'int-exec-002',
      timeout_ms: 0,
    });

    const cancelled = controller.cancelExecution('int-exec-002', 'analyst override');
    expect(cancelled.status).toBe('cancelled');
    expect(cancelled.cancel_reason).toBe('analyst override');
  });

  it('shouldAbort returns true after cancellation', () => {
    const controller = new ExecutionController();

    controller.startExecution({
      execution_id: 'int-exec-003',
      timeout_ms: 0,
    });

    expect(controller.shouldAbort('int-exec-003')).toBe(false);
    controller.cancelExecution('int-exec-003', 'test');
    expect(controller.shouldAbort('int-exec-003')).toBe(true);
  });

  it('shutdownAll cancels all running executions', async () => {
    const controller = new ExecutionController();

    controller.startExecution({ execution_id: 'shutdown-a', timeout_ms: 0 });
    controller.startExecution({ execution_id: 'shutdown-b', timeout_ms: 0 });

    await controller.shutdownAll();

    expect(controller.listActive()).toEqual([]);
    expect(controller.getExecution('shutdown-a')!.status).toBe('cancelled');
    expect(controller.getExecution('shutdown-b')!.status).toBe('cancelled');
  });
});

// ---------------------------------------------------------------------------
// Audit Logging Integration
// ---------------------------------------------------------------------------

describe('Pipeline: Audit Logging', () => {
  it('logs full execution lifecycle with hash chain', () => {
    // Create execution record first (FK constraint)
    const repo = new ExecutionRepository(db);
    repo.createExecution({
      executionId: 'audit-exec-001',
      runbookId: 'rb-lsass-001',
      runbookVersion: '1.0.0',
      runbookName: 'LSASS Credential Dumping',
      mode: 'production',
    });

    const auditLogger = new AuditLogger(db);

    // Start execution
    auditLogger.logExecutionStarted('audit-exec-001', 'rb-lsass-001', 'system', {
      playbook: 'lsass-credential-dumping-l0',
    });

    // Log steps
    auditLogger.logStepStarted('audit-exec-001', 'rb-lsass-001', 'step-01', 'query_siem');
    auditLogger.logStepCompleted('audit-exec-001', 'rb-lsass-001', 'step-01', 'query_siem', 150);
    auditLogger.logStepStarted('audit-exec-001', 'rb-lsass-001', 'step-02', 'enrich_ioc');
    auditLogger.logStepCompleted('audit-exec-001', 'rb-lsass-001', 'step-02', 'enrich_ioc', 200);

    // Complete execution
    auditLogger.logExecutionCompleted('audit-exec-001', 'rb-lsass-001', {
      total_steps: 2,
      duration_ms: 350,
    });

    const log = auditLogger.getExecutionLog('audit-exec-001');

    expect(log).toHaveLength(6);
    expect(log[0]!.event_type).toBe('execution_started');
    expect(log[5]!.event_type).toBe('execution_completed');

    // Verify hash chain
    for (let i = 1; i < log.length; i++) {
      expect(log[i]!.prev_hash).toBe(log[i - 1]!.hash);
    }
  });

  it('persists execution records in DB', () => {
    const repo = new ExecutionRepository(db);

    repo.createExecution({
      executionId: 'db-exec-001',
      runbookId: 'rb-lsass-001',
      runbookVersion: '1.0.0',
      runbookName: 'LSASS Credential Dumping L0',
      mode: 'production',
    });

    const record = repo.getExecution('db-exec-001');

    expect(record).toBeDefined();
    expect(record!.runbook_id).toBe('rb-lsass-001');
    expect(record!.state).toBe('idle');
  });

  it('queries executions by state', () => {
    const repo = new ExecutionRepository(db);

    repo.createExecution({
      executionId: 'q-exec-001',
      runbookId: 'rb-001',
      runbookVersion: '1.0.0',
      runbookName: 'Test',
      mode: 'production',
    });
    repo.createExecution({
      executionId: 'q-exec-002',
      runbookId: 'rb-001',
      runbookVersion: '1.0.0',
      runbookName: 'Test',
      mode: 'simulation',
    });

    repo.updateState('q-exec-001', 'completed');

    const completed = repo.queryExecutions({ state: 'completed' });
    expect(completed).toHaveLength(1);
    expect(completed[0]!.execution_id).toBe('q-exec-001');

    const idle = repo.queryExecutions({ state: 'idle' });
    expect(idle).toHaveLength(1);
    expect(idle[0]!.execution_id).toBe('q-exec-002');
  });
});

// ---------------------------------------------------------------------------
// Full Pipeline: Alert → Match → Enrich → Track
// ---------------------------------------------------------------------------

describe('Pipeline: Full Alert-to-Execution Flow', () => {
  it('processes LSASS alert through complete pipeline', async () => {
    // 1. Ingest alert
    const alert = makeLsassAlert();
    const validation = validateAlertEvent(alert);
    expect(validation.valid).toBe(true);

    // 2. Match to playbook
    const matcher = new PlaybookMatcher(CONFIG_PATH);
    const technique = alert.threat?.technique?.id?.[0];
    expect(technique).toBe('T1003.001');

    const match = matcher.match(technique!);
    expect(match).toBeDefined();
    expect(match!.matched_playbooks.length).toBeGreaterThan(0);

    // 3. Evaluate trigger
    const trigger: RunbookTrigger = {
      detection_sources: ['detectforge'],
      mitre_techniques: ['T1003.001'],
      platforms: ['windows'],
    };
    const triggerResult = evaluateTrigger(trigger, alert, {
      operator: 'gte',
      field: 'event.severity',
      value: 50,
    });
    expect(triggerResult.matched).toBe(true);

    // 4. Enrich
    const pipeline = new EnrichmentPipeline();
    pipeline.registerSource(createGeoIPEnricher());
    pipeline.registerSource(createAssetInventoryEnricher());
    const enrichment = await pipeline.enrich(alert);
    expect(enrichment.success_count).toBe(2);

    // 5. Start execution tracking
    const controller = new ExecutionController();
    const handle = controller.startExecution({
      execution_id: 'pipeline-exec-001',
      timeout_ms: 30000,
    });
    expect(handle.status).toBe('running');

    // 6. Persist in DB (must happen before audit logging due to FK constraint)
    const repo = new ExecutionRepository(db);
    repo.createExecution({
      executionId: 'pipeline-exec-001',
      runbookId: match!.technique_id,
      runbookVersion: '1.0.0',
      runbookName: 'LSASS Credential Dumping L0',
      mode: 'production',
    });

    // 7. Log to audit
    const auditLogger = new AuditLogger(db);
    auditLogger.logExecutionStarted('pipeline-exec-001', 'rb-lsass-001');

    // 8. Complete
    controller.completeExecution('pipeline-exec-001');
    auditLogger.logExecutionCompleted('pipeline-exec-001', 'rb-lsass-001');
    repo.updateState('pipeline-exec-001', 'completed');

    // Verify final state
    expect(controller.getExecution('pipeline-exec-001')!.status).toBe('completed');
    const dbRecord = repo.getExecution('pipeline-exec-001');
    expect(dbRecord!.state).toBe('completed');
    const auditLog = auditLogger.getExecutionLog('pipeline-exec-001');
    expect(auditLog.length).toBe(2);
  });

  it('processes batch of alerts and matches each to playbooks', () => {
    const alerts = [makeLsassAlert(), makeWmiAlert(), makeUnknownAlert()];
    const result = ingestFromString(JSON.stringify(alerts));

    expect(result.alerts).toHaveLength(3);

    const matcher = new PlaybookMatcher(CONFIG_PATH);

    // LSASS → known playbook
    const lsassMatch = matcher.match('T1003.001');
    expect(lsassMatch).toBeDefined();

    // WMI → known playbook
    const wmiMatch = matcher.match('T1047');
    expect(wmiMatch).toBeDefined();

    // Unknown → global default
    const unknownPlaybook = matcher.getDefaultPlaybook('T9999');
    expect(unknownPlaybook).toBe('playbooks/generic-triage-l0.yml');
  });
});
