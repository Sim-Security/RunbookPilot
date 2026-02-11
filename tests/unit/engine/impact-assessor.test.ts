import { describe, it, expect } from 'vitest';
import {
  assessStepImpact,
  assessPlaybookImpact,
  calculateOverallRisk,
  getAffectedAssets,
  isReversible,
  estimateBlastRadius,
} from '../../../src/engine/impact-assessor.ts';
import type { RunbookStep } from '../../../src/types/playbook.ts';
import type { ImpactAssessment } from '../../../src/types/simulation.ts';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

function makeStep(overrides: Partial<RunbookStep> = {}): RunbookStep {
  return {
    id: 'step-01',
    name: 'Test Step',
    action: 'collect_logs',
    executor: 'mock',
    parameters: {},
    on_error: 'halt',
    timeout: 30,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// assessStepImpact
// ---------------------------------------------------------------------------

describe('assessStepImpact', () => {
  it('returns low risk for read-only action (collect_logs)', () => {
    const step = makeStep({ action: 'collect_logs' });
    const result = assessStepImpact(step, {});

    expect(result.action).toBe('collect_logs');
    expect(result.risk_score).toBe(1);
    expect(result.risk_level).toBe('low');
    expect(result.reversible).toBe(false);
  });

  it('returns high risk for isolate_host', () => {
    const step = makeStep({ action: 'isolate_host' });
    const result = assessStepImpact(step, { host_id: 'ws-001' });

    expect(result.risk_score).toBe(8);
    expect(result.risk_level).toBe('high');
    expect(result.reversible).toBe(true);
    expect(result.rollback_available).toBe(true);
  });

  it('returns critical risk for delete_file', () => {
    const step = makeStep({ action: 'delete_file' });
    const result = assessStepImpact(step, { file_path: '/tmp/malware.exe' });

    expect(result.risk_score).toBe(9);
    expect(result.risk_level).toBe('critical');
    expect(result.reversible).toBe(false);
    expect(result.rollback_available).toBe(false);
  });

  it('returns critical risk for execute_script', () => {
    const step = makeStep({ action: 'execute_script' });
    const result = assessStepImpact(step, {});

    expect(result.risk_score).toBe(9);
    expect(result.risk_level).toBe('critical');
  });

  it('returns medium risk for block_ip', () => {
    const step = makeStep({ action: 'block_ip' });
    const result = assessStepImpact(step, { ip: '10.0.0.5' });

    expect(result.risk_score).toBe(6);
    expect(result.risk_level).toBe('medium');
    expect(result.reversible).toBe(true);
  });

  it('marks rollback_available true when step has rollback definition', () => {
    const step = makeStep({
      action: 'kill_process',
      rollback: {
        action: 'start_edr_scan',
        parameters: {},
        timeout: 30,
      },
    });
    const result = assessStepImpact(step, {});

    // kill_process is not in ROLLBACK_PAIRS, but step has rollback def
    expect(result.reversible).toBe(false);
    expect(result.rollback_available).toBe(true);
  });

  it('marks rollback_available true for known rollback pairs even without rollback definition', () => {
    const step = makeStep({ action: 'isolate_host' });
    const result = assessStepImpact(step, {});

    expect(result.reversible).toBe(true);
    expect(result.rollback_available).toBe(true);
  });

  it('includes a human-readable summary', () => {
    const step = makeStep({ action: 'isolate_host' });
    const result = assessStepImpact(step, { host_id: 'ws-042' });

    expect(result.summary).toContain('Would isolate host');
    expect(result.summary).toContain('ws-042');
    expect(result.summary).toContain('Risk: HIGH');
    expect(result.summary).toContain('Rollback available');
  });

  it('includes dependencies from service/system params', () => {
    const step = makeStep({ action: 'block_ip' });
    const result = assessStepImpact(step, {
      ip: '10.0.0.5',
      service: 'web-gateway',
      systems: ['firewall-01', 'firewall-02'],
    });

    expect(result.dependencies).toContain('web-gateway');
    expect(result.dependencies).toContain('firewall-01');
    expect(result.dependencies).toContain('firewall-02');
  });

  it('returns low risk for query_siem', () => {
    const step = makeStep({ action: 'query_siem' });
    const result = assessStepImpact(step, {});

    expect(result.risk_score).toBe(1);
    expect(result.risk_level).toBe('low');
  });

  it('returns medium risk for revoke_session', () => {
    const step = makeStep({ action: 'revoke_session' });
    const result = assessStepImpact(step, { user: 'jdoe' });

    expect(result.risk_score).toBe(5);
    expect(result.risk_level).toBe('medium');
  });

  it('returns high risk for disable_account', () => {
    const step = makeStep({ action: 'disable_account' });
    const result = assessStepImpact(step, { account: 'admin@corp.com' });

    expect(result.risk_score).toBe(8);
    expect(result.risk_level).toBe('high');
    expect(result.reversible).toBe(true);
  });

  it('uses params to override step.parameters for affected assets', () => {
    const step = makeStep({
      action: 'block_ip',
      parameters: { ip: '1.1.1.1' },
    });
    const result = assessStepImpact(step, { ip: '2.2.2.2' });

    // params override step.parameters for the same key
    const assets = result.blast_radius.affected_assets;
    expect(assets).toContain('2.2.2.2');
  });

  it('summary shows "No rollback available" for irreversible actions', () => {
    const step = makeStep({ action: 'delete_file' });
    const result = assessStepImpact(step, { file_path: '/etc/shadow' });

    expect(result.summary).toContain('No rollback available');
  });

  it('returns correct blast_radius structure', () => {
    const step = makeStep({ action: 'isolate_host' });
    const result = assessStepImpact(step, { host_id: 'ws-001' });

    expect(result.blast_radius).toHaveProperty('hosts_affected');
    expect(result.blast_radius).toHaveProperty('users_affected');
    expect(result.blast_radius).toHaveProperty('services_affected');
    expect(result.blast_radius).toHaveProperty('affected_assets');
    expect(result.blast_radius.hosts_affected).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// assessPlaybookImpact
// ---------------------------------------------------------------------------

describe('assessPlaybookImpact', () => {
  it('assesses multiple steps and returns one assessment per step', () => {
    const steps = [
      makeStep({ id: 'step-01', action: 'query_siem' }),
      makeStep({ id: 'step-02', action: 'isolate_host' }),
      makeStep({ id: 'step-03', action: 'block_ip' }),
    ];
    const params: Record<string, Record<string, unknown>> = {
      'step-01': { query: 'test' },
      'step-02': { host_id: 'ws-001' },
      'step-03': { ip: '10.0.0.5' },
    };

    const results = assessPlaybookImpact(steps, params);

    expect(results).toHaveLength(3);
    expect(results[0]!.action).toBe('query_siem');
    expect(results[1]!.action).toBe('isolate_host');
    expect(results[2]!.action).toBe('block_ip');
  });

  it('falls back to step.parameters when params map is empty', () => {
    const steps = [
      makeStep({ id: 'step-01', action: 'block_ip', parameters: { ip: '10.0.0.1' } }),
    ];

    const results = assessPlaybookImpact(steps, {});

    expect(results).toHaveLength(1);
    expect(results[0]!.blast_radius.affected_assets).toContain('10.0.0.1');
  });

  it('returns empty array for empty steps', () => {
    const results = assessPlaybookImpact([], {});
    expect(results).toEqual([]);
  });

  it('preserves step order in assessments', () => {
    const steps = [
      makeStep({ id: 'step-01', action: 'delete_file' }),
      makeStep({ id: 'step-02', action: 'collect_logs' }),
      makeStep({ id: 'step-03', action: 'isolate_host' }),
    ];

    const results = assessPlaybookImpact(steps, {});

    expect(results[0]!.risk_score).toBe(9); // delete_file
    expect(results[1]!.risk_score).toBe(1); // collect_logs
    expect(results[2]!.risk_score).toBe(8); // isolate_host
  });
});

// ---------------------------------------------------------------------------
// calculateOverallRisk
// ---------------------------------------------------------------------------

describe('calculateOverallRisk', () => {
  it('returns max risk score across all assessments', () => {
    const assessments: ImpactAssessment[] = [
      { action: 'collect_logs', risk_score: 1, risk_level: 'low', blast_radius: { hosts_affected: 0, users_affected: 0, services_affected: 0, affected_assets: [] }, dependencies: [], summary: '', reversible: false, rollback_available: false },
      { action: 'isolate_host', risk_score: 8, risk_level: 'high', blast_radius: { hosts_affected: 1, users_affected: 0, services_affected: 0, affected_assets: ['ws-001'] }, dependencies: [], summary: '', reversible: true, rollback_available: true },
      { action: 'block_ip', risk_score: 6, risk_level: 'medium', blast_radius: { hosts_affected: 1, users_affected: 0, services_affected: 1, affected_assets: ['10.0.0.5'] }, dependencies: [], summary: '', reversible: true, rollback_available: true },
    ];

    const overall = calculateOverallRisk(assessments);

    expect(overall.score).toBe(8);
    expect(overall.level).toBe('high');
  });

  it('returns low risk for empty assessments array', () => {
    const overall = calculateOverallRisk([]);

    expect(overall.score).toBe(1);
    expect(overall.level).toBe('low');
  });

  it('returns critical when any assessment is critical', () => {
    const assessments: ImpactAssessment[] = [
      { action: 'collect_logs', risk_score: 1, risk_level: 'low', blast_radius: { hosts_affected: 0, users_affected: 0, services_affected: 0, affected_assets: [] }, dependencies: [], summary: '', reversible: false, rollback_available: false },
      { action: 'delete_file', risk_score: 9, risk_level: 'critical', blast_radius: { hosts_affected: 1, users_affected: 0, services_affected: 0, affected_assets: [] }, dependencies: [], summary: '', reversible: false, rollback_available: false },
    ];

    const overall = calculateOverallRisk(assessments);

    expect(overall.score).toBe(9);
    expect(overall.level).toBe('critical');
  });

  it('returns single assessment risk for a one-element array', () => {
    const assessments: ImpactAssessment[] = [
      { action: 'block_ip', risk_score: 6, risk_level: 'medium', blast_radius: { hosts_affected: 1, users_affected: 0, services_affected: 1, affected_assets: [] }, dependencies: [], summary: '', reversible: true, rollback_available: true },
    ];

    const overall = calculateOverallRisk(assessments);

    expect(overall.score).toBe(6);
    expect(overall.level).toBe('medium');
  });
});

// ---------------------------------------------------------------------------
// getAffectedAssets
// ---------------------------------------------------------------------------

describe('getAffectedAssets', () => {
  it('extracts host_id from params', () => {
    const step = makeStep({ action: 'isolate_host' });
    const assets = getAffectedAssets(step, { host_id: 'ws-001' });

    expect(assets).toContain('ws-001');
  });

  it('extracts ip from params', () => {
    const step = makeStep({ action: 'block_ip' });
    const assets = getAffectedAssets(step, { ip: '10.0.0.5' });

    expect(assets).toContain('10.0.0.5');
  });

  it('extracts hostname from params', () => {
    const step = makeStep({ action: 'isolate_host' });
    const assets = getAffectedAssets(step, { hostname: 'server-01' });

    expect(assets).toContain('server-01');
  });

  it('extracts domain from params', () => {
    const step = makeStep({ action: 'block_domain' });
    const assets = getAffectedAssets(step, { domain: 'evil.com' });

    expect(assets).toContain('evil.com');
  });

  it('extracts account from params', () => {
    const step = makeStep({ action: 'disable_account' });
    const assets = getAffectedAssets(step, { account: 'admin@corp.com' });

    expect(assets).toContain('admin@corp.com');
  });

  it('extracts user from params', () => {
    const step = makeStep({ action: 'revoke_session' });
    const assets = getAffectedAssets(step, { user: 'jdoe' });

    expect(assets).toContain('jdoe');
  });

  it('extracts file_path from params', () => {
    const step = makeStep({ action: 'quarantine_file' });
    const assets = getAffectedAssets(step, { file_path: '/tmp/malware.exe' });

    expect(assets).toContain('/tmp/malware.exe');
  });

  it('extracts process_id from params', () => {
    const step = makeStep({ action: 'kill_process' });
    const assets = getAffectedAssets(step, { process_id: '1234' });

    expect(assets).toContain('1234');
  });

  it('handles array values', () => {
    const step = makeStep({ action: 'block_ip' });
    const assets = getAffectedAssets(step, {
      ip: ['10.0.0.1', '10.0.0.2', '10.0.0.3'],
    });

    expect(assets).toContain('10.0.0.1');
    expect(assets).toContain('10.0.0.2');
    expect(assets).toContain('10.0.0.3');
  });

  it('merges step.parameters and params (params override)', () => {
    const step = makeStep({
      action: 'block_ip',
      parameters: { ip: '1.1.1.1', hostname: 'old-host' },
    });
    const assets = getAffectedAssets(step, { ip: '2.2.2.2' });

    // ip is overridden by params, hostname comes from step.parameters
    expect(assets).toContain('2.2.2.2');
    expect(assets).toContain('old-host');
    expect(assets).not.toContain('1.1.1.1');
  });

  it('returns empty array when no asset params present', () => {
    const step = makeStep({ action: 'collect_logs', parameters: { query: 'test' } });
    const assets = getAffectedAssets(step, { query: 'test' });

    expect(assets).toEqual([]);
  });

  it('skips null and undefined values', () => {
    const step = makeStep({ action: 'block_ip' });
    const assets = getAffectedAssets(step, {
      ip: null,
      hostname: undefined,
      domain: 'evil.com',
    });

    expect(assets).toEqual(['evil.com']);
  });

  it('handles arrays with null items', () => {
    const step = makeStep({ action: 'block_ip' });
    const assets = getAffectedAssets(step, {
      ip: ['10.0.0.1', null, '10.0.0.3'],
    });

    expect(assets).toContain('10.0.0.1');
    expect(assets).toContain('10.0.0.3');
    expect(assets).toHaveLength(2);
  });

  it('extracts multiple asset types', () => {
    const step = makeStep({ action: 'isolate_host' });
    const assets = getAffectedAssets(step, {
      host_id: 'ws-001',
      ip: '10.0.0.5',
      user: 'jdoe',
    });

    expect(assets).toContain('ws-001');
    expect(assets).toContain('10.0.0.5');
    expect(assets).toContain('jdoe');
    expect(assets).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// isReversible
// ---------------------------------------------------------------------------

describe('isReversible', () => {
  it('returns true for isolate_host', () => {
    expect(isReversible('isolate_host')).toBe(true);
  });

  it('returns true for block_ip', () => {
    expect(isReversible('block_ip')).toBe(true);
  });

  it('returns true for block_domain', () => {
    expect(isReversible('block_domain')).toBe(true);
  });

  it('returns true for disable_account', () => {
    expect(isReversible('disable_account')).toBe(true);
  });

  it('returns true for quarantine_file', () => {
    expect(isReversible('quarantine_file')).toBe(true);
  });

  it('returns false for delete_file (irreversible)', () => {
    expect(isReversible('delete_file')).toBe(false);
  });

  it('returns false for kill_process', () => {
    expect(isReversible('kill_process')).toBe(false);
  });

  it('returns false for execute_script', () => {
    expect(isReversible('execute_script')).toBe(false);
  });

  it('returns false for collect_logs (read-only)', () => {
    expect(isReversible('collect_logs')).toBe(false);
  });

  it('returns false for query_siem (read-only)', () => {
    expect(isReversible('query_siem')).toBe(false);
  });

  it('returns false for restore_connectivity (reverse of isolate_host, not itself reversible)', () => {
    expect(isReversible('restore_connectivity')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// estimateBlastRadius
// ---------------------------------------------------------------------------

describe('estimateBlastRadius', () => {
  it('counts hosts from host_id param', () => {
    const radius = estimateBlastRadius('isolate_host', { host_id: 'ws-001' });

    expect(radius.hosts_affected).toBeGreaterThanOrEqual(1);
    expect(radius.affected_assets).toContain('ws-001');
  });

  it('counts users from account param', () => {
    const radius = estimateBlastRadius('disable_account', { account: 'admin@corp.com' });

    expect(radius.users_affected).toBeGreaterThanOrEqual(1);
    expect(radius.affected_assets).toContain('admin@corp.com');
  });

  it('counts services from domain param for block_domain', () => {
    const radius = estimateBlastRadius('block_domain', { domain: 'evil.com' });

    expect(radius.services_affected).toBeGreaterThanOrEqual(1);
    expect(radius.affected_assets).toContain('evil.com');
  });

  it('defaults to at least 1 host for isolate_host with no params', () => {
    const radius = estimateBlastRadius('isolate_host', {});

    expect(radius.hosts_affected).toBe(1);
  });

  it('defaults to at least 1 user for disable_account with no params', () => {
    const radius = estimateBlastRadius('disable_account', {});

    expect(radius.users_affected).toBe(1);
  });

  it('defaults to at least 1 service for block_ip', () => {
    const radius = estimateBlastRadius('block_ip', {});

    expect(radius.services_affected).toBe(1);
  });

  it('handles multiple hosts in array', () => {
    const radius = estimateBlastRadius('isolate_host', {
      host_id: ['ws-001', 'ws-002', 'ws-003'],
    });

    expect(radius.hosts_affected).toBeGreaterThanOrEqual(3);
    expect(radius.affected_assets).toContain('ws-001');
    expect(radius.affected_assets).toContain('ws-002');
    expect(radius.affected_assets).toContain('ws-003');
  });

  it('returns zero counts for read-only actions with no params', () => {
    const radius = estimateBlastRadius('collect_logs', {});

    expect(radius.hosts_affected).toBe(0);
    expect(radius.users_affected).toBe(0);
    expect(radius.services_affected).toBe(0);
    expect(radius.affected_assets).toEqual([]);
  });

  it('counts hosts for kill_process with no host param', () => {
    const radius = estimateBlastRadius('kill_process', {});

    expect(radius.hosts_affected).toBe(1);
  });

  it('counts hosts and services for execute_script', () => {
    const radius = estimateBlastRadius('execute_script', {});

    expect(radius.hosts_affected).toBe(1);
    expect(radius.services_affected).toBe(1);
  });

  it('counts hosts for quarantine_file', () => {
    const radius = estimateBlastRadius('quarantine_file', { file_path: '/tmp/malware.exe' });

    expect(radius.hosts_affected).toBeGreaterThanOrEqual(1);
    expect(radius.affected_assets).toContain('/tmp/malware.exe');
  });

  it('includes all asset types in affected_assets', () => {
    const radius = estimateBlastRadius('isolate_host', {
      host_id: 'ws-001',
      ip: '10.0.0.5',
      user: 'jdoe',
    });

    expect(radius.affected_assets).toContain('ws-001');
    expect(radius.affected_assets).toContain('10.0.0.5');
    expect(radius.affected_assets).toContain('jdoe');
  });
});

// ---------------------------------------------------------------------------
// Risk Level Mapping
// ---------------------------------------------------------------------------

describe('risk level mapping', () => {
  it('scores 1 maps to low', () => {
    const step = makeStep({ action: 'collect_logs' }); // risk=1
    const result = assessStepImpact(step, {});
    expect(result.risk_level).toBe('low');
  });

  it('scores 2-3 map to low', () => {
    const step2 = makeStep({ action: 'notify_oncall' }); // risk=2
    const result2 = assessStepImpact(step2, {});
    expect(result2.risk_level).toBe('low');

    const step3 = makeStep({ action: 'restore_connectivity' }); // risk=3
    const result3 = assessStepImpact(step3, {});
    expect(result3.risk_level).toBe('low');
  });

  it('scores 4-6 map to medium', () => {
    const step5 = makeStep({ action: 'revoke_session' }); // risk=5
    const result5 = assessStepImpact(step5, {});
    expect(result5.risk_level).toBe('medium');

    const step6 = makeStep({ action: 'block_ip' }); // risk=6
    const result6 = assessStepImpact(step6, {});
    expect(result6.risk_level).toBe('medium');

    const step4 = makeStep({ action: 'quarantine_file' }); // risk=6
    const result4 = assessStepImpact(step4, {});
    expect(result4.risk_level).toBe('medium');
  });

  it('scores 7-8 map to high', () => {
    const step7 = makeStep({ action: 'kill_process' }); // risk=7
    const result7 = assessStepImpact(step7, {});
    expect(result7.risk_level).toBe('high');

    const step8 = makeStep({ action: 'isolate_host' }); // risk=8
    const result8 = assessStepImpact(step8, {});
    expect(result8.risk_level).toBe('high');
  });

  it('scores 9-10 map to critical', () => {
    const step9 = makeStep({ action: 'delete_file' }); // risk=9
    const result9 = assessStepImpact(step9, {});
    expect(result9.risk_level).toBe('critical');

    const step9b = makeStep({ action: 'execute_script' }); // risk=9
    const result9b = assessStepImpact(step9b, {});
    expect(result9b.risk_level).toBe('critical');
  });
});
