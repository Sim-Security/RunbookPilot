import { describe, it, expect } from 'vitest';
import {
  isLevelSufficient,
  getRequiredLevel,
  requiresApproval,
  checkPolicy,
  validateL2Enabled,
  validateExecutionPolicy,
  DEFAULT_POLICY,
  LEVEL_ORDER,
} from '../../../src/engine/policy-enforcer.ts';
import type { StepAction } from '../../../src/types/playbook.ts';
import type { AutomationPolicy } from '../../../src/types/simulation.ts';

// ---------------------------------------------------------------------------
// isLevelSufficient
// ---------------------------------------------------------------------------

describe('isLevelSufficient', () => {
  it('L0 is sufficient for L0', () => {
    expect(isLevelSufficient('L0', 'L0')).toBe(true);
  });

  it('L1 is sufficient for L0', () => {
    expect(isLevelSufficient('L1', 'L0')).toBe(true);
  });

  it('L1 is sufficient for L1', () => {
    expect(isLevelSufficient('L1', 'L1')).toBe(true);
  });

  it('L2 is sufficient for L0', () => {
    expect(isLevelSufficient('L2', 'L0')).toBe(true);
  });

  it('L2 is sufficient for L1', () => {
    expect(isLevelSufficient('L2', 'L1')).toBe(true);
  });

  it('L2 is sufficient for L2', () => {
    expect(isLevelSufficient('L2', 'L2')).toBe(true);
  });

  it('L0 is NOT sufficient for L1', () => {
    expect(isLevelSufficient('L0', 'L1')).toBe(false);
  });

  it('L0 is NOT sufficient for L2', () => {
    expect(isLevelSufficient('L0', 'L2')).toBe(false);
  });

  it('L1 is NOT sufficient for L2', () => {
    expect(isLevelSufficient('L1', 'L2')).toBe(false);
  });

  it('LEVEL_ORDER has correct numeric ordering', () => {
    expect(LEVEL_ORDER.L0).toBeLessThan(LEVEL_ORDER.L1);
    expect(LEVEL_ORDER.L1).toBeLessThan(LEVEL_ORDER.L2);
  });
});

// ---------------------------------------------------------------------------
// getRequiredLevel
// ---------------------------------------------------------------------------

describe('getRequiredLevel', () => {
  it('returns L0 for collect_logs (read-only)', () => {
    expect(getRequiredLevel('collect_logs')).toBe('L0');
  });

  it('returns L0 for query_siem', () => {
    expect(getRequiredLevel('query_siem')).toBe('L0');
  });

  it('returns L0 for enrich_ioc', () => {
    expect(getRequiredLevel('enrich_ioc')).toBe('L0');
  });

  it('returns L0 for notify_analyst', () => {
    expect(getRequiredLevel('notify_analyst')).toBe('L0');
  });

  it('returns L0 for create_ticket', () => {
    expect(getRequiredLevel('create_ticket')).toBe('L0');
  });

  it('returns L0 for wait', () => {
    expect(getRequiredLevel('wait')).toBe('L0');
  });

  it('returns L1 for isolate_host', () => {
    expect(getRequiredLevel('isolate_host')).toBe('L1');
  });

  it('returns L1 for block_ip', () => {
    expect(getRequiredLevel('block_ip')).toBe('L1');
  });

  it('returns L1 for disable_account', () => {
    expect(getRequiredLevel('disable_account')).toBe('L1');
  });

  it('returns L1 for reset_password', () => {
    expect(getRequiredLevel('reset_password')).toBe('L1');
  });

  it('returns L2 for kill_process', () => {
    expect(getRequiredLevel('kill_process')).toBe('L2');
  });

  it('returns L2 for delete_file', () => {
    expect(getRequiredLevel('delete_file')).toBe('L2');
  });

  it('returns L2 for execute_script', () => {
    expect(getRequiredLevel('execute_script')).toBe('L2');
  });

  it('returns L2 for quarantine_file', () => {
    expect(getRequiredLevel('quarantine_file')).toBe('L2');
  });
});

// ---------------------------------------------------------------------------
// requiresApproval
// ---------------------------------------------------------------------------

describe('requiresApproval', () => {
  it('returns false for read-only actions (collect_logs)', () => {
    expect(requiresApproval('collect_logs', 'L0')).toBe(false);
  });

  it('returns false for query_siem', () => {
    expect(requiresApproval('query_siem', 'L0')).toBe(false);
  });

  it('returns false for enrich_ioc', () => {
    expect(requiresApproval('enrich_ioc', 'L0')).toBe(false);
  });

  it('returns false for notify_analyst', () => {
    expect(requiresApproval('notify_analyst', 'L0')).toBe(false);
  });

  it('returns false for create_ticket', () => {
    expect(requiresApproval('create_ticket', 'L0')).toBe(false);
  });

  it('returns true for isolate_host (write action)', () => {
    expect(requiresApproval('isolate_host', 'L1')).toBe(true);
  });

  it('returns true for block_ip', () => {
    expect(requiresApproval('block_ip', 'L1')).toBe(true);
  });

  it('returns true for disable_account', () => {
    expect(requiresApproval('disable_account', 'L1')).toBe(true);
  });

  it('returns true for kill_process', () => {
    expect(requiresApproval('kill_process', 'L2')).toBe(true);
  });

  it('returns true for delete_file', () => {
    expect(requiresApproval('delete_file', 'L2')).toBe(true);
  });

  it('returns true for execute_script', () => {
    expect(requiresApproval('execute_script', 'L2')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — constraint 1: automation level sufficiency
// ---------------------------------------------------------------------------

describe('checkPolicy — level sufficiency', () => {
  it('allows L1 for an L1-required action (isolate_host)', () => {
    const result = checkPolicy('isolate_host', 'L1', 'production');

    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('blocks L0 for an L1-required action (isolate_host)', () => {
    const result = checkPolicy('isolate_host', 'L0', 'production');

    expect(result.allowed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0]!.rule).toBe('insufficient_level');
  });

  it('allows L2 for an L1-required action', () => {
    const result = checkPolicy('isolate_host', 'L2', 'simulation');

    expect(result.allowed).toBe(true);
  });

  it('blocks L1 for an L2-required action (kill_process)', () => {
    const result = checkPolicy('kill_process', 'L1', 'production');

    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'insufficient_level')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — constraint 2: execution mode allowance
// ---------------------------------------------------------------------------

describe('checkPolicy — mode allowance', () => {
  it('allows production mode for all default policy actions', () => {
    const result = checkPolicy('collect_logs', 'L0', 'production');
    expect(result.allowed).toBe(true);
  });

  it('allows simulation mode for all default policy actions', () => {
    const result = checkPolicy('collect_logs', 'L0', 'simulation');
    expect(result.allowed).toBe(true);
  });

  it('allows dry-run mode for all default policy actions', () => {
    const result = checkPolicy('collect_logs', 'L0', 'dry-run');
    expect(result.allowed).toBe(true);
  });

  it('blocks mode not in allowed_modes', () => {
    const restrictedPolicy: AutomationPolicy = {
      name: 'restricted',
      rules: [
        {
          action: 'isolate_host',
          min_level: 'L1',
          requires_approval: true,
          allowed_modes: ['simulation', 'dry-run'],
          admin_override: false,
        },
      ],
    };

    const result = checkPolicy('isolate_host', 'L1', 'production', restrictedPolicy);

    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'mode_not_allowed')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — constraint 3: risk score cap
// ---------------------------------------------------------------------------

describe('checkPolicy — risk score cap', () => {
  it('allows action within risk cap', () => {
    const result = checkPolicy('kill_process', 'L2', 'simulation', DEFAULT_POLICY, 7);

    expect(result.allowed).toBe(true);
  });

  it('allows action at exactly max risk score', () => {
    const result = checkPolicy('kill_process', 'L2', 'simulation', DEFAULT_POLICY, 8);

    expect(result.allowed).toBe(true);
  });

  it('blocks action exceeding risk cap', () => {
    const result = checkPolicy('kill_process', 'L2', 'simulation', DEFAULT_POLICY, 9);

    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'risk_score_exceeded')).toBe(true);
  });

  it('does not check risk cap when riskScore is not provided', () => {
    const result = checkPolicy('kill_process', 'L2', 'simulation');

    expect(result.allowed).toBe(true);
  });

  it('does not check risk cap for actions without max_risk_score', () => {
    // isolate_host has no max_risk_score in DEFAULT_POLICY
    const result = checkPolicy('isolate_host', 'L1', 'production', DEFAULT_POLICY, 10);

    expect(result.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — constraint 4: L2 production write guard
// ---------------------------------------------------------------------------

describe('checkPolicy — L2 production write guard', () => {
  it('blocks L2 write action in production mode', () => {
    const result = checkPolicy('isolate_host', 'L2', 'production');

    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'l2_production_write_blocked')).toBe(true);
  });

  it('allows L2 write action in simulation mode', () => {
    const result = checkPolicy('isolate_host', 'L2', 'simulation');

    expect(result.allowed).toBe(true);
  });

  it('allows L2 write action in dry-run mode', () => {
    const result = checkPolicy('isolate_host', 'L2', 'dry-run');

    expect(result.allowed).toBe(true);
  });

  it('allows L2 read action in production mode', () => {
    const result = checkPolicy('collect_logs', 'L2', 'production');

    expect(result.allowed).toBe(true);
  });

  it('blocks L2 kill_process in production mode', () => {
    const result = checkPolicy('kill_process', 'L2', 'production');

    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.rule === 'l2_production_write_blocked')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — constraint 5: admin override
// ---------------------------------------------------------------------------

describe('checkPolicy — admin override', () => {
  it('admin override allows action that would otherwise be blocked', () => {
    const result = checkPolicy('isolate_host', 'L0', 'production', DEFAULT_POLICY, undefined, true);

    expect(result.allowed).toBe(true);
    expect(result.violations.length).toBeGreaterThan(0);
    // Violations should be downgraded to warnings
    for (const v of result.violations) {
      expect(v.severity).toBe('warning');
    }
  });

  it('admin override downgrades violations to warnings', () => {
    const result = checkPolicy('kill_process', 'L1', 'simulation', DEFAULT_POLICY, 9, true);

    expect(result.allowed).toBe(true);
    expect(result.violations.length).toBeGreaterThan(0);
    for (const v of result.violations) {
      expect(v.severity).toBe('warning');
    }
  });

  it('admin override does NOT help when rule does not allow override', () => {
    const noOverridePolicy: AutomationPolicy = {
      name: 'strict',
      rules: [
        {
          action: 'delete_file',
          min_level: 'L2',
          requires_approval: true,
          allowed_modes: ['simulation'],
          admin_override: false,
        },
      ],
    };

    const result = checkPolicy('delete_file', 'L1', 'production', noOverridePolicy, undefined, true);

    expect(result.allowed).toBe(false);
    // Violations remain as errors
    for (const v of result.violations) {
      expect(v.severity).toBe('error');
    }
  });

  it('non-admin gets errors, not warnings', () => {
    const result = checkPolicy('isolate_host', 'L0', 'production', DEFAULT_POLICY, undefined, false);

    expect(result.allowed).toBe(false);
    for (const v of result.violations) {
      expect(v.severity).toBe('error');
    }
  });
});

// ---------------------------------------------------------------------------
// checkPolicy — result shape
// ---------------------------------------------------------------------------

describe('checkPolicy — result shape', () => {
  it('returns correct action', () => {
    const result = checkPolicy('block_ip', 'L1', 'production');
    expect(result.action).toBe('block_ip');
  });

  it('returns correct requested_level', () => {
    const result = checkPolicy('block_ip', 'L1', 'production');
    expect(result.requested_level).toBe('L1');
  });

  it('returns correct required_level from policy rule', () => {
    const result = checkPolicy('block_ip', 'L1', 'production');
    expect(result.required_level).toBe('L1');
  });

  it('returns requires_approval from policy rule', () => {
    const result = checkPolicy('block_ip', 'L1', 'production');
    expect(result.requires_approval).toBe(true);
  });

  it('falls back to wildcard rule for unknown actions', () => {
    // The catch-all '*' rule requires L1 and approval
    const result = checkPolicy('restore_file' as StepAction, 'L1', 'production');
    // restore_file should match either an explicit rule or fallback to '*'
    expect(result.required_level).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// validateL2Enabled
// ---------------------------------------------------------------------------

describe('validateL2Enabled', () => {
  it('blocks L2 when enableL2 is false', () => {
    const result = validateL2Enabled(false, 'L2');

    expect(result.allowed).toBe(false);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]!.rule).toBe('l2_flag_required');
    expect(result.violations[0]!.message).toContain('--enable-l2');
  });

  it('allows L2 when enableL2 is true', () => {
    const result = validateL2Enabled(true, 'L2');

    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('allows L0 regardless of enableL2 flag', () => {
    const result = validateL2Enabled(false, 'L0');

    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('allows L1 regardless of enableL2 flag', () => {
    const result = validateL2Enabled(false, 'L1');

    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// validateExecutionPolicy
// ---------------------------------------------------------------------------

describe('validateExecutionPolicy', () => {
  it('validates multiple steps and returns one result per step', () => {
    const steps = [
      { action: 'collect_logs' as StepAction, step_id: 'step-01' },
      { action: 'isolate_host' as StepAction, step_id: 'step-02' },
      { action: 'block_ip' as StepAction, step_id: 'step-03' },
    ];

    const results = validateExecutionPolicy(steps, 'L1', 'production', true);

    expect(results).toHaveLength(3);
    expect(results[0]!.allowed).toBe(true);
    expect(results[1]!.allowed).toBe(true);
    expect(results[2]!.allowed).toBe(true);
  });

  it('blocks all steps when L2 is not enabled', () => {
    const steps = [
      { action: 'collect_logs' as StepAction, step_id: 'step-01' },
      { action: 'isolate_host' as StepAction, step_id: 'step-02' },
    ];

    const results = validateExecutionPolicy(steps, 'L2', 'simulation', false);

    expect(results).toHaveLength(2);
    expect(results[0]!.allowed).toBe(false);
    expect(results[1]!.allowed).toBe(false);
    expect(results[0]!.violations[0]!.rule).toBe('l2_flag_required');
    expect(results[1]!.violations[0]!.rule).toBe('l2_flag_required');
  });

  it('identifies insufficient level for individual steps', () => {
    const steps = [
      { action: 'collect_logs' as StepAction, step_id: 'step-01' },
      { action: 'kill_process' as StepAction, step_id: 'step-02' },
    ];

    const results = validateExecutionPolicy(steps, 'L1', 'production', true);

    expect(results[0]!.allowed).toBe(true); // collect_logs is L0
    expect(results[1]!.allowed).toBe(false); // kill_process requires L2
    expect(results[1]!.violations.some((v) => v.rule === 'insufficient_level')).toBe(true);
  });

  it('returns empty array for empty steps', () => {
    const results = validateExecutionPolicy([], 'L1', 'production', true);
    expect(results).toEqual([]);
  });

  it('uses the correct action per step in the result', () => {
    const steps = [
      { action: 'collect_logs' as StepAction, step_id: 'step-01' },
      { action: 'isolate_host' as StepAction, step_id: 'step-02' },
    ];

    const results = validateExecutionPolicy(steps, 'L1', 'production', true);

    expect(results[0]!.action).toBe('collect_logs');
    expect(results[1]!.action).toBe('isolate_host');
  });

  it('L2 simulation mode allows L2 write actions', () => {
    const steps = [
      { action: 'kill_process' as StepAction, step_id: 'step-01' },
      { action: 'delete_file' as StepAction, step_id: 'step-02' },
    ];

    const results = validateExecutionPolicy(steps, 'L2', 'simulation', true);

    expect(results[0]!.allowed).toBe(true);
    expect(results[1]!.allowed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DEFAULT_POLICY structure
// ---------------------------------------------------------------------------

describe('DEFAULT_POLICY', () => {
  it('has 33 rules', () => {
    expect(DEFAULT_POLICY.rules).toHaveLength(33);
  });

  it('has name "default"', () => {
    expect(DEFAULT_POLICY.name).toBe('default');
  });

  it('has a description', () => {
    expect(DEFAULT_POLICY.description).toBeTruthy();
  });

  it('last rule is the wildcard catch-all', () => {
    const lastRule = DEFAULT_POLICY.rules[DEFAULT_POLICY.rules.length - 1]!;
    expect(lastRule.action).toBe('*');
  });

  it('all rules have required fields', () => {
    for (const rule of DEFAULT_POLICY.rules) {
      expect(rule.action).toBeDefined();
      expect(rule.min_level).toBeDefined();
      expect(typeof rule.requires_approval).toBe('boolean');
      expect(Array.isArray(rule.allowed_modes)).toBe(true);
      expect(typeof rule.admin_override).toBe('boolean');
    }
  });

  it('read-only actions have min_level L0 and no approval required', () => {
    const readActions: StepAction[] = [
      'collect_logs', 'query_siem', 'collect_network_traffic',
      'snapshot_memory', 'collect_file_metadata', 'enrich_ioc',
      'check_reputation', 'query_threat_feed', 'retrieve_edr_data',
      'calculate_hash', 'http_request', 'wait', 'start_edr_scan',
    ];

    for (const action of readActions) {
      const rule = DEFAULT_POLICY.rules.find((r) => r.action === action);
      expect(rule).toBeDefined();
      expect(rule!.min_level).toBe('L0');
      expect(rule!.requires_approval).toBe(false);
    }
  });

  it('destructive actions have min_level L2 and max_risk_score 8', () => {
    const destructiveActions: StepAction[] = [
      'kill_process', 'delete_file', 'quarantine_file', 'execute_script',
    ];

    for (const action of destructiveActions) {
      const rule = DEFAULT_POLICY.rules.find((r) => r.action === action);
      expect(rule).toBeDefined();
      expect(rule!.min_level).toBe('L2');
      expect(rule!.max_risk_score).toBe(8);
      expect(rule!.requires_approval).toBe(true);
    }
  });

  it('notification actions have min_level L0', () => {
    const notificationActions: StepAction[] = [
      'notify_analyst', 'notify_oncall', 'send_email', 'create_ticket', 'update_ticket',
    ];

    for (const action of notificationActions) {
      const rule = DEFAULT_POLICY.rules.find((r) => r.action === action);
      expect(rule).toBeDefined();
      expect(rule!.min_level).toBe('L0');
    }
  });
});
