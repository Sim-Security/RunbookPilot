/**
 * Policy Enforcer for Automation Level Constraints
 *
 * Enforces automation level constraints (L0/L1/L2) by checking
 * requested actions against an AutomationPolicy ruleset. Each rule
 * specifies the minimum automation level, approval requirements,
 * risk-score caps, and allowed execution modes per action.
 *
 * Key design decisions:
 * - L2 in production mode with write actions is always blocked (v1: simulation-only).
 * - Admin override allows actions to proceed despite violations, but violations
 *   are still reported as warnings for audit purposes.
 * - Unknown actions fall through to the '*' catch-all rule.
 *
 * @module engine/policy-enforcer
 */

import type {
  StepAction,
  AutomationLevel,
  ExecutionMode,
} from '../types/playbook.ts';
import type {
  AutomationPolicy,
  PolicyRule,
  PolicyCheckResult,
  PolicyViolation,
} from '../types/simulation.ts';
import { isWriteAction } from './action-classifier.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Numeric ordering of automation levels.
 * L0 (recommend only) < L1 (auto-execute safe) < L2 (auto-execute impactful).
 * Higher numbers are more permissive.
 */
export const LEVEL_ORDER: Record<AutomationLevel, number> = {
  L0: 0,
  L1: 1,
  L2: 2,
};

/**
 * Default automation policy shipped with RunbookPilot.
 * Rules are matched in order: exact action match first, then '*' fallback.
 */
export const DEFAULT_POLICY: AutomationPolicy = {
  name: 'default',
  description:
    'Default RunbookPilot automation policy with graduated autonomy constraints.',
  rules: [
    // --- Read / data-collection actions (L0, no approval) ---
    {
      action: 'collect_logs',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'query_siem',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'collect_network_traffic',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'snapshot_memory',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'collect_file_metadata',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'enrich_ioc',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'check_reputation',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'query_threat_feed',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'retrieve_edr_data',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'calculate_hash',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'http_request',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'wait',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'start_edr_scan',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },

    // --- Notification actions (L0, no approval) ---
    {
      action: 'notify_analyst',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'notify_oncall',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'send_email',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'create_ticket',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },
    {
      action: 'update_ticket',
      min_level: 'L0',
      requires_approval: false,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: false,
    },

    // --- Network isolation (L1, approval required) ---
    {
      action: 'isolate_host',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'restore_connectivity',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },

    // --- IP/domain blocking (L1, approval required) ---
    {
      action: 'block_ip',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'unblock_ip',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'block_domain',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'unblock_domain',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },

    // --- Account management (L1, approval required) ---
    {
      action: 'disable_account',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'enable_account',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'reset_password',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'revoke_session',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },

    // --- Destructive actions (L2, approval required, risk-capped) ---
    {
      action: 'kill_process',
      min_level: 'L2',
      requires_approval: true,
      max_risk_score: 8,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'delete_file',
      min_level: 'L2',
      requires_approval: true,
      max_risk_score: 8,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'quarantine_file',
      min_level: 'L2',
      requires_approval: true,
      max_risk_score: 8,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
    {
      action: 'execute_script',
      min_level: 'L2',
      requires_approval: true,
      max_risk_score: 8,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },

    // --- Catch-all rule (must be last) ---
    {
      action: '*',
      min_level: 'L1',
      requires_approval: true,
      allowed_modes: ['production', 'simulation', 'dry-run'],
      admin_override: true,
    },
  ],
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Find the matching policy rule for a given action.
 * Performs an exact match first; falls back to the '*' catch-all rule.
 *
 * @param action  - The step action to look up.
 * @param policy  - The automation policy to search.
 * @returns The matching PolicyRule, or undefined if no rule found.
 */
function findRule(
  action: StepAction,
  policy: AutomationPolicy,
): PolicyRule | undefined {
  // Exact match first
  const exact = policy.rules.find((r) => r.action === action);
  if (exact) return exact;

  // Fallback to wildcard
  return policy.rules.find((r) => r.action === '*');
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Check whether an automation level is sufficient for a required level.
 *
 * @param requested - The level the caller is requesting to operate at.
 * @param required  - The minimum level the policy requires.
 * @returns `true` if requested >= required.
 */
export function isLevelSufficient(
  requested: AutomationLevel,
  required: AutomationLevel,
): boolean {
  return LEVEL_ORDER[requested] >= LEVEL_ORDER[required];
}

/**
 * Get the minimum automation level required for a given action.
 *
 * @param action - The step action to check.
 * @param policy - The automation policy (defaults to DEFAULT_POLICY).
 * @returns The minimum AutomationLevel needed.
 */
export function getRequiredLevel(
  action: StepAction,
  policy: AutomationPolicy = DEFAULT_POLICY,
): AutomationLevel {
  const rule = findRule(action, policy);
  return rule ? rule.min_level : 'L1'; // safe default
}

/**
 * Determine whether a given action requires approval at the specified level.
 *
 * @param action - The step action to check.
 * @param level  - The automation level being used.
 * @param policy - The automation policy (defaults to DEFAULT_POLICY).
 * @returns `true` if approval is required.
 */
export function requiresApproval(
  action: StepAction,
  _level: AutomationLevel,
  policy: AutomationPolicy = DEFAULT_POLICY,
): boolean {
  const rule = findRule(action, policy);
  if (!rule) return true; // safe default
  return rule.requires_approval;
}

/**
 * Validate that L2 simulation mode has been explicitly enabled.
 *
 * In v1 of RunbookPilot, L2 is simulation-only and must be opted into
 * via the `--enable-l2` CLI flag.
 *
 * @param enableL2 - Whether the --enable-l2 flag was provided.
 * @param level    - The requested automation level.
 * @returns A PolicyCheckResult indicating whether L2 is allowed.
 */
export function validateL2Enabled(
  enableL2: boolean,
  level: AutomationLevel,
): PolicyCheckResult {
  if (level === 'L2' && !enableL2) {
    return {
      allowed: false,
      action: '*' as StepAction,
      requested_level: level,
      required_level: 'L2',
      requires_approval: false,
      violations: [
        {
          rule: 'l2_flag_required',
          message: 'L2 simulation mode requires --enable-l2 flag',
          severity: 'error',
        },
      ],
    };
  }

  return {
    allowed: true,
    action: '*' as StepAction,
    requested_level: level,
    required_level: level,
    requires_approval: false,
    violations: [],
  };
}

/**
 * Check a single action against the automation policy.
 *
 * Evaluates the following constraints in order:
 * 1. Automation level sufficiency (requestedLevel >= rule.min_level)
 * 2. Execution mode allowance (mode in rule.allowed_modes)
 * 3. Risk score cap (riskScore <= rule.max_risk_score, if defined)
 * 4. L2 production write guard (L2 + production + write = blocked in v1)
 * 5. Admin override (admin can bypass violations if rule.admin_override is true)
 *
 * @param action         - The step action to check.
 * @param requestedLevel - The automation level being requested.
 * @param mode           - The execution mode (production/simulation/dry-run).
 * @param policy         - The automation policy (defaults to DEFAULT_POLICY).
 * @param riskScore      - Optional risk score for the action (1-10).
 * @param isAdmin        - Whether the caller has admin privileges.
 * @returns A PolicyCheckResult with violations (if any).
 */
export function checkPolicy(
  action: StepAction,
  requestedLevel: AutomationLevel,
  mode: ExecutionMode,
  policy: AutomationPolicy = DEFAULT_POLICY,
  riskScore?: number,
  isAdmin?: boolean,
): PolicyCheckResult {
  const rule = findRule(action, policy);
  const violations: PolicyViolation[] = [];

  // If no rule found, deny by default
  if (!rule) {
    return {
      allowed: false,
      action,
      requested_level: requestedLevel,
      required_level: 'L1',
      requires_approval: true,
      violations: [
        {
          rule: 'no_matching_rule',
          message: `No policy rule found for action '${action}'`,
          severity: 'error',
        },
      ],
    };
  }

  const requiredLevel = rule.min_level;

  // 1. Check automation level sufficiency
  if (!isLevelSufficient(requestedLevel, requiredLevel)) {
    violations.push({
      rule: 'insufficient_level',
      message: `Action '${action}' requires ${requiredLevel} but requested level is ${requestedLevel}`,
      severity: 'error',
    });
  }

  // 2. Check execution mode allowance
  if (!rule.allowed_modes.includes(mode)) {
    violations.push({
      rule: 'mode_not_allowed',
      message: `Action '${action}' is not allowed in '${mode}' mode`,
      severity: 'error',
    });
  }

  // 3. Check risk score cap
  if (
    rule.max_risk_score !== undefined &&
    riskScore !== undefined &&
    riskScore > rule.max_risk_score
  ) {
    violations.push({
      rule: 'risk_score_exceeded',
      message: `Action '${action}' has risk score ${riskScore} exceeding max allowed ${rule.max_risk_score}`,
      severity: 'error',
    });
  }

  // 4. L2 production write guard (v1: L2 is simulation-only)
  if (
    requestedLevel === 'L2' &&
    mode === 'production' &&
    isWriteAction(action)
  ) {
    violations.push({
      rule: 'l2_production_write_blocked',
      message: `L2 write action '${action}' is not allowed in production mode (L2 is simulation-only in v1)`,
      severity: 'error',
    });
  }

  // 5. Determine final allowed status
  let allowed = violations.length === 0;

  // Admin override: if the caller is admin and the rule supports override,
  // allow the action but downgrade violations to warnings for audit trail.
  if (!allowed && isAdmin && rule.admin_override) {
    allowed = true;
    for (const violation of violations) {
      violation.severity = 'warning';
    }
  }

  return {
    allowed,
    action,
    requested_level: requestedLevel,
    required_level: requiredLevel,
    requires_approval: rule.requires_approval,
    violations,
  };
}

/**
 * Validate an entire set of execution steps against the automation policy.
 *
 * Iterates over each step, running `checkPolicy` and (for L2) the
 * `validateL2Enabled` gate. Returns one PolicyCheckResult per step.
 *
 * @param steps    - Array of steps with action and step_id fields.
 * @param level    - The automation level for this execution.
 * @param mode     - The execution mode (production/simulation/dry-run).
 * @param enableL2 - Whether the --enable-l2 flag was provided.
 * @param policy   - The automation policy (defaults to DEFAULT_POLICY).
 * @returns An array of PolicyCheckResult, one per step.
 */
export function validateExecutionPolicy(
  steps: Array<{ action: StepAction; step_id: string }>,
  level: AutomationLevel,
  mode: ExecutionMode,
  enableL2: boolean,
  policy: AutomationPolicy = DEFAULT_POLICY,
): PolicyCheckResult[] {
  // Check the L2 flag once up front
  const l2Check = validateL2Enabled(enableL2, level);
  if (!l2Check.allowed) {
    // Return the same L2 violation for every step
    return steps.map((step) => ({
      ...l2Check,
      action: step.action,
    }));
  }

  return steps.map((step) => checkPolicy(step.action, level, mode, policy));
}
