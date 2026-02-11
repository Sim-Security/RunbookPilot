/**
 * Impact Assessor for L2 Simulation
 *
 * Assesses the blast radius and risk of simulated actions.
 * Calculates risk scores, determines blast radius, checks reversibility,
 * and generates human-readable impact summaries for approval workflows.
 *
 * Risk scores are deterministic (no LLM) and based on a static mapping
 * of StepAction -> base risk score (1-10), adjusted by the number of
 * affected assets extracted from step parameters.
 *
 * @module engine/impact-assessor
 */

import type { StepAction, RunbookStep } from '../types/playbook.ts';
import type { ImpactAssessment, RiskLevel, BlastRadius } from '../types/simulation.ts';
import { isWriteAction } from './action-classifier.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Base risk scores for each action (1-10 scale).
 * Read-only actions score 1; write actions vary by destructiveness.
 */
const ACTION_RISK_SCORES: Readonly<Record<StepAction, number>> = {
  // Network isolation
  isolate_host: 8,           // high impact - cuts off network
  restore_connectivity: 3,   // low - restoring access
  block_ip: 6,               // medium - blocks one IP
  unblock_ip: 3,             // low - restoring access
  block_domain: 7,           // medium-high - could break services
  unblock_domain: 3,         // low - restoring access

  // Data collection (read-only)
  collect_logs: 1,
  query_siem: 1,
  collect_network_traffic: 1,
  snapshot_memory: 1,
  collect_file_metadata: 1,

  // Threat intelligence (read-only)
  enrich_ioc: 1,
  check_reputation: 1,
  query_threat_feed: 1,

  // Ticketing and notifications
  create_ticket: 1,          // minimal - creates a ticket
  update_ticket: 1,          // minimal
  notify_analyst: 1,         // minimal
  notify_oncall: 2,          // slightly higher - pages someone
  send_email: 2,             // low

  // Account management
  disable_account: 8,        // high - locks out user
  enable_account: 3,         // low - restoring access
  reset_password: 7,         // high - user can't log in
  revoke_session: 5,         // medium - disrupts user

  // File operations
  quarantine_file: 6,        // medium - removes file from use
  restore_file: 3,           // low - restoring access
  delete_file: 9,            // very high - irreversible
  calculate_hash: 1,         // read-only

  // EDR/XDR actions
  kill_process: 7,           // high - could kill critical process
  start_edr_scan: 2,         // low - just a scan
  retrieve_edr_data: 1,      // read-only

  // Custom actions
  execute_script: 9,         // very high - arbitrary code
  http_request: 1,           // read-only (classified as read)
  wait: 1,                   // no side effects
};

/**
 * Known rollback pairs: action -> its reverse action.
 * If an action appears as a key, it is considered reversible.
 */
const ROLLBACK_PAIRS: Readonly<Partial<Record<StepAction, StepAction>>> = {
  isolate_host: 'restore_connectivity',
  block_ip: 'unblock_ip',
  block_domain: 'unblock_domain',
  disable_account: 'enable_account',
  quarantine_file: 'restore_file',
};

/**
 * Parameter keys that identify affected assets.
 */
const ASSET_PARAM_KEYS: readonly string[] = [
  'host_id',
  'hostname',
  'ip',
  'ip_address',
  'domain',
  'account',
  'user',
  'file_path',
  'process_id',
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Assess the impact of a single runbook step.
 *
 * @param step - The runbook step to assess.
 * @param params - Resolved parameters for the step (may override step.parameters).
 * @returns A full ImpactAssessment for the step.
 */
export function assessStepImpact(
  step: RunbookStep,
  params: Record<string, unknown>,
): ImpactAssessment {
  const action = step.action;
  const riskScore = ACTION_RISK_SCORES[action] ?? (isWriteAction(action) ? 5 : 1);
  const riskLevel = riskLevelFromScore(riskScore);
  const blastRadius = estimateBlastRadius(action, params);
  const reversible = isReversible(action);
  const rollbackAvailable = reversible || step.rollback !== undefined;
  const affectedAssets = getAffectedAssets(step, params);
  const dependencies = extractDependencies(action, params);
  const summary = generateSummary(action, affectedAssets, riskLevel, blastRadius, rollbackAvailable);

  return {
    action,
    risk_score: riskScore,
    risk_level: riskLevel,
    blast_radius: blastRadius,
    dependencies,
    summary,
    reversible,
    rollback_available: rollbackAvailable,
  };
}

/**
 * Assess the impact of every step in a playbook.
 *
 * @param steps - Ordered list of runbook steps.
 * @param params - Map of step ID to resolved parameters.
 * @returns An ImpactAssessment for each step (same order).
 */
export function assessPlaybookImpact(
  steps: RunbookStep[],
  params: Record<string, Record<string, unknown>>,
): ImpactAssessment[] {
  return steps.map((step) => {
    const stepParams = params[step.id] ?? step.parameters;
    return assessStepImpact(step, stepParams);
  });
}

/**
 * Calculate the overall risk across multiple assessments.
 * Overall risk is the maximum of individual risk scores.
 *
 * @param assessments - Array of per-step impact assessments.
 * @returns Combined risk score (1-10) and corresponding risk level.
 */
export function calculateOverallRisk(
  assessments: ImpactAssessment[],
): { score: number; level: RiskLevel } {
  if (assessments.length === 0) {
    return { score: 1, level: 'low' };
  }

  const maxScore = Math.max(...assessments.map((a) => a.risk_score));
  return {
    score: maxScore,
    level: riskLevelFromScore(maxScore),
  };
}

/**
 * Extract affected asset identifiers from step parameters.
 * Looks for well-known parameter keys (host_id, hostname, ip, etc.)
 * and returns their values as strings.
 *
 * @param step - The runbook step.
 * @param params - Resolved parameters for the step.
 * @returns Array of asset identifier strings.
 */
export function getAffectedAssets(
  step: RunbookStep,
  params: Record<string, unknown>,
): string[] {
  const merged: Record<string, unknown> = { ...step.parameters, ...params };
  const assets: string[] = [];

  for (const key of ASSET_PARAM_KEYS) {
    const value = merged[key];
    if (value === undefined || value === null) continue;

    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) {
          assets.push(String(item));
        }
      }
    } else {
      assets.push(String(value));
    }
  }

  return assets;
}

/**
 * Check whether an action has a known rollback pair,
 * making it inherently reversible.
 *
 * @param action - The step action to check.
 * @returns True if a rollback pair exists for the action.
 */
export function isReversible(action: StepAction): boolean {
  return action in ROLLBACK_PAIRS;
}

/**
 * Estimate the blast radius for an action based on its type and parameters.
 * Counts hosts, users, and services affected by examining the params.
 *
 * @param action - The step action.
 * @param params - Resolved parameters for the step.
 * @returns A BlastRadius estimate.
 */
export function estimateBlastRadius(
  action: StepAction,
  params: Record<string, unknown>,
): BlastRadius {
  const affectedAssets: string[] = [];
  let hostsAffected = 0;
  let usersAffected = 0;
  let servicesAffected = 0;

  // Count hosts from host-related params
  hostsAffected += countParam(params, 'host_id');
  hostsAffected += countParam(params, 'hostname');

  // Count users from user-related params
  usersAffected += countParam(params, 'account');
  usersAffected += countParam(params, 'user');

  // Collect all asset identifiers
  for (const key of ASSET_PARAM_KEYS) {
    const value = params[key];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) {
          affectedAssets.push(String(item));
        }
      }
    } else {
      affectedAssets.push(String(value));
    }
  }

  // Estimate based on action type when params don't give us counts
  switch (action) {
    case 'isolate_host':
    case 'restore_connectivity':
      // At least 1 host
      hostsAffected = Math.max(hostsAffected, 1);
      break;

    case 'block_ip':
    case 'unblock_ip':
      // Blocking an IP may affect the service behind it
      hostsAffected = Math.max(hostsAffected, countParam(params, 'ip') + countParam(params, 'ip_address'));
      servicesAffected = Math.max(servicesAffected, 1);
      break;

    case 'block_domain':
    case 'unblock_domain':
      // Blocking a domain can affect many services
      servicesAffected = Math.max(servicesAffected, countParam(params, 'domain'));
      servicesAffected = Math.max(servicesAffected, 1);
      break;

    case 'disable_account':
    case 'enable_account':
    case 'reset_password':
    case 'revoke_session':
      // At least 1 user
      usersAffected = Math.max(usersAffected, 1);
      break;

    case 'kill_process':
      // At least 1 host
      hostsAffected = Math.max(hostsAffected, 1);
      break;

    case 'quarantine_file':
    case 'restore_file':
    case 'delete_file':
      // At least 1 host (where the file lives)
      hostsAffected = Math.max(hostsAffected, 1);
      break;

    case 'execute_script':
      // Scripts can affect multiple hosts; default to at least 1
      hostsAffected = Math.max(hostsAffected, 1);
      servicesAffected = Math.max(servicesAffected, 1);
      break;

    default:
      // Read-only / low-impact actions: no blast radius adjustment
      break;
  }

  return {
    hosts_affected: hostsAffected,
    users_affected: usersAffected,
    services_affected: servicesAffected,
    affected_assets: affectedAssets,
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Map a numeric risk score (1-10) to a RiskLevel label.
 *
 * @param score - Risk score from 1 to 10.
 * @returns The corresponding RiskLevel.
 */
function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Count the number of values for a parameter key.
 * Arrays count as their length; scalars count as 1; missing counts as 0.
 *
 * @param params - Parameter map to inspect.
 * @param key - The key to count.
 * @returns Number of values for the key.
 */
function countParam(params: Record<string, unknown>, key: string): number {
  const value = params[key];
  if (value === undefined || value === null) return 0;
  if (Array.isArray(value)) return value.length;
  return 1;
}

/**
 * Extract dependency/service identifiers from params.
 * Looks for 'service', 'services', 'system', 'systems' keys.
 *
 * @param action - The step action (unused currently but available for future logic).
 * @param params - Resolved parameters.
 * @returns Array of dependency/service names.
 */
function extractDependencies(
  _action: StepAction,
  params: Record<string, unknown>,
): string[] {
  const depKeys = ['service', 'services', 'system', 'systems'];
  const deps: string[] = [];

  for (const key of depKeys) {
    const value = params[key];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== undefined && item !== null) {
          deps.push(String(item));
        }
      }
    } else {
      deps.push(String(value));
    }
  }

  return deps;
}

/**
 * Format a StepAction for human-readable display.
 * Replaces underscores with spaces (e.g., 'isolate_host' -> 'isolate host').
 *
 * @param action - The step action.
 * @returns Human-readable action label.
 */
function formatAction(action: StepAction): string {
  return action.replace(/_/g, ' ');
}

/**
 * Generate a human-readable impact summary string.
 *
 * Example output:
 * "Would isolate host workstation-042 from network. Risk: HIGH. 1 host, 0 users affected. Rollback available."
 *
 * @param action - The step action.
 * @param assets - Affected asset identifiers.
 * @param riskLevel - Computed risk level.
 * @param blastRadius - Computed blast radius.
 * @param rollbackAvailable - Whether a rollback path exists.
 * @returns Human-readable summary.
 */
function generateSummary(
  action: StepAction,
  assets: string[],
  riskLevel: RiskLevel,
  blastRadius: BlastRadius,
  rollbackAvailable: boolean,
): string {
  const actionLabel = formatAction(action);
  const assetStr = assets.length > 0 ? ` ${assets.join(', ')}` : '';

  // Build the action description
  let description: string;
  switch (action) {
    case 'isolate_host':
      description = `Would isolate host${assetStr} from network`;
      break;
    case 'restore_connectivity':
      description = `Would restore connectivity for host${assetStr}`;
      break;
    case 'block_ip':
      description = `Would block IP${assetStr}`;
      break;
    case 'unblock_ip':
      description = `Would unblock IP${assetStr}`;
      break;
    case 'block_domain':
      description = `Would block domain${assetStr}`;
      break;
    case 'unblock_domain':
      description = `Would unblock domain${assetStr}`;
      break;
    case 'disable_account':
      description = `Would disable account${assetStr}`;
      break;
    case 'enable_account':
      description = `Would enable account${assetStr}`;
      break;
    case 'reset_password':
      description = `Would reset password for${assetStr || ' target account'}`;
      break;
    case 'revoke_session':
      description = `Would revoke session for${assetStr || ' target user'}`;
      break;
    case 'kill_process':
      description = `Would kill process${assetStr}`;
      break;
    case 'quarantine_file':
      description = `Would quarantine file${assetStr}`;
      break;
    case 'restore_file':
      description = `Would restore file${assetStr}`;
      break;
    case 'delete_file':
      description = `Would delete file${assetStr}`;
      break;
    case 'execute_script':
      description = `Would execute script${assetStr}`;
      break;
    default:
      description = `Would ${actionLabel}${assetStr}`;
      break;
  }

  const hostsLabel = blastRadius.hosts_affected === 1 ? 'host' : 'hosts';
  const usersLabel = blastRadius.users_affected === 1 ? 'user' : 'users';
  const rollbackLabel = rollbackAvailable ? 'Rollback available' : 'No rollback available';

  return (
    `${description}. ` +
    `Risk: ${riskLevel.toUpperCase()}. ` +
    `${blastRadius.hosts_affected} ${hostsLabel}, ` +
    `${blastRadius.users_affected} ${usersLabel} affected. ` +
    `${rollbackLabel}.`
  );
}
