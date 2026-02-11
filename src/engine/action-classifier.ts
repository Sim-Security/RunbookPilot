/**
 * Action Classification for L1 Automation
 *
 * Classifies StepAction types as 'read' (safe to auto-execute)
 * or 'write' (requires approval). Unknown actions default to 'write'
 * as the safe default.
 *
 * @module engine/action-classifier
 */

import type { StepAction } from '../types/playbook.ts';

export type ActionClassification = 'read' | 'write';

/**
 * Read-only actions that are safe to auto-execute at L1.
 * These actions gather information without modifying state.
 */
const READ_ACTIONS: ReadonlySet<StepAction> = new Set([
  // Data collection
  'collect_logs',
  'query_siem',
  'collect_network_traffic',
  'snapshot_memory',
  'collect_file_metadata',

  // Threat intelligence
  'enrich_ioc',
  'check_reputation',
  'query_threat_feed',

  // EDR read-only
  'retrieve_edr_data',

  // Hash calculation (read-only)
  'calculate_hash',

  // HTTP request (classified as read — specific adapters can override)
  'http_request',

  // Wait (no side effects)
  'wait',
]);

/**
 * Write actions that modify system state and require approval at L1.
 */
const WRITE_ACTIONS: ReadonlySet<StepAction> = new Set([
  // Network isolation
  'isolate_host',
  'restore_connectivity',
  'block_ip',
  'unblock_ip',
  'block_domain',
  'unblock_domain',

  // Ticketing and notifications
  'create_ticket',
  'update_ticket',
  'notify_analyst',
  'notify_oncall',
  'send_email',

  // Account management
  'disable_account',
  'enable_account',
  'reset_password',
  'revoke_session',

  // File operations
  'quarantine_file',
  'restore_file',
  'delete_file',

  // EDR active actions
  'kill_process',
  'start_edr_scan',

  // Script execution
  'execute_script',
]);

/**
 * Classify an action as read or write.
 * Unknown actions default to 'write' (safe default).
 */
export function classifyAction(action: StepAction): ActionClassification {
  if (READ_ACTIONS.has(action)) return 'read';
  if (WRITE_ACTIONS.has(action)) return 'write';
  // Safe default: unknown actions are treated as write
  return 'write';
}

/**
 * Check if an action is read-only (safe to auto-execute).
 */
export function isReadOnly(action: StepAction): boolean {
  return classifyAction(action) === 'read';
}

/**
 * Check if an action is a write operation (requires approval at L1).
 */
export function isWriteAction(action: StepAction): boolean {
  return classifyAction(action) === 'write';
}

/**
 * Get all read-only actions.
 */
export function getReadActions(): StepAction[] {
  return [...READ_ACTIONS];
}

/**
 * Get all write actions.
 */
export function getWriteActions(): StepAction[] {
  return [...WRITE_ACTIONS];
}
