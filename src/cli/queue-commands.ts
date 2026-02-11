/**
 * Approval Queue CLI Commands
 *
 * Registers queue-related subcommands on the main Commander.js program:
 *   queue list     — list pending approval queue entries
 *   queue approve  — approve a pending request
 *   queue deny     — deny a pending request
 *   queue inspect  — show full details of a queue entry
 *   queue expire   — expire all stale entries past their expires_at
 *
 * @module cli/queue-commands
 */

import type { Command } from 'commander';
import type { ApprovalStatus } from '../types/playbook.ts';
import type { ApprovalQueueEntry, SimulationReport } from '../types/simulation.ts';
import { ApprovalQueueRepository } from '../db/approval-queue-repository.ts';
import { initDatabase } from '../db/index.ts';
import { loadConfig } from '../config/index.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Truncate a string to `maxLen` characters, appending an ellipsis if needed. */
function truncate(value: string, maxLen: number): string {
  if (value.length <= maxLen) return value;
  return value.slice(0, maxLen - 1) + '\u2026';
}

/**
 * Compute a human-readable "age" string from an ISO-8601 timestamp to now.
 * Examples: "2m", "1h 14m", "3d 2h"
 */
function formatAge(isoTimestamp: string): string {
  const requestedMs = new Date(isoTimestamp).getTime();
  const nowMs = Date.now();
  let diffSeconds = Math.max(0, Math.floor((nowMs - requestedMs) / 1_000));

  const days = Math.floor(diffSeconds / 86_400);
  diffSeconds %= 86_400;
  const hours = Math.floor(diffSeconds / 3_600);
  diffSeconds %= 3_600;
  const minutes = Math.floor(diffSeconds / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return '<1m';
}

/**
 * Safely parse a JSON string, returning `undefined` on failure.
 */
function safeParse(jsonStr: string): unknown {
  try {
    return JSON.parse(jsonStr);
  } catch {
    return undefined;
  }
}

/**
 * Initialize the database and return an ApprovalQueueRepository.
 * Loads config to determine the DB path, then opens the database.
 */
function getRepository(): ApprovalQueueRepository {
  const config = loadConfig();
  const db = initDatabase({ path: config.dbPath });
  return new ApprovalQueueRepository(db);
}

/**
 * Extract risk score and confidence from a simulation_result JSON string.
 * Falls back to 'N/A' if the JSON is unparseable or the fields are missing.
 */
function extractSimulationMeta(simulationResult: string): {
  riskScore: string;
  confidence: string;
} {
  const parsed = safeParse(simulationResult) as SimulationReport | undefined;
  if (!parsed) {
    return { riskScore: 'N/A', confidence: 'N/A' };
  }
  const riskScore =
    typeof parsed.overall_risk_score === 'number'
      ? String(parsed.overall_risk_score)
      : 'N/A';
  const confidence =
    typeof parsed.overall_confidence === 'number'
      ? `${Math.round(parsed.overall_confidence * 100)}%`
      : 'N/A';
  return { riskScore, confidence };
}

// ---------------------------------------------------------------------------
// Table renderer
// ---------------------------------------------------------------------------

interface Column {
  header: string;
  width: number;
  align: 'left' | 'right';
}

function renderTable(columns: Column[], rows: string[][]): void {
  // Header
  const headerLine = columns
    .map((col) =>
      col.align === 'right'
        ? col.header.padStart(col.width)
        : col.header.padEnd(col.width),
    )
    .join('  ');
  console.log(headerLine);

  // Separator
  const separator = columns.map((col) => '-'.repeat(col.width)).join('  ');
  console.log(separator);

  // Rows
  for (const row of rows) {
    const line = columns
      .map((col, i) => {
        const value = truncate(row[i] ?? '', col.width);
        return col.align === 'right'
          ? value.padStart(col.width)
          : value.padEnd(col.width);
      })
      .join('  ');
    console.log(line);
  }
}

// ---------------------------------------------------------------------------
// Command registration
// ---------------------------------------------------------------------------

const VALID_STATUSES = new Set<ApprovalStatus>([
  'pending',
  'approved',
  'denied',
  'expired',
]);

export function registerQueueCommands(program: Command): void {
  const queue = program
    .command('queue')
    .description('Manage the L2 approval queue');

  // -----------------------------------------------------------------------
  // queue list
  // -----------------------------------------------------------------------
  queue
    .command('list')
    .description('List approval queue entries')
    .option(
      '--status <status>',
      'Filter by status (pending|approved|denied|expired)',
      'pending',
    )
    .option('--limit <n>', 'Maximum number of entries to show', '50')
    .option('--format <format>', 'Output format (table|json)', 'table')
    .action((options: { status: string; limit: string; format: string }) => {
      const status = options.status as ApprovalStatus;
      if (!VALID_STATUSES.has(status)) {
        console.error(
          `Error: Invalid status "${options.status}". Must be one of: pending, approved, denied, expired`,
        );
        process.exit(1);
      }

      const limit = Number.parseInt(options.limit, 10);
      if (Number.isNaN(limit) || limit < 1) {
        console.error(
          `Error: Invalid limit "${options.limit}". Must be a positive integer.`,
        );
        process.exit(1);
      }

      const repo = getRepository();
      const entries = repo.listByStatus(status, limit);

      if (options.format === 'json') {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      // Table format
      if (entries.length === 0) {
        console.log(`No ${status} entries in the approval queue.`);
        return;
      }

      const columns: Column[] = [
        { header: 'ID', width: 8, align: 'left' },
        { header: 'Playbook', width: 24, align: 'left' },
        { header: 'Action', width: 18, align: 'left' },
        { header: 'Risk', width: 5, align: 'right' },
        { header: 'Conf.', width: 5, align: 'right' },
        { header: 'Age', width: 8, align: 'right' },
      ];

      const rows = entries.map((entry: ApprovalQueueEntry) => {
        const { riskScore, confidence } = extractSimulationMeta(
          entry.simulation_result,
        );
        return [
          entry.request_id.slice(0, 8),
          entry.runbook_name,
          entry.action,
          riskScore,
          confidence,
          formatAge(entry.requested_at),
        ];
      });

      console.log('');
      console.log(`Approval Queue — ${status} (${entries.length} entries)`);
      console.log('');
      renderTable(columns, rows);
      console.log('');
    });

  // -----------------------------------------------------------------------
  // queue approve <request-id>
  // -----------------------------------------------------------------------
  queue
    .command('approve <request-id>')
    .description('Approve a pending approval request')
    .option(
      '--approver <name>',
      'Name of the approver',
      process.env['USER'] || 'cli-user',
    )
    .action((requestId: string, options: { approver: string }) => {
      const repo = getRepository();

      try {
        const updated = repo.approve(requestId, options.approver);
        console.log('');
        console.log('Request approved successfully.');
        console.log('');
        console.log(`  Request ID:  ${updated.request_id}`);
        console.log(`  Playbook:    ${updated.runbook_name}`);
        console.log(`  Step:        ${updated.step_name}`);
        console.log(`  Action:      ${updated.action}`);
        console.log(`  Approved By: ${updated.approved_by}`);
        console.log(`  Approved At: ${updated.approved_at}`);
        console.log('');
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`,
        );
        process.exit(1);
      }
    });

  // -----------------------------------------------------------------------
  // queue deny <request-id>
  // -----------------------------------------------------------------------
  queue
    .command('deny <request-id>')
    .description('Deny a pending approval request')
    .requiredOption('--reason <reason>', 'Reason for denial')
    .action((requestId: string, options: { reason: string }) => {
      const repo = getRepository();

      try {
        const updated = repo.deny(requestId, options.reason);
        console.log('');
        console.log('Request denied.');
        console.log('');
        console.log(`  Request ID:     ${updated.request_id}`);
        console.log(`  Playbook:       ${updated.runbook_name}`);
        console.log(`  Step:           ${updated.step_name}`);
        console.log(`  Action:         ${updated.action}`);
        console.log(`  Denial Reason:  ${updated.denial_reason}`);
        console.log('');
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`,
        );
        process.exit(1);
      }
    });

  // -----------------------------------------------------------------------
  // queue inspect <request-id>
  // -----------------------------------------------------------------------
  queue
    .command('inspect <request-id>')
    .description('Show full details of a queue entry')
    .option('--json', 'Output as raw JSON')
    .action((requestId: string, options: { json?: boolean }) => {
      const repo = getRepository();
      const entry = repo.getById(requestId);

      if (!entry) {
        console.error(`Error: Approval request not found: ${requestId}`);
        process.exit(1);
      }

      if (options.json) {
        // Expand JSON-serialized fields for a fully parsed output
        const output = {
          ...entry,
          parameters: safeParse(entry.parameters) ?? entry.parameters,
          simulation_result:
            safeParse(entry.simulation_result) ?? entry.simulation_result,
        };
        console.log(JSON.stringify(output, null, 2));
        return;
      }

      // Human-readable output
      const { riskScore, confidence } = extractSimulationMeta(
        entry.simulation_result,
      );
      const simReport = safeParse(entry.simulation_result) as
        | SimulationReport
        | undefined;

      console.log('');
      console.log(`Approval Request: ${entry.request_id}`);
      console.log('='.repeat(60));
      console.log('');

      // Core fields
      console.log('  General');
      console.log('  ' + '-'.repeat(56));
      console.log(`  Status:          ${entry.status}`);
      console.log(`  Execution ID:    ${entry.execution_id}`);
      console.log(`  Runbook:         ${entry.runbook_name} (${entry.runbook_id})`);
      console.log(`  Step:            ${entry.step_name} (${entry.step_id})`);
      console.log(`  Action:          ${entry.action}`);
      console.log(`  Requested At:    ${entry.requested_at}`);
      console.log(`  Expires At:      ${entry.expires_at}`);
      console.log(`  Age:             ${formatAge(entry.requested_at)}`);
      console.log('');

      // Approval / denial details
      if (entry.status === 'approved') {
        console.log('  Approval');
        console.log('  ' + '-'.repeat(56));
        console.log(`  Approved By:     ${entry.approved_by ?? 'N/A'}`);
        console.log(`  Approved At:     ${entry.approved_at ?? 'N/A'}`);
        console.log('');
      } else if (entry.status === 'denied') {
        console.log('  Denial');
        console.log('  ' + '-'.repeat(56));
        console.log(`  Denial Reason:   ${entry.denial_reason ?? 'N/A'}`);
        console.log('');
      }

      // Parameters
      console.log('  Parameters');
      console.log('  ' + '-'.repeat(56));
      const params = safeParse(entry.parameters);
      if (params && typeof params === 'object') {
        for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
          console.log(`  ${key.padEnd(16)} ${JSON.stringify(value)}`);
        }
      } else {
        console.log(`  ${entry.parameters}`);
      }
      console.log('');

      // Risk assessment
      console.log('  Risk Assessment');
      console.log('  ' + '-'.repeat(56));
      console.log(`  Risk Score:      ${riskScore}`);
      console.log(`  Confidence:      ${confidence}`);
      if (simReport) {
        console.log(`  Risk Level:      ${simReport.overall_risk_level ?? 'N/A'}`);
        console.log(`  Predicted:       ${simReport.predicted_outcome ?? 'N/A'}`);
        if (
          simReport.risks_identified &&
          simReport.risks_identified.length > 0
        ) {
          console.log('  Risks:');
          for (const risk of simReport.risks_identified) {
            console.log(`    - ${risk}`);
          }
        }
        if (
          simReport.affected_assets &&
          simReport.affected_assets.length > 0
        ) {
          console.log(
            `  Affected Assets: ${simReport.affected_assets.join(', ')}`,
          );
        }
      }
      console.log('');

      // Simulation report steps summary
      if (simReport && simReport.steps && simReport.steps.length > 0) {
        console.log('  Simulation Steps');
        console.log('  ' + '-'.repeat(56));
        for (const step of simReport.steps) {
          const stepConf =
            typeof step.confidence === 'number'
              ? `${Math.round(step.confidence * 100)}%`
              : 'N/A';
          console.log(
            `  [${step.step_id}] ${step.step_name} — ${step.action} (conf: ${stepConf})`,
          );
          if (step.side_effects && step.side_effects.length > 0) {
            for (const effect of step.side_effects) {
              console.log(`    side-effect: ${effect}`);
            }
          }
          if (step.validation_errors && step.validation_errors.length > 0) {
            for (const err of step.validation_errors) {
              console.log(`    validation-error: ${err}`);
            }
          }
        }
        console.log('');
      }

      // Rollback plan
      if (simReport && simReport.rollback_plan) {
        const plan = simReport.rollback_plan;
        console.log('  Rollback Plan');
        console.log('  ' + '-'.repeat(56));
        console.log(`  Available:       ${plan.available ? 'yes' : 'no'}`);
        if (plan.steps && plan.steps.length > 0) {
          for (const rbStep of plan.steps) {
            console.log(
              `  [${rbStep.step_id}] ${rbStep.original_action} -> ${rbStep.rollback_action} (timeout: ${rbStep.timeout}s)`,
            );
          }
        }
        console.log('');
      }
    });

  // -----------------------------------------------------------------------
  // queue expire
  // -----------------------------------------------------------------------
  queue
    .command('expire')
    .description('Expire all stale entries past their expires_at')
    .action(() => {
      const repo = getRepository();
      const count = repo.expireStale();

      if (count === 0) {
        console.log('No stale entries to expire.');
      } else {
        console.log(`Expired ${count} stale approval queue ${count === 1 ? 'entry' : 'entries'}.`);
      }
    });
}
