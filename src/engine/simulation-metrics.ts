/**
 * Simulation Metrics Collector
 *
 * Collects and aggregates L2 simulation metrics for dashboard reporting.
 * Since no dedicated simulation_metrics table exists in the schema, this
 * module performs in-memory aggregation from the audit_log and approval_queue
 * tables. Individual simulation events are recorded via audit log entries,
 * and approval lifecycle events (approval, denial, expiration, execution
 * from queue) are tracked via the approval_queue table.
 *
 * The collector also maintains an in-memory buffer of events recorded
 * through its public API, so that metrics can be computed even before
 * data is persisted to SQLite.
 *
 * @module engine/simulation-metrics
 */

import { randomUUID } from 'crypto';
import type Database from 'better-sqlite3';
import type { SimulationMetricsRecord, SimulationReport } from '../types/simulation.ts';
import { logger } from '../logging/logger.ts';

// ---------------------------------------------------------------------------
// Internal Types
// ---------------------------------------------------------------------------

/**
 * Raw row shape from an audit_log query aggregated by event_type.
 */
interface AuditCountRow {
  readonly event_type: string;
  readonly count: number;
}

/**
 * Raw row from audit_log with details JSON for simulation events.
 */
interface AuditDetailRow {
  readonly id: string;
  readonly timestamp: string;
  readonly execution_id: string;
  readonly event_type: string;
  readonly details: string;
}

/**
 * Raw row from approval_queue for latency calculations.
 */
interface ApprovalLatencyRow {
  readonly request_id: string;
  readonly requested_at: string;
  readonly approved_at: string | null;
  readonly status: string;
}

/**
 * In-memory record of a simulation event.
 */
interface SimulationEvent {
  simulation_id: string;
  timestamp: string;
  risk_score: number;
  confidence: number;
  action_distribution: Record<string, number>;
}

/**
 * In-memory record of an approval lifecycle event.
 */
interface ApprovalEvent {
  request_id: string;
  timestamp: string;
  type: 'approval' | 'denial' | 'expiration' | 'execution';
  latency_ms?: number;
}

// ---------------------------------------------------------------------------
// SimulationMetricsCollector
// ---------------------------------------------------------------------------

export class SimulationMetricsCollector {
  private readonly db: Database.Database;
  private readonly log = logger.child({ component: 'simulation-metrics' });

  // Prepared statements for querying audit_log and approval_queue
  private readonly stmtAuditCountByType: Database.Statement;
  private readonly stmtAuditSimulationDetails: Database.Statement;
  private readonly stmtApprovalLatencies: Database.Statement;
  private readonly stmtApprovalExecutedCount: Database.Statement;

  // In-memory buffers for events recorded through the public API
  private readonly simulationEvents: SimulationEvent[] = [];
  private readonly approvalEvents: ApprovalEvent[] = [];

  constructor(db: Database.Database) {
    this.db = db;

    // Count audit_log entries by event_type within a period
    this.stmtAuditCountByType = db.prepare(`
      SELECT event_type, COUNT(*) as count
      FROM audit_log
      WHERE timestamp >= ? AND timestamp <= ?
        AND event_type IN (
          'simulation_started', 'simulation_completed', 'simulation_failed',
          'approval_granted', 'approval_denied', 'approval_expired',
          'approval_queue_executed'
        )
      GROUP BY event_type
    `);

    // Fetch simulation_completed details within a period for risk/confidence extraction
    this.stmtAuditSimulationDetails = db.prepare(`
      SELECT id, timestamp, execution_id, event_type, details
      FROM audit_log
      WHERE timestamp >= ? AND timestamp <= ?
        AND event_type = 'simulation_completed'
      ORDER BY timestamp ASC
    `);

    // Fetch approval latencies (approved entries) within a period
    this.stmtApprovalLatencies = db.prepare(`
      SELECT request_id, requested_at, approved_at, status
      FROM approval_queue
      WHERE requested_at >= ? AND requested_at <= ?
        AND status = 'approved'
        AND approved_at IS NOT NULL
    `);

    // Count approval queue entries that were executed within a period
    // (tracked via audit_log event_type = 'approval_queue_executed')
    this.stmtApprovalExecutedCount = db.prepare(`
      SELECT COUNT(*) as count
      FROM audit_log
      WHERE timestamp >= ? AND timestamp <= ?
        AND event_type = 'approval_queue_executed'
    `);

    this.log.debug('SimulationMetricsCollector initialized');
  }

  // -----------------------------------------------------------------------
  // Public API -- Recording Events
  // -----------------------------------------------------------------------

  /**
   * Record a completed simulation.
   *
   * Extracts risk score, confidence, and action distribution from the
   * simulation report and stores them in the in-memory buffer.
   *
   * @param report - The completed simulation report.
   */
  recordSimulation(report: SimulationReport): void {
    const actionDistribution: Record<string, number> = {};

    for (const step of report.steps) {
      const action = step.action;
      actionDistribution[action] = (actionDistribution[action] ?? 0) + 1;
    }

    const event: SimulationEvent = {
      simulation_id: report.simulation_id,
      timestamp: report.timestamp,
      risk_score: report.overall_risk_score,
      confidence: report.overall_confidence,
      action_distribution: actionDistribution,
    };

    this.simulationEvents.push(event);

    this.log.debug('Recorded simulation event', {
      simulation_id: report.simulation_id,
      risk_score: report.overall_risk_score,
      confidence: report.overall_confidence,
      step_count: report.steps.length,
    });
  }

  /**
   * Record an approval event.
   *
   * @param requestId  - The approval request identifier.
   * @param latencyMs  - Time in milliseconds from request to approval.
   */
  recordApproval(requestId: string, latencyMs: number): void {
    this.approvalEvents.push({
      request_id: requestId,
      timestamp: new Date().toISOString(),
      type: 'approval',
      latency_ms: latencyMs,
    });

    this.log.debug('Recorded approval event', {
      request_id: requestId,
      latency_ms: latencyMs,
    });
  }

  /**
   * Record a denial event.
   *
   * @param requestId - The approval request identifier.
   */
  recordDenial(requestId: string): void {
    this.approvalEvents.push({
      request_id: requestId,
      timestamp: new Date().toISOString(),
      type: 'denial',
    });

    this.log.debug('Recorded denial event', { request_id: requestId });
  }

  /**
   * Record an expiration event.
   *
   * @param requestId - The approval request identifier.
   */
  recordExpiration(requestId: string): void {
    this.approvalEvents.push({
      request_id: requestId,
      timestamp: new Date().toISOString(),
      type: 'expiration',
    });

    this.log.debug('Recorded expiration event', { request_id: requestId });
  }

  /**
   * Record an execution from queue event.
   *
   * @param requestId - The approval request identifier.
   */
  recordExecution(requestId: string): void {
    this.approvalEvents.push({
      request_id: requestId,
      timestamp: new Date().toISOString(),
      type: 'execution',
    });

    this.log.debug('Recorded execution-from-queue event', {
      request_id: requestId,
    });
  }

  // -----------------------------------------------------------------------
  // Public API -- Querying Metrics
  // -----------------------------------------------------------------------

  /**
   * Aggregate metrics for a given time period.
   *
   * Combines data from the SQLite audit_log and approval_queue tables
   * with any in-memory events recorded through the public API.
   *
   * @param periodStart - ISO8601 timestamp for the period start (inclusive).
   * @param periodEnd   - ISO8601 timestamp for the period end (inclusive).
   * @returns A fully populated {@link SimulationMetricsRecord}.
   */
  getMetrics(periodStart: string, periodEnd: string): SimulationMetricsRecord {
    // -- 1. Audit log counts by event type ----------------------------------
    const auditCounts = this.stmtAuditCountByType.all(
      periodStart,
      periodEnd,
    ) as AuditCountRow[];

    const auditCountMap = new Map<string, number>();
    for (const row of auditCounts) {
      auditCountMap.set(row.event_type, row.count);
    }

    // -- 2. In-memory simulation events in period ---------------------------
    const inPeriodSimulations = this.simulationEvents.filter(
      (e) => e.timestamp >= periodStart && e.timestamp <= periodEnd,
    );

    // -- 3. In-memory approval events in period -----------------------------
    const inPeriodApprovals = this.approvalEvents.filter(
      (e) => e.timestamp >= periodStart && e.timestamp <= periodEnd,
    );

    // -- 4. Total simulations -----------------------------------------------
    const dbSimulations =
      (auditCountMap.get('simulation_completed') ?? 0) +
      (auditCountMap.get('simulation_failed') ?? 0);
    const memSimulations = inPeriodSimulations.length;
    const totalSimulations = dbSimulations + memSimulations;

    // -- 5. Approval counts -------------------------------------------------
    const dbApprovals = auditCountMap.get('approval_granted') ?? 0;
    const dbDenials = auditCountMap.get('approval_denied') ?? 0;
    const dbExpirations = auditCountMap.get('approval_expired') ?? 0;
    const dbExecutions = (
      this.stmtApprovalExecutedCount.get(periodStart, periodEnd) as {
        count: number;
      }
    ).count;

    const memApprovals = inPeriodApprovals.filter(
      (e) => e.type === 'approval',
    ).length;
    const memDenials = inPeriodApprovals.filter(
      (e) => e.type === 'denial',
    ).length;
    const memExpirations = inPeriodApprovals.filter(
      (e) => e.type === 'expiration',
    ).length;
    const memExecutions = inPeriodApprovals.filter(
      (e) => e.type === 'execution',
    ).length;

    const totalApprovals = dbApprovals + memApprovals;
    const totalDenials = dbDenials + memDenials;
    const totalExpirations = dbExpirations + memExpirations;
    const totalExecutionsFromQueue = dbExecutions + memExecutions;

    // -- 6. Approval rate ---------------------------------------------------
    const totalDecisions = totalApprovals + totalDenials + totalExpirations;
    const approvalRate =
      totalDecisions > 0 ? totalApprovals / totalDecisions : 0;

    // -- 7. Average approval latency ----------------------------------------
    const dbLatencyRows = this.stmtApprovalLatencies.all(
      periodStart,
      periodEnd,
    ) as ApprovalLatencyRow[];

    let totalLatencyMs = 0;
    let latencyCount = 0;

    for (const row of dbLatencyRows) {
      if (row.approved_at) {
        const requested = new Date(row.requested_at).getTime();
        const approved = new Date(row.approved_at).getTime();
        const latency = approved - requested;
        if (latency >= 0) {
          totalLatencyMs += latency;
          latencyCount++;
        }
      }
    }

    for (const event of inPeriodApprovals) {
      if (event.type === 'approval' && event.latency_ms !== undefined) {
        totalLatencyMs += event.latency_ms;
        latencyCount++;
      }
    }

    const avgApprovalLatencyMs =
      latencyCount > 0 ? totalLatencyMs / latencyCount : 0;

    // -- 8. Action distribution ---------------------------------------------
    const actionDistribution: Record<string, number> = {};

    // From audit_log simulation_completed details
    const detailRows = this.stmtAuditSimulationDetails.all(
      periodStart,
      periodEnd,
    ) as AuditDetailRow[];

    for (const row of detailRows) {
      const details = safeJsonParse(row.details);
      const actions = details?.['action_distribution'] as
        | Record<string, number>
        | undefined;
      if (actions) {
        for (const [action, count] of Object.entries(actions)) {
          actionDistribution[action] =
            (actionDistribution[action] ?? 0) + (count as number);
        }
      }
    }

    // From in-memory simulation events
    for (const event of inPeriodSimulations) {
      for (const [action, count] of Object.entries(
        event.action_distribution,
      )) {
        actionDistribution[action] =
          (actionDistribution[action] ?? 0) + count;
      }
    }

    // -- 9. Average risk score and confidence --------------------------------
    let totalRiskScore = 0;
    let totalConfidence = 0;
    let scoreCount = 0;

    // From audit_log simulation_completed details
    for (const row of detailRows) {
      const details = safeJsonParse(row.details);
      const riskScore = details?.['risk_score'] as number | undefined;
      const confidence = details?.['confidence'] as number | undefined;

      if (riskScore !== undefined && confidence !== undefined) {
        totalRiskScore += riskScore;
        totalConfidence += confidence;
        scoreCount++;
      }
    }

    // From in-memory simulation events
    for (const event of inPeriodSimulations) {
      totalRiskScore += event.risk_score;
      totalConfidence += event.confidence;
      scoreCount++;
    }

    const avgRiskScore = scoreCount > 0 ? totalRiskScore / scoreCount : 0;
    const avgConfidence = scoreCount > 0 ? totalConfidence / scoreCount : 0;

    // -- 10. Build record ---------------------------------------------------
    const record: SimulationMetricsRecord = {
      id: randomUUID(),
      period_start: periodStart,
      period_end: periodEnd,
      total_simulations: totalSimulations,
      total_approvals: totalApprovals,
      total_denials: totalDenials,
      total_expirations: totalExpirations,
      total_executions_from_queue: totalExecutionsFromQueue,
      approval_rate: clamp(approvalRate, 0, 1),
      avg_approval_latency_ms: Math.round(avgApprovalLatencyMs),
      action_distribution: actionDistribution,
      avg_risk_score: round2(avgRiskScore),
      avg_confidence: clamp(round2(avgConfidence), 0, 1),
    };

    this.log.debug('Computed simulation metrics', {
      period_start: periodStart,
      period_end: periodEnd,
      total_simulations: totalSimulations,
      total_approvals: totalApprovals,
      total_denials: totalDenials,
    });

    return record;
  }

  /**
   * Get the most recent period's metrics.
   *
   * Looks at the latest simulation_completed event in the audit_log to
   * determine the most recent period, then aggregates the full 24-hour
   * window ending at that event's timestamp.
   *
   * @returns The metrics record for the most recent period, or `undefined`
   *          if no simulation data exists.
   */
  getLatestMetrics(): SimulationMetricsRecord | undefined {
    // Find the latest simulation event timestamp from both DB and memory
    const latestDbRow = this.db
      .prepare(
        `SELECT MAX(timestamp) as latest
         FROM audit_log
         WHERE event_type IN ('simulation_completed', 'simulation_failed')`,
      )
      .get() as { latest: string | null } | undefined;

    const latestDbTimestamp = latestDbRow?.latest ?? null;

    const latestMemTimestamp =
      this.simulationEvents.length > 0
        ? this.simulationEvents[this.simulationEvents.length - 1]!.timestamp
        : null;

    // Determine the most recent timestamp
    let latestTimestamp: string | null = null;

    if (latestDbTimestamp && latestMemTimestamp) {
      latestTimestamp =
        latestDbTimestamp > latestMemTimestamp
          ? latestDbTimestamp
          : latestMemTimestamp;
    } else {
      latestTimestamp = latestDbTimestamp ?? latestMemTimestamp;
    }

    if (!latestTimestamp) {
      this.log.debug('No simulation data found for latest metrics');
      return undefined;
    }

    // Use a 24-hour window ending at the latest timestamp
    const endDate = new Date(latestTimestamp);
    const startDate = new Date(endDate.getTime() - 24 * 60 * 60 * 1000);

    return this.getMetrics(startDate.toISOString(), endDate.toISOString());
  }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Safely parse a JSON string, returning null on failure.
 */
function safeJsonParse(json: string): Record<string, unknown> | null {
  try {
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Clamp a number to the range [min, max].
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/**
 * Round a number to two decimal places.
 */
function round2(value: number): number {
  return Math.round(value * 100) / 100;
}
