/**
 * L2 Executor -- Simulation Mode
 *
 * Simulates write actions without executing them against real systems,
 * while executing read-only actions normally (adapters return real results
 * in simulation mode). Each write step receives an impact assessment and
 * confidence score. All results are collected into a {@link SimulationReport}
 * that includes a rollback plan and overall risk assessment.
 *
 * Key behaviours:
 * - Read actions: executed via adapter in simulation mode (real query results).
 * - Write actions: adapter called in simulation mode (no system changes).
 * - Impact and confidence scored per write step.
 * - Rollback plan generated from step rollback definitions.
 * - NO actual system changes occur for write actions.
 *
 * @module engine/executors/l2-executor
 */

import { randomUUID } from 'crypto';

import type {
  Runbook,
  RunbookStep,
  StepResult,
  ExecutionMode,
} from '../../types/playbook.ts';
import type {
  SimulatedStep,
  SimulationReport,
  RollbackPlan,
  RollbackStep,
  ImpactAssessment,
  ConfidenceBreakdown,
} from '../../types/simulation.ts';
import type { TemplateContext } from '../templating.ts';
import type { AdapterResolver } from '../step-executor.ts';
import { executeStep, evaluateCondition } from '../step-executor.ts';
import { isWriteAction } from '../action-classifier.ts';
import {
  assessStepImpact,
  calculateOverallRisk,
} from '../impact-assessor.ts';
import {
  calculateStepConfidence,
  calculateOverallConfidence,
  extractDetectForgeConfidence,
  extractDetectForgeRuleId,
} from '../confidence-scorer.ts';
import type { AlertEvent } from '../../types/ecs.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface L2ExecutorOptions {
  mode: ExecutionMode; // should be 'simulation'
  templateContext: TemplateContext;
  resolveAdapter: AdapterResolver;
  alert?: AlertEvent;
  enableL2: boolean;
}

// ---------------------------------------------------------------------------
// L2 Executor
// ---------------------------------------------------------------------------

/**
 * Execute an L2 simulation of the given runbook.
 *
 * Read-only steps are executed normally (adapter returns real query data in
 * simulation mode). Write steps are sent to the adapter in simulation mode
 * so that no real changes are made. Each write step is scored for impact and
 * confidence. The result is a comprehensive {@link SimulationReport}.
 *
 * @throws Error if `options.enableL2` is false.
 */
export async function executeL2(
  runbook: Runbook,
  options: L2ExecutorOptions,
): Promise<SimulationReport> {
  // 1. Gate check
  if (!options.enableL2) {
    throw new Error('L2 simulation mode requires --enable-l2 flag');
  }

  // 2. Identifiers
  const simulationId = randomUUID();
  const executionId =
    (options.templateContext.context?.['execution_id'] as string) ?? randomUUID();

  // 3. DetectForge metadata (if alert is provided)
  const detectforgeConfidence = options.alert
    ? extractDetectForgeConfidence(options.alert)
    : undefined;
  const detectforgeRuleId = options.alert
    ? extractDetectForgeRuleId(options.alert)
    : undefined;

  // 4. Resolve execution order
  const executionOrder = resolveExecutionOrder(runbook.steps);

  // 5. Walk steps
  const simulatedSteps: SimulatedStep[] = [];
  const completedSteps = new Set<string>();

  for (const step of executionOrder) {
    // --- Dependency check ---------------------------------------------------
    const depsReady = (step.depends_on ?? []).every((dep) =>
      completedSteps.has(dep),
    );
    if (!depsReady) {
      const skipped = buildSkippedSimulatedStep(step, 'Dependencies not met');
      simulatedSteps.push(skipped);
      continue;
    }

    // --- Condition guard ----------------------------------------------------
    if (!evaluateCondition(step.condition, options.templateContext)) {
      const skipped = buildSkippedSimulatedStep(step, 'Condition not met');
      simulatedSteps.push(skipped);
      completedSteps.add(step.id);
      continue;
    }

    // --- Execute the step ---------------------------------------------------
    const stepStartTime = Date.now();

    const result = await executeStep(step, {
      mode: 'simulation',
      templateContext: options.templateContext,
      resolveAdapter: options.resolveAdapter,
    });

    const stepDurationMs = Date.now() - stepStartTime;
    const writeAction = isWriteAction(step.action);

    // Impact assessment (write actions only)
    const impact: ImpactAssessment | undefined = writeAction
      ? assessStepImpact(step, step.parameters)
      : undefined;

    // Confidence scoring
    const confidence = calculateStepConfidence({
      parameterValidationPassed: result.stepResult.success,
      adapterHealth: undefined,
      rollbackAvailable: step.rollback !== undefined,
      detectforgeConfidence,
    });

    const simulated = buildSimulatedStep(
      step,
      result.stepResult,
      impact,
      confidence,
      writeAction,
      stepDurationMs,
    );

    simulatedSteps.push(simulated);

    if (result.stepResult.success) {
      completedSteps.add(step.id);

      // Propagate step output into template context
      if (options.templateContext.steps) {
        options.templateContext.steps[step.id] = {
          output: result.stepResult.output,
        };
      }
    }
  }

  // 6. Build report
  return buildSimulationReport({
    simulationId,
    executionId,
    runbook,
    simulatedSteps,
    detectforgeConfidence,
    detectforgeRuleId,
  });
}

// ---------------------------------------------------------------------------
// Execution Order (Topological Sort)
// ---------------------------------------------------------------------------

/**
 * Resolve step execution order using topological sort on `depends_on`.
 * Falls back to declared order if no dependencies exist.
 */
function resolveExecutionOrder(steps: RunbookStep[]): RunbookStep[] {
  const stepMap = new Map(steps.map((s) => [s.id, s]));
  const visited = new Set<string>();
  const result: RunbookStep[] = [];

  function visit(stepId: string): void {
    if (visited.has(stepId)) return;
    visited.add(stepId);

    const step = stepMap.get(stepId);
    if (!step) return;

    for (const dep of step.depends_on ?? []) {
      visit(dep);
    }

    result.push(step);
  }

  for (const step of steps) {
    visit(step.id);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Simulated Step Builders
// ---------------------------------------------------------------------------

/**
 * Build a {@link SimulatedStep} from a step execution result.
 */
function buildSimulatedStep(
  step: RunbookStep,
  result: StepResult,
  impact: ImpactAssessment | undefined,
  confidence: ConfidenceBreakdown,
  isWrite: boolean,
  durationMs: number,
): SimulatedStep {
  const sideEffects: string[] = [];

  if (isWrite && impact) {
    if (impact.blast_radius.hosts_affected > 0) {
      sideEffects.push(
        `Affects ${impact.blast_radius.hosts_affected} host(s)`,
      );
    }
    if (impact.blast_radius.users_affected > 0) {
      sideEffects.push(
        `Affects ${impact.blast_radius.users_affected} user(s)`,
      );
    }
    if (impact.blast_radius.services_affected > 0) {
      sideEffects.push(
        `Affects ${impact.blast_radius.services_affected} service(s)`,
      );
    }
  }

  return {
    step_id: step.id,
    step_name: step.name,
    action: step.action,
    executor: step.executor,
    parameters: step.parameters,
    predicted_result: result.output,
    confidence: confidence.overall,
    side_effects: sideEffects,
    rollback_action: step.rollback?.action,
    rollback_parameters: step.rollback?.parameters,
    validations_passed: result.success,
    validation_errors: result.error ? [result.error.message] : [],
    is_write_action: isWrite,
    duration_ms: durationMs,
    impact,
  };
}

/**
 * Build a skipped {@link SimulatedStep} when dependencies or conditions are
 * not met.
 */
function buildSkippedSimulatedStep(
  step: RunbookStep,
  reason: string,
): SimulatedStep {
  return {
    step_id: step.id,
    step_name: step.name,
    action: step.action,
    executor: step.executor,
    parameters: step.parameters,
    predicted_result: { skipped: true, reason },
    confidence: 0,
    side_effects: [],
    validations_passed: true,
    validation_errors: [],
    is_write_action: isWriteAction(step.action),
    duration_ms: 0,
  };
}

// ---------------------------------------------------------------------------
// Rollback Plan
// ---------------------------------------------------------------------------

/**
 * Build a rollback plan from all write steps that define rollback actions.
 */
function buildRollbackPlan(
  steps: RunbookStep[],
  simulatedSteps: SimulatedStep[],
): RollbackPlan {
  const writeStepIds = new Set(
    simulatedSteps.filter((s) => s.is_write_action).map((s) => s.step_id),
  );

  const rollbackSteps: RollbackStep[] = [];

  // Walk steps in reverse order so rollbacks undo the most recent change first
  for (let i = steps.length - 1; i >= 0; i--) {
    const step = steps[i]!;
    if (!writeStepIds.has(step.id)) continue;
    if (!step.rollback) continue;

    rollbackSteps.push({
      step_id: step.id,
      original_action: step.action,
      rollback_action: step.rollback.action,
      executor: step.rollback.executor ?? step.executor,
      parameters: step.rollback.parameters,
      timeout: step.rollback.timeout,
    });
  }

  const estimatedDuration = rollbackSteps.reduce(
    (sum, rs) => sum + rs.timeout * 1000,
    0,
  );

  return {
    available: rollbackSteps.length > 0,
    steps: rollbackSteps,
    estimated_duration_ms: estimatedDuration,
  };
}

// ---------------------------------------------------------------------------
// Predicted Outcome
// ---------------------------------------------------------------------------

/**
 * Calculate the predicted outcome based on simulated step results.
 *
 * - `SUCCESS`: all steps passed validation.
 * - `PARTIAL`: some steps failed but at least one write step succeeded.
 * - `FAILURE`: all write steps failed (or no steps succeeded).
 */
function calculatePredictedOutcome(
  simulatedSteps: SimulatedStep[],
): 'SUCCESS' | 'PARTIAL' | 'FAILURE' {
  const nonSkipped = simulatedSteps.filter(
    (s) => (s.predicted_result as Record<string, unknown> | undefined)?.['skipped'] !== true,
  );

  if (nonSkipped.length === 0) return 'SUCCESS';

  const allPassed = nonSkipped.every((s) => s.validations_passed);
  if (allPassed) return 'SUCCESS';

  const writeSteps = nonSkipped.filter((s) => s.is_write_action);
  if (writeSteps.length > 0 && writeSteps.every((s) => !s.validations_passed)) {
    return 'FAILURE';
  }

  return 'PARTIAL';
}

// ---------------------------------------------------------------------------
// Simulation Report
// ---------------------------------------------------------------------------

interface BuildReportOptions {
  simulationId: string;
  executionId: string;
  runbook: Runbook;
  simulatedSteps: SimulatedStep[];
  detectforgeConfidence?: number;
  detectforgeRuleId?: string;
}

/**
 * Assemble the final {@link SimulationReport}.
 */
function buildSimulationReport(opts: BuildReportOptions): SimulationReport {
  const {
    simulationId,
    executionId,
    runbook,
    simulatedSteps,
    detectforgeConfidence,
    detectforgeRuleId,
  } = opts;

  // Overall confidence from all step confidence scores
  // Build ConfidenceBreakdown objects from per-step confidence numbers
  const confidenceBreakdowns: ConfidenceBreakdown[] = simulatedSteps.map((s) => ({
    parameter_validation: s.validations_passed ? 1.0 : 0.0,
    adapter_health: 1.0,
    rollback_available: s.rollback_action ? 1.0 : 0.0,
    overall: s.confidence,
  }));
  const overallConfidence = calculateOverallConfidence(confidenceBreakdowns);

  // Overall risk from impact assessments of write steps
  const impacts = simulatedSteps
    .filter((s) => s.impact !== undefined)
    .map((s) => s.impact!);
  const overallRisk = calculateOverallRisk(impacts);

  // Collect all unique affected assets
  const affectedAssets = [
    ...new Set(
      impacts.flatMap((imp) => imp.blast_radius.affected_assets),
    ),
  ];

  // Collect risk descriptions
  const risksIdentified = impacts
    .filter((imp) => imp.risk_level === 'high' || imp.risk_level === 'critical')
    .map((imp) => imp.summary);

  // Build rollback plan
  const rollbackPlan = buildRollbackPlan(runbook.steps, simulatedSteps);

  // Predicted outcome
  const predictedOutcome = calculatePredictedOutcome(simulatedSteps);

  // Estimated total duration
  const estimatedDuration = simulatedSteps.reduce(
    (sum, s) => sum + s.duration_ms,
    0,
  );

  return {
    simulation_id: simulationId,
    execution_id: executionId,
    runbook_id: runbook.id,
    runbook_name: runbook.metadata.name,
    timestamp: new Date().toISOString(),
    steps: simulatedSteps,
    predicted_outcome: predictedOutcome,
    overall_confidence: overallConfidence,
    overall_risk_score: overallRisk.score,
    overall_risk_level: overallRisk.level,
    estimated_duration_ms: estimatedDuration,
    risks_identified: risksIdentified,
    affected_assets: affectedAssets,
    rollback_plan: rollbackPlan,
    detectforge_confidence: detectforgeConfidence,
    detectforge_rule_id: detectforgeRuleId,
  };
}
