/**
 * S1-014: Engine Integration Tests
 *
 * End-to-end tests that exercise the full orchestration pipeline:
 * orchestrator → state machine → executor → adapter → rollback
 *
 * Uses mock adapters to simulate real adapter behavior.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type {
  Runbook,
  StepAction,
  ExecutionMode,
  AdapterResult,
} from '../../src/types/playbook.ts';
import type { StepAdapter, AdapterResolver } from '../../src/engine/step-executor.ts';
import { executeRunbook } from '../../src/engine/orchestrator.ts';
import { ExecutionStateMachine } from '../../src/engine/state-machine.ts';
import { executeL0 } from '../../src/engine/executors/l0-executor.ts';
import { executeL1 } from '../../src/engine/executors/l1-executor.ts';
import { executeRollback } from '../../src/engine/rollback.ts';
import { classifyAction, isReadOnly } from '../../src/engine/action-classifier.ts';
import { resolveTemplateString } from '../../src/engine/templating.ts';

// ---------------------------------------------------------------------------
// Mock Adapter Factory
// ---------------------------------------------------------------------------

function createMockAdapter(
  name: string,
  behavior: Record<string, (params: Record<string, unknown>, mode: ExecutionMode) => AdapterResult> = {},
): StepAdapter {
  return {
    name,
    execute: async (
      action: StepAction,
      params: Record<string, unknown>,
      mode: ExecutionMode,
    ): Promise<AdapterResult> => {
      if (behavior[action]) {
        return behavior[action](params, mode);
      }
      // Default: succeed with echo output
      return {
        success: true,
        action,
        executor: name,
        duration_ms: 5,
        output: { action, params, mode },
      };
    },
  };
}

function createFailingAdapter(name: string, failAction?: string): StepAdapter {
  return {
    name,
    execute: async (
      action: StepAction,
      _params: Record<string, unknown>,
      _mode: ExecutionMode,
    ): Promise<AdapterResult> => {
      if (!failAction || action === failAction) {
        return {
          success: false,
          action,
          executor: name,
          duration_ms: 1,
          error: {
            code: 'ADAPTER_ERROR',
            message: `Simulated failure for ${action}`,
            adapter: name,
            action,
            retryable: false,
          },
        };
      }
      return {
        success: true,
        action,
        executor: name,
        duration_ms: 5,
        output: { action },
      };
    },
  };
}

// Slow adapter factory — available for timeout tests
// function createSlowAdapter(name: string, delayMs: number): StepAdapter { ... }

// ---------------------------------------------------------------------------
// Test Runbook Factories
// ---------------------------------------------------------------------------

function makeRunbook(overrides: Partial<Runbook> = {}): Runbook {
  return {
    id: 'test-runbook-001',
    version: '1.0.0',
    metadata: {
      name: 'Test Runbook',
      description: 'Integration test runbook',
      author: 'test',
      created: '2026-01-01T00:00:00Z',
      updated: '2026-01-01T00:00:00Z',
      tags: ['test'],
    },
    triggers: {
      detection_sources: ['manual'],
      mitre_techniques: ['T1059'],
      platforms: ['linux'],
    },
    config: {
      automation_level: 'L1',
      max_execution_time: 300,
      requires_approval: false,
      rollback_on_failure: true,
    },
    steps: [
      {
        id: 'step-01',
        name: 'Collect Logs',
        action: 'collect_logs',
        executor: 'siem',
        parameters: { query: 'host.name: test-host', timerange: '1h' },
        on_error: 'halt',
        timeout: 30,
      },
      {
        id: 'step-02',
        name: 'Enrich IOC',
        action: 'enrich_ioc',
        executor: 'threat-intel',
        parameters: { ioc: '{{ alert.source.ip }}', type: 'ip' },
        depends_on: ['step-01'],
        on_error: 'continue',
        timeout: 30,
      },
      {
        id: 'step-03',
        name: 'Block IP',
        action: 'block_ip',
        executor: 'firewall',
        parameters: { ip: '{{ alert.source.ip }}', direction: 'inbound' },
        depends_on: ['step-02'],
        on_error: 'halt',
        timeout: 30,
        approval_required: true,
        rollback: {
          action: 'unblock_ip',
          parameters: { ip: '{{ alert.source.ip }}' },
          timeout: 30,
        },
      },
    ],
    ...overrides,
  };
}

function makeAdapterResolver(adapters: Record<string, StepAdapter>): AdapterResolver {
  return (name: string) => adapters[name];
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

describe('Engine Integration Tests', () => {
  let adapters: Record<string, StepAdapter>;
  let resolveAdapter: AdapterResolver;

  beforeEach(() => {
    adapters = {
      siem: createMockAdapter('siem', {
        collect_logs: () => ({
          success: true,
          action: 'collect_logs',
          executor: 'siem',
          duration_ms: 10,
          output: { total_hits: 42, events: [{ host: 'test-host', message: 'suspicious activity' }] },
        }),
        query_siem: () => ({
          success: true,
          action: 'query_siem',
          executor: 'siem',
          duration_ms: 8,
          output: { results: [] },
        }),
      }),
      'threat-intel': createMockAdapter('threat-intel', {
        enrich_ioc: (_params) => ({
          success: true,
          action: 'enrich_ioc',
          executor: 'threat-intel',
          duration_ms: 15,
          output: { risk_score: 85, malicious: true, source: 'VirusTotal' },
        }),
      }),
      firewall: createMockAdapter('firewall', {
        block_ip: () => ({
          success: true,
          action: 'block_ip',
          executor: 'firewall',
          duration_ms: 20,
          output: { rule_id: 'fw-001', status: 'active' },
        }),
        unblock_ip: () => ({
          success: true,
          action: 'unblock_ip',
          executor: 'firewall',
          duration_ms: 10,
          output: { rule_id: 'fw-001', status: 'removed' },
        }),
      }),
      edr: createMockAdapter('edr'),
    };
    resolveAdapter = makeAdapterResolver(adapters);
  });

  // -------------------------------------------------------------------------
  // Full Pipeline: Orchestrator
  // -------------------------------------------------------------------------

  describe('Full Pipeline via Orchestrator', () => {
    it('executes L1 runbook end-to-end with all steps succeeding', async () => {
      const runbook = makeRunbook();
      const stateChanges: Array<{ from: string; to: string }> = [];

      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
        requestL1Approval: async () => true,
        alert: { source: { ip: '10.20.30.40' } },
        onStateChange: (_id, from, to) => stateChanges.push({ from, to }),
      });

      expect(result.success).toBe(true);
      expect(result.state).toBe('completed');
      expect(result.steps_executed).toHaveLength(3);
      expect(result.steps_executed.every((s) => s.success)).toBe(true);
      expect(result.metrics.total_steps).toBe(3);
      expect(result.metrics.successful_steps).toBe(3);
      expect(result.metrics.failed_steps).toBe(0);
      expect(result.duration_ms).toBeGreaterThan(0);

      // State machine traversed the expected path
      expect(stateChanges).toEqual([
        { from: 'idle', to: 'validating' },
        { from: 'validating', to: 'planning' },
        { from: 'planning', to: 'executing' },
        { from: 'executing', to: 'completed' },
      ]);
    });

    it('executes L0 runbook as display-only checklist', async () => {
      const runbook = makeRunbook({
        config: {
          automation_level: 'L0',
          max_execution_time: 300,
          requires_approval: false,
        },
      });

      const confirmedSteps: string[] = [];
      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
        confirmL0Step: async (step) => {
          confirmedSteps.push(step.stepId);
          return true;
        },
      });

      expect(result.success).toBe(true);
      expect(result.state).toBe('completed');
      expect(confirmedSteps).toContain('step-01');
    });

    it('returns L2 not-implemented error for v1', async () => {
      const runbook = makeRunbook({
        config: {
          automation_level: 'L2',
          max_execution_time: 300,
          requires_approval: true,
        },
      });

      const result = await executeRunbook(runbook, {
        mode: 'simulation',
        resolveAdapter,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('L2_NOT_IMPLEMENTED');
    });

    it('handles missing adapter gracefully', async () => {
      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Use Missing Adapter',
            action: 'collect_logs',
            executor: 'nonexistent-adapter',
            parameters: {},
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
      });

      expect(result.success).toBe(false);
      expect(result.state).toBe('failed');
    });

    it('triggers rollback when step fails and rollback is enabled', async () => {
      adapters['firewall'] = createFailingAdapter('firewall', 'block_ip');

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Collect Logs',
            action: 'collect_logs',
            executor: 'siem',
            parameters: {},
            on_error: 'continue',
            timeout: 30,
            rollback: {
              action: 'collect_logs',
              parameters: {},
              timeout: 30,
            },
          },
          {
            id: 'step-02',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
        config: {
          automation_level: 'L1',
          max_execution_time: 300,
          requires_approval: false,
          rollback_on_failure: true,
        },
      });

      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
        requestL1Approval: async () => true,
      });

      expect(result.success).toBe(false);
      // Rollback was triggered for step-01 (which succeeded and has rollback def)
      expect(result.metrics.rollbacks_triggered).toBeGreaterThan(0);
    });

    it('does not rollback when rollback_on_failure is false', async () => {
      adapters['firewall'] = createFailingAdapter('firewall', 'block_ip');

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Collect Logs',
            action: 'collect_logs',
            executor: 'siem',
            parameters: {},
            on_error: 'continue',
            timeout: 30,
            rollback: {
              action: 'collect_logs',
              parameters: {},
              timeout: 30,
            },
          },
          {
            id: 'step-02',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
        config: {
          automation_level: 'L1',
          max_execution_time: 300,
          requires_approval: false,
          rollback_on_failure: false,
        },
      });

      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
        requestL1Approval: async () => true,
      });

      expect(result.success).toBe(false);
      expect(result.metrics.rollbacks_triggered).toBe(0);
    });

    it('passes template-resolved alert data through the pipeline', async () => {
      const capturedParams: Record<string, unknown>[] = [];
      adapters['firewall'] = {
        name: 'firewall',
        execute: async (action, params, _mode) => {
          capturedParams.push(params);
          return {
            success: true,
            action,
            executor: 'firewall',
            duration_ms: 5,
            output: { blocked: true },
          };
        },
      };

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: {
              ip: '{{ alert.source.ip }}',
              hostname: '{{ alert.host.name }}',
            },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
        requestL1Approval: async () => true,
        alert: {
          source: { ip: '192.168.1.100' },
          host: { name: 'workstation-42' },
        },
      });

      expect(capturedParams).toHaveLength(1);
      expect(capturedParams[0]).toEqual({
        ip: '192.168.1.100',
        hostname: 'workstation-42',
      });
    });

    it('notifies on step completions via callback', async () => {
      const completedSteps: string[] = [];

      await executeRunbook(makeRunbook(), {
        mode: 'production',
        resolveAdapter,
        requestL1Approval: async () => true,
        alert: { source: { ip: '10.0.0.1' } },
        onStepComplete: (_id, stepResult) => {
          completedSteps.push(stepResult.step_id);
        },
      });

      expect(completedSteps).toEqual(['step-01', 'step-02', 'step-03']);
    });

    it('handles empty runbook with validation failure', async () => {
      const runbook = makeRunbook({ id: '', steps: [] });

      const result = await executeRunbook(runbook, {
        mode: 'production',
        resolveAdapter,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VALIDATION_FAILED');
    });
  });

  // -------------------------------------------------------------------------
  // L1 Executor: Read/Write Classification
  // -------------------------------------------------------------------------

  describe('L1 Read/Write Classification Pipeline', () => {
    it('auto-executes read-only actions without approval', async () => {
      const approvalRequests: string[] = [];

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Query SIEM',
            action: 'query_siem',
            executor: 'siem',
            parameters: { query: 'test' },
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Enrich IOC',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: { ioc: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'test-123' } },
        resolveAdapter,
        requestApproval: async (req) => {
          approvalRequests.push(req.stepId);
          return true;
        },
      });

      expect(result.success).toBe(true);
      expect(result.steps_executed).toHaveLength(2);
      // No approval requested — both are read-only
      expect(approvalRequests).toHaveLength(0);
    });

    it('requests approval for write actions', async () => {
      const approvalRequests: string[] = [];

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'test-456' } },
        resolveAdapter,
        requestApproval: async (req) => {
          approvalRequests.push(req.stepId);
          return true;
        },
      });

      expect(result.success).toBe(true);
      expect(approvalRequests).toEqual(['step-01']);
    });

    it('halts execution when write action is denied', async () => {
      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Create Ticket',
            action: 'create_ticket',
            executor: 'siem',
            parameters: { title: 'test' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'test-789' } },
        resolveAdapter,
        requestApproval: async () => false,
      });

      expect(result.success).toBe(false);
      // Only 1 step attempted — halted after denial
      expect(result.steps_executed).toHaveLength(1);
      expect(result.steps_executed[0]!.error?.code).toBe('APPROVAL_DENIED');
    });

    it('continues after denied write action with on_error=continue', async () => {
      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'continue',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Query SIEM',
            action: 'query_siem',
            executor: 'siem',
            parameters: { query: 'test' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'test' } },
        resolveAdapter,
        requestApproval: async () => false,
      });

      // Both steps executed — first failed (denied), second succeeded
      expect(result.steps_executed).toHaveLength(2);
      expect(result.steps_executed[0]!.success).toBe(false);
      expect(result.steps_executed[1]!.success).toBe(true);
    });

    it('skips write approval when approval_required is false', async () => {
      const approvalRequests: string[] = [];

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Block IP',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            on_error: 'halt',
            timeout: 30,
            approval_required: false,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'test' } },
        resolveAdapter,
        requestApproval: async (req) => {
          approvalRequests.push(req.stepId);
          return true;
        },
      });

      expect(result.success).toBe(true);
      // No approval requested — step-level override
      expect(approvalRequests).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Dependency Chain
  // -------------------------------------------------------------------------

  describe('Step Dependencies', () => {
    it('executes steps in dependency order', async () => {
      const executionOrder: string[] = [];
      const trackingAdapter: StepAdapter = {
        name: 'tracker',
        execute: async (action, params) => {
          executionOrder.push(params['step_id'] as string);
          return {
            success: true,
            action,
            executor: 'tracker',
            duration_ms: 1,
            output: { tracked: true },
          };
        },
      };

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-c',
            name: 'Step C',
            action: 'collect_logs',
            executor: 'tracker',
            parameters: { step_id: 'step-c' },
            depends_on: ['step-a', 'step-b'],
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-a',
            name: 'Step A',
            action: 'collect_logs',
            executor: 'tracker',
            parameters: { step_id: 'step-a' },
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-b',
            name: 'Step B',
            action: 'collect_logs',
            executor: 'tracker',
            parameters: { step_id: 'step-b' },
            depends_on: ['step-a'],
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'dep-test' } },
        resolveAdapter: () => trackingAdapter,
        requestApproval: async () => true,
      });

      expect(result.success).toBe(true);
      // Topological: A first, then B (depends on A), then C (depends on A & B)
      expect(executionOrder).toEqual(['step-a', 'step-b', 'step-c']);
    });

    it('skips steps with unmet dependencies', async () => {
      adapters['siem'] = createFailingAdapter('siem', 'collect_logs');

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Collect Logs (will fail)',
            action: 'collect_logs',
            executor: 'siem',
            parameters: {},
            on_error: 'continue',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Enrich (depends on step-01)',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: { ioc: 'test' },
            depends_on: ['step-01'],
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'dep-fail' } },
        resolveAdapter,
        requestApproval: async () => true,
      });

      expect(result.steps_executed).toHaveLength(2);
      expect(result.steps_executed[0]!.success).toBe(false);
      // Step-02 skipped because step-01 failed (dep not met)
      const step2Output = result.steps_executed[1]!.output as Record<string, unknown>;
      expect(step2Output?.['skipped']).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Condition Guards
  // -------------------------------------------------------------------------

  describe('Condition Guards', () => {
    it('skips steps when condition evaluates to false', async () => {
      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Conditional Step',
            action: 'collect_logs',
            executor: 'siem',
            parameters: {},
            condition: 'false',
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Always Run',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: { ioc: 'test' },
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'cond-test' } },
        resolveAdapter,
        requestApproval: async () => true,
      });

      expect(result.success).toBe(true);
      const step1Output = result.steps_executed[0]!.output as Record<string, unknown>;
      expect(step1Output?.['skipped']).toBe(true);
      expect(result.steps_executed[1]!.success).toBe(true);
    });

    it('evaluates numeric comparison conditions from template', async () => {
      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Enrichment',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: { ioc: 'test' },
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Block if High Risk',
            action: 'block_ip',
            executor: 'firewall',
            parameters: { ip: '1.2.3.4' },
            depends_on: ['step-01'],
            condition: '{{ steps.step-01.output.risk_score }} > 50',
            on_error: 'halt',
            timeout: 30,
            approval_required: false,
          },
        ],
      });

      const result = await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'cond-num' } },
        resolveAdapter,
        requestApproval: async () => true,
      });

      expect(result.success).toBe(true);
      // Step-01 enrichment output has risk_score: 85
      // Step-02 condition "85 > 50" should evaluate to true → step executes
      expect(result.steps_executed[1]!.success).toBe(true);
      const step2Output = result.steps_executed[1]!.output as Record<string, unknown>;
      expect(step2Output?.['skipped']).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Rollback Pipeline
  // -------------------------------------------------------------------------

  describe('Rollback Pipeline', () => {
    it('rolls back completed steps in reverse order', async () => {
      const rollbackOrder: string[] = [];
      const trackingFirewall: StepAdapter = {
        name: 'firewall',
        execute: async (action, _params) => {
          if (action === 'unblock_ip' || action === 'unblock_domain') {
            rollbackOrder.push(action);
          }
          return {
            success: true,
            action,
            executor: 'firewall',
            duration_ms: 5,
            output: { ok: true },
          };
        },
      };

      const completedSteps = [
        {
          step_id: 'step-01',
          step_name: 'Block IP',
          action: 'block_ip' as StepAction,
          success: true,
          started_at: '2026-01-01T00:00:00Z',
          completed_at: '2026-01-01T00:00:01Z',
          duration_ms: 1000,
        },
        {
          step_id: 'step-02',
          step_name: 'Block Domain',
          action: 'block_domain' as StepAction,
          success: true,
          started_at: '2026-01-01T00:00:01Z',
          completed_at: '2026-01-01T00:00:02Z',
          duration_ms: 1000,
        },
      ];

      const allSteps = [
        {
          id: 'step-01',
          name: 'Block IP',
          action: 'block_ip' as StepAction,
          executor: 'firewall',
          parameters: { ip: '1.2.3.4' },
          on_error: 'halt' as const,
          timeout: 30,
          rollback: {
            action: 'unblock_ip' as StepAction,
            parameters: { ip: '1.2.3.4' },
            timeout: 30,
          },
        },
        {
          id: 'step-02',
          name: 'Block Domain',
          action: 'block_domain' as StepAction,
          executor: 'firewall',
          parameters: { domain: 'evil.com' },
          on_error: 'halt' as const,
          timeout: 30,
          rollback: {
            action: 'unblock_domain' as StepAction,
            parameters: { domain: 'evil.com' },
            timeout: 30,
          },
        },
      ];

      const result = await executeRollback(completedSteps, allSteps, {
        mode: 'production',
        templateContext: { steps: {} },
        resolveAdapter: () => trackingFirewall,
      });

      expect(result.success).toBe(true);
      expect(result.totalAttempted).toBe(2);
      expect(result.totalSucceeded).toBe(2);
      // Reversed: step-02 rolled back first, then step-01
      expect(rollbackOrder).toEqual(['unblock_domain', 'unblock_ip']);
    });

    it('continues rollback after individual step rollback failure', async () => {
      const failOnceFirewall: StepAdapter = {
        name: 'firewall',
        execute: async (action) => {
          if (action === 'unblock_domain') {
            return {
              success: false,
              action,
              executor: 'firewall',
              duration_ms: 1,
              error: {
                code: 'ROLLBACK_FAIL',
                message: 'Domain unblock failed',
                adapter: 'firewall',
                action,
                retryable: false,
              },
            };
          }
          return { success: true, action, executor: 'firewall', duration_ms: 5 };
        },
      };

      const completedSteps = [
        {
          step_id: 'step-01',
          step_name: 'Block IP',
          action: 'block_ip' as StepAction,
          success: true,
          started_at: '2026-01-01T00:00:00Z',
          completed_at: '2026-01-01T00:00:01Z',
          duration_ms: 1000,
        },
        {
          step_id: 'step-02',
          step_name: 'Block Domain',
          action: 'block_domain' as StepAction,
          success: true,
          started_at: '2026-01-01T00:00:01Z',
          completed_at: '2026-01-01T00:00:02Z',
          duration_ms: 1000,
        },
      ];

      const allSteps = [
        {
          id: 'step-01',
          name: 'Block IP',
          action: 'block_ip' as StepAction,
          executor: 'firewall',
          parameters: { ip: '1.2.3.4' },
          on_error: 'halt' as const,
          timeout: 30,
          rollback: { action: 'unblock_ip' as StepAction, parameters: { ip: '1.2.3.4' }, timeout: 30 },
        },
        {
          id: 'step-02',
          name: 'Block Domain',
          action: 'block_domain' as StepAction,
          executor: 'firewall',
          parameters: { domain: 'evil.com' },
          on_error: 'halt' as const,
          timeout: 30,
          rollback: { action: 'unblock_domain' as StepAction, parameters: { domain: 'evil.com' }, timeout: 30 },
        },
      ];

      const result = await executeRollback(completedSteps, allSteps, {
        mode: 'production',
        templateContext: { steps: {} },
        resolveAdapter: () => failOnceFirewall,
      });

      // Best-effort: domain rollback failed, but IP rollback still attempted
      expect(result.success).toBe(false);
      expect(result.totalAttempted).toBe(2);
      expect(result.totalSucceeded).toBe(1);
      expect(result.totalFailed).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // State Machine Integration
  // -------------------------------------------------------------------------

  describe('State Machine Integration', () => {
    it('tracks full execution lifecycle', () => {
      const sm = new ExecutionStateMachine('integration-test');
      const history: string[] = [sm.state];

      sm.onStateChange((t) => history.push(t.to));

      sm.transition('trigger'); // → validating
      sm.transition('validation_success'); // → planning
      sm.transition('plan_ready'); // → executing
      sm.transition('all_steps_completed'); // → completed

      expect(history).toEqual(['idle', 'validating', 'planning', 'executing', 'completed']);
      expect(sm.isTerminal).toBe(true);
    });

    it('tracks approval flow', () => {
      const sm = new ExecutionStateMachine('approval-test');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('approval_required');

      expect(sm.state).toBe('awaiting_approval');

      sm.transition('approval_granted');
      expect(sm.state).toBe('executing');
    });

    it('tracks rollback flow', () => {
      const sm = new ExecutionStateMachine('rollback-test');
      sm.transition('trigger');
      sm.transition('validation_success');
      sm.transition('plan_ready');
      sm.startRollback();

      expect(sm.state).toBe('rolling_back');

      sm.transition('rollback_completed');
      expect(sm.state).toBe('completed');
    });

    it('serializes and restores state', () => {
      const sm = new ExecutionStateMachine('serialize-test');
      sm.transition('trigger');
      sm.transition('validation_success');

      const snapshot = sm.serialize();
      expect(snapshot.state).toBe('planning');
      expect(snapshot.executionId).toBe('serialize-test');

      const restored = ExecutionStateMachine.restore(snapshot);
      expect(restored.state).toBe('planning');
      restored.transition('plan_ready');
      expect(restored.state).toBe('executing');
    });
  });

  // -------------------------------------------------------------------------
  // Template Resolution in Pipeline
  // -------------------------------------------------------------------------

  describe('Template Resolution in Pipeline', () => {
    it('resolves step output references across steps', async () => {
      const capturedParams: Record<string, unknown>[] = [];
      const capturingFirewall: StepAdapter = {
        name: 'firewall',
        execute: async (action, params) => {
          capturedParams.push(params);
          return { success: true, action, executor: 'firewall', duration_ms: 5, output: { blocked: true } };
        },
      };

      const runbook = makeRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Enrich IOC',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: { ioc: '10.0.0.1' },
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Block based on enrichment',
            action: 'block_ip',
            executor: 'firewall',
            parameters: {
              ip: '10.0.0.1',
              reason: '{{ steps.step-01.output.source }}',
            },
            depends_on: ['step-01'],
            on_error: 'halt',
            timeout: 30,
            approval_required: false,
          },
        ],
      });

      await executeL1(runbook, {
        mode: 'production',
        templateContext: { steps: {}, context: { execution_id: 'tmpl-test' } },
        resolveAdapter: (name) => {
          if (name === 'threat-intel') return adapters['threat-intel']!;
          return capturingFirewall;
        },
        requestApproval: async () => true,
      });

      expect(capturedParams).toHaveLength(1);
      // step-01 output has source: 'VirusTotal', which should resolve in step-02
      expect(capturedParams[0]!['reason']).toBe('VirusTotal');
    });

    it('handles unresolved templates with defaults', () => {
      const result = resolveTemplateString(
        'Host: {{ alert.host.name | default: unknown }}',
        { alert: {} },
      );
      expect(result.resolved).toBe('Host: unknown');
    });

    it('resolves env variables', () => {
      const result = resolveTemplateString('{{ env.TEST_VAR }}', {
        env: { TEST_VAR: 'hello-world' },
      });
      expect(result.resolved).toBe('hello-world');
    });
  });

  // -------------------------------------------------------------------------
  // Action Classifier Integration
  // -------------------------------------------------------------------------

  describe('Action Classifier Integration', () => {
    it('all read actions are correctly identified', () => {
      const readActions: StepAction[] = [
        'collect_logs', 'query_siem', 'collect_network_traffic', 'snapshot_memory',
        'collect_file_metadata', 'enrich_ioc', 'check_reputation', 'query_threat_feed',
        'retrieve_edr_data', 'calculate_hash', 'http_request', 'wait',
      ];

      for (const action of readActions) {
        expect(isReadOnly(action)).toBe(true);
        expect(classifyAction(action)).toBe('read');
      }
    });

    it('all write actions require L1 approval', () => {
      const writeActions: StepAction[] = [
        'isolate_host', 'restore_connectivity', 'block_ip', 'unblock_ip',
        'block_domain', 'unblock_domain', 'create_ticket', 'update_ticket',
        'notify_analyst', 'notify_oncall', 'send_email', 'disable_account',
        'enable_account', 'reset_password', 'revoke_session', 'quarantine_file',
        'restore_file', 'delete_file', 'kill_process', 'start_edr_scan',
        'execute_script',
      ];

      for (const action of writeActions) {
        expect(isReadOnly(action)).toBe(false);
        expect(classifyAction(action)).toBe('write');
      }
    });
  });

  // -------------------------------------------------------------------------
  // L0 Executor Integration
  // -------------------------------------------------------------------------

  describe('L0 Executor Integration', () => {
    it('generates display plan with resolved parameters', async () => {
      const runbook = makeRunbook({
        config: {
          automation_level: 'L0',
          max_execution_time: 300,
          requires_approval: false,
        },
      });

      const confirmedSteps: string[] = [];
      const result = await executeL0(
        runbook,
        {
          alert: { source: { ip: '10.0.0.1' } },
          steps: {},
          context: { execution_id: 'l0-test', mode: 'production' },
        },
        async (step) => {
          confirmedSteps.push(step.stepId);
          return true;
        },
      );

      expect(result.success).toBe(true);
      expect(confirmedSteps).toContain('step-01');
      expect(confirmedSteps).toContain('step-02');
      expect(confirmedSteps).toContain('step-03');
    });

    it('halts when analyst rejects a halt-on-error step', async () => {
      const runbook = makeRunbook({
        config: {
          automation_level: 'L0',
          max_execution_time: 300,
          requires_approval: false,
        },
        steps: [
          {
            id: 'step-01',
            name: 'First Step',
            action: 'collect_logs',
            executor: 'siem',
            parameters: {},
            on_error: 'halt',
            timeout: 30,
          },
          {
            id: 'step-02',
            name: 'Second Step',
            action: 'enrich_ioc',
            executor: 'threat-intel',
            parameters: {},
            on_error: 'halt',
            timeout: 30,
          },
        ],
      });

      const result = await executeL0(
        runbook,
        { steps: {}, context: { execution_id: 'l0-halt' } },
        async () => false, // Reject all steps
      );

      expect(result.success).toBe(false);
      // Only first step attempted — halted after rejection
      expect(result.steps_executed).toHaveLength(1);
    });
  });
});
