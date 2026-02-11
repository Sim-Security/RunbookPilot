import { describe, it, expect } from 'vitest';
import { executeStep, evaluateCondition } from '../../../src/engine/step-executor.ts';
import type { StepAdapter } from '../../../src/engine/step-executor.ts';
import type { RunbookStep } from '../../../src/types/playbook.ts';
import type { TemplateContext } from '../../../src/engine/templating.ts';

// ---------------------------------------------------------------------------
// Mock Adapters
// ---------------------------------------------------------------------------

const mockAdapter: StepAdapter = {
  name: 'mock',
  execute: async (action, params, _mode) => ({
    success: true,
    action,
    executor: 'mock',
    duration_ms: 1,
    output: { params },
  }),
};

const failingAdapter: StepAdapter = {
  name: 'failing',
  execute: async (action, _params, _mode) => ({
    success: false,
    action,
    executor: 'failing',
    duration_ms: 1,
    error: {
      code: 'ADAPTER_ERROR',
      message: 'Adapter execution failed',
      adapter: 'failing',
      action,
      retryable: false,
    },
  }),
};

const throwingAdapter: StepAdapter = {
  name: 'throwing',
  execute: async () => {
    throw new Error('Unexpected adapter crash');
  },
};

const slowAdapter: StepAdapter = {
  name: 'slow',
  execute: async (action, _params, _mode) => {
    await new Promise((resolve) => setTimeout(resolve, 200));
    return {
      success: true,
      action,
      executor: 'slow',
      duration_ms: 200,
      output: { delayed: true },
    };
  },
};

// ---------------------------------------------------------------------------
// Adapter Resolver
// ---------------------------------------------------------------------------

const resolver = (name: string): StepAdapter | undefined => {
  const adapters: Record<string, StepAdapter> = {
    mock: mockAdapter,
    failing: failingAdapter,
    throwing: throwingAdapter,
    slow: slowAdapter,
  };
  return adapters[name];
};

// ---------------------------------------------------------------------------
// Shared Test Fixtures
// ---------------------------------------------------------------------------

const baseTemplateContext: TemplateContext = {
  alert: {
    host: { hostname: 'workstation-042', ip: ['10.20.30.40'] },
    event: { severity: 85 },
  },
  steps: {
    'step-00': { output: { score: 92 } },
  },
  context: {
    analyst_email: 'analyst@example.com',
  },
};

function makeStep(overrides: Partial<RunbookStep> = {}): RunbookStep {
  return {
    id: 'step-01',
    name: 'Test Step',
    action: 'collect_logs' as const,
    executor: 'mock',
    parameters: { query: 'test' },
    on_error: 'halt' as const,
    timeout: 30,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests: executeStep
// ---------------------------------------------------------------------------

describe('executeStep', () => {
  it('successful execution returns success result', async () => {
    const step = makeStep();
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(true);
    expect(result.stepResult.step_id).toBe('step-01');
    expect(result.stepResult.step_name).toBe('Test Step');
    expect(result.stepResult.action).toBe('collect_logs');
    expect(result.stepResult.error).toBeUndefined();
    expect(result.stepResult.output).toEqual({ params: { query: 'test' } });
    expect(result.stepResult.duration_ms).toBeGreaterThanOrEqual(0);
    expect(result.stepResult.started_at).toBeTruthy();
    expect(result.stepResult.completed_at).toBeTruthy();
    expect(result.shouldContinue).toBe(true);
  });

  it('missing adapter returns ADAPTER_NOT_FOUND error', async () => {
    const step = makeStep({ executor: 'nonexistent' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.stepResult.error).toBeDefined();
    expect(result.stepResult.error!.code).toBe('ADAPTER_NOT_FOUND');
    expect(result.stepResult.error!.message).toContain('nonexistent');
    expect(result.stepResult.error!.step_id).toBe('step-01');
  });

  it('adapter failure returns STEP_EXECUTION_FAILED', async () => {
    const step = makeStep({ executor: 'failing' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.stepResult.error).toBeDefined();
    expect(result.stepResult.error!.code).toBe('STEP_EXECUTION_FAILED');
    expect(result.stepResult.error!.step_id).toBe('step-01');
  });

  it('adapter throwing returns STEP_EXECUTION_ERROR', async () => {
    const step = makeStep({ executor: 'throwing' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.stepResult.error).toBeDefined();
    expect(result.stepResult.error!.code).toBe('STEP_EXECUTION_ERROR');
    expect(result.stepResult.error!.message).toBe('Unexpected adapter crash');
    expect(result.stepResult.error!.step_id).toBe('step-01');
  });

  it('step timeout returns STEP_TIMEOUT', async () => {
    const step = makeStep({ executor: 'slow', timeout: 0.05 }); // 50ms timeout
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.stepResult.error).toBeDefined();
    expect(result.stepResult.error!.code).toBe('STEP_TIMEOUT');
    expect(result.stepResult.error!.message).toContain('timed out');
    expect(result.stepResult.error!.step_id).toBe('step-01');
  });

  it('on_error: halt sets shouldContinue to false on failure', async () => {
    const step = makeStep({ executor: 'failing', on_error: 'halt' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.shouldContinue).toBe(false);
  });

  it('on_error: continue sets shouldContinue to true on failure', async () => {
    const step = makeStep({ executor: 'failing', on_error: 'continue' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.shouldContinue).toBe(true);
  });

  it('on_error: skip sets shouldContinue to true on failure', async () => {
    const step = makeStep({ executor: 'failing', on_error: 'skip' });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.stepResult.success).toBe(false);
    expect(result.shouldContinue).toBe(true);
  });

  it('hasRollback is true when step has rollback definition', async () => {
    const step = makeStep({
      rollback: {
        action: 'restore_connectivity',
        parameters: { host: 'workstation-042' },
        timeout: 30,
      },
    });
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.hasRollback).toBe(true);
  });

  it('hasRollback is false when step has no rollback definition', async () => {
    const step = makeStep();
    const result = await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: resolver,
    });

    expect(result.hasRollback).toBe(false);
  });

  it('template parameters are resolved before passing to adapter', async () => {
    const step = makeStep({
      parameters: {
        host: '{{ alert.host.hostname }}',
        severity: '{{ alert.event.severity }}',
      },
    });

    let capturedParams: Record<string, unknown> | undefined;
    const capturingAdapter: StepAdapter = {
      name: 'capturing',
      execute: async (action, params, _mode) => {
        capturedParams = params;
        return {
          success: true,
          action,
          executor: 'capturing',
          duration_ms: 1,
          output: {},
        };
      },
    };

    await executeStep(step, {
      mode: 'production',
      templateContext: baseTemplateContext,
      resolveAdapter: (name) => (name === 'mock' ? capturingAdapter : undefined),
    });

    expect(capturedParams).toBeDefined();
    expect(capturedParams!.host).toBe('workstation-042');
    expect(capturedParams!.severity).toBe(85);
  });
});

// ---------------------------------------------------------------------------
// Tests: evaluateCondition
// ---------------------------------------------------------------------------

describe('evaluateCondition', () => {
  it('undefined condition returns true', () => {
    expect(evaluateCondition(undefined, baseTemplateContext)).toBe(true);
  });

  it('"true" returns true', () => {
    expect(evaluateCondition('true', baseTemplateContext)).toBe(true);
  });

  it('"false" returns false', () => {
    expect(evaluateCondition('false', baseTemplateContext)).toBe(false);
  });

  it('"85 > 50" returns true', () => {
    expect(evaluateCondition('85 > 50', baseTemplateContext)).toBe(true);
  });

  it('"30 > 50" returns false', () => {
    expect(evaluateCondition('30 > 50', baseTemplateContext)).toBe(false);
  });

  it('"10 >= 10" returns true', () => {
    expect(evaluateCondition('10 >= 10', baseTemplateContext)).toBe(true);
  });

  it('"5 <= 3" returns false', () => {
    expect(evaluateCondition('5 <= 3', baseTemplateContext)).toBe(false);
  });

  it('"10 == 10" returns true', () => {
    expect(evaluateCondition('10 == 10', baseTemplateContext)).toBe(true);
  });

  it('"10 != 5" returns true', () => {
    expect(evaluateCondition('10 != 5', baseTemplateContext)).toBe(true);
  });

  it('non-empty string returns true', () => {
    expect(evaluateCondition('some_truthy_value', baseTemplateContext)).toBe(true);
  });

  it('template-resolved condition evaluates correctly', () => {
    // alert.event.severity = 85, so "85 > 50" should be true
    expect(
      evaluateCondition('{{ alert.event.severity }} > 50', baseTemplateContext),
    ).toBe(true);
  });
});
