/**
 * Unit tests for NotificationAdapter
 *
 * Tests Slack webhook notifications, email delivery (v1 placeholder),
 * and all execution modes (production, simulation, dry-run).
 * All fetch calls are mocked via globalThis.fetch.
 *
 * @module tests/unit/adapters/notification-adapter
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { NotificationAdapter } from '../../../src/adapters/notification/notification-adapter.ts';
import type { AdapterConfig } from '../../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof globalThis.fetch>();

beforeEach(() => {
  globalThis.fetch = mockFetch;
  mockFetch.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides?: Partial<AdapterConfig>): AdapterConfig {
  return {
    name: 'notification-adapter',
    type: 'notification',
    enabled: true,
    config: {
      slack_webhook_url: 'https://hooks.slack.com/services/T00/B00/xxxx',
      smtp_host: 'smtp.example.com',
      smtp_port: 587,
      smtp_user: 'alerts@example.com',
    },
    timeout: 30,
    ...overrides,
  };
}

function makeSlackOnlyConfig(): AdapterConfig {
  return {
    name: 'notification-adapter',
    type: 'notification',
    enabled: true,
    config: {
      slack_webhook_url: 'https://hooks.slack.com/services/T00/B00/xxxx',
    },
    timeout: 30,
  };
}

function makeMinimalConfig(): AdapterConfig {
  return {
    name: 'notification-adapter',
    type: 'notification',
    enabled: true,
    config: {},
  };
}

async function initAdapter(config?: AdapterConfig): Promise<NotificationAdapter> {
  const adapter = new NotificationAdapter();
  await adapter.initialize(config ?? makeConfig());
  return adapter;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NotificationAdapter', () => {
  // ---- Initialization ----------------------------------------------------

  describe('initialize()', () => {
    it('stores config values after initialization', async () => {
      const adapter = new NotificationAdapter();
      const config = makeConfig();
      await adapter.initialize(config);

      // Prove config is stored by checking healthCheck uses the webhook URL
      mockFetch.mockResolvedValueOnce(
        new Response('', { status: 200 }),
      );
      const health = await adapter.healthCheck();
      expect(health.status).toBe('healthy');
      expect(health.message).toContain('Slack webhook reachable');
    });

    it('sets name and version correctly', () => {
      const adapter = new NotificationAdapter();
      expect(adapter.name).toBe('notification-adapter');
      expect(adapter.version).toBe('1.0.0');
    });

    it('defines all supported actions', () => {
      const adapter = new NotificationAdapter();
      expect(adapter.supportedActions).toEqual([
        'notify_analyst',
        'notify_oncall',
        'send_email',
      ]);
    });
  });

  // ---- Execution: simulation mode ----------------------------------------

  describe('execute() in simulation mode', () => {
    it('returns simulated success for notify_analyst without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Alert: suspicious login detected' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('notify_analyst');
      expect(result.executor).toBe('notification-adapter');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('simulation');
      expect(output.simulated).toBe(true);
      expect(output.delivered).toBe(false);
      expect(output.message).toBe('Alert: suspicious login detected');
      expect(output.notification_id).toMatch(/^sim-/);
    });

    it('returns simulated success for notify_oncall without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'notify_oncall',
        { message: 'Critical incident escalation' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('notify_oncall');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('simulation');
      expect(output.simulated).toBe(true);
    });

    it('returns simulated success for send_email without calling fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'send_email',
        { to: 'analyst@example.com', subject: 'Alert', body: 'Check this out' },
        'simulation',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('send_email');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('simulation');
      expect(output.simulated).toBe(true);
    });
  });

  // ---- Execution: dry-run mode -------------------------------------------

  describe('execute() in dry-run mode', () => {
    it('validates only for notify_analyst and does not call fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test message' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('dry-run');
      expect(output.delivered).toBe(false);
      expect(output.message).toContain('Dry-run validation passed');
    });

    it('validates only for send_email and does not call fetch', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute(
        'send_email',
        { to: 'a@b.com', subject: 'Subj', body: 'Body' },
        'dry-run',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('dry-run');
    });

    it('returns validation error for missing message in dry-run', async () => {
      const adapter = await initAdapter();
      const result = await adapter.execute('notify_analyst', {}, 'dry-run');

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VALIDATION_ERROR');
      expect(result.error?.message).toContain("requires a string 'message' parameter");
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ---- Execution: production with Slack ----------------------------------

  describe('execute() production with Slack', () => {
    it('POSTs notify_analyst to the Slack webhook URL', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('ok', { status: 200 }),
      );

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Suspicious activity on host-42' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('notify_analyst');
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://hooks.slack.com/services/T00/B00/xxxx');
      expect((options as RequestInit).method).toBe('POST');
      expect((options as RequestInit).headers).toEqual({
        'Content-Type': 'application/json',
      });

      const body = JSON.parse((options as RequestInit).body as string) as Record<string, unknown>;
      expect(body.text).toBe('Suspicious activity on host-42');
      expect(body.username).toBe('RunbookPilot');

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('production');
      expect(output.delivered).toBe(true);
      expect(output.message).toBe('Suspicious activity on host-42');
    });

    it('POSTs notify_oncall to the Slack webhook URL', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('ok', { status: 200 }),
      );

      const result = await adapter.execute(
        'notify_oncall',
        { message: 'Escalation required', channel: '#oncall-alerts', username: 'IncidentBot' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const body = JSON.parse(
        (mockFetch.mock.calls[0]![1] as RequestInit).body as string,
      ) as Record<string, unknown>;
      expect(body.text).toBe('Escalation required');
      expect(body.channel).toBe('#oncall-alerts');
      expect(body.username).toBe('IncidentBot');
    });

    it('includes httpStatus in metadata on Slack success', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('ok', { status: 200 }),
      );

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'production',
      );

      expect(result.metadata).toEqual({ mode: 'production', httpStatus: 200 });
    });

    it('returns SLACK_API_ERROR for non-ok Slack responses', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('invalid_payload', { status: 400 }),
      );

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('SLACK_API_ERROR');
      expect(result.error?.message).toContain('HTTP 400');
      expect(result.error?.message).toContain('invalid_payload');
      expect(result.error?.retryable).toBe(false);
    });

    it('marks Slack server errors (5xx) as retryable', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('Internal Server Error', { status: 500 }),
      );

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('SLACK_API_ERROR');
      expect(result.error?.retryable).toBe(true);
    });

    it('returns NETWORK_ERROR when Slack fetch throws', async () => {
      const adapter = await initAdapter();

      mockFetch.mockRejectedValueOnce(new Error('Network timeout'));

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NETWORK_ERROR');
      expect(result.error?.message).toContain('Network timeout');
      expect(result.error?.retryable).toBe(true);
    });

    it('returns MISSING_CONFIG when slack_webhook_url is not configured', async () => {
      const adapter = await initAdapter(makeMinimalConfig());

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MISSING_CONFIG');
      expect(result.error?.message).toContain('slack_webhook_url');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('uses default username "RunbookPilot" when none provided', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('ok', { status: 200 }),
      );

      await adapter.execute(
        'notify_analyst',
        { message: 'Hello' },
        'production',
      );

      const body = JSON.parse(
        (mockFetch.mock.calls[0]![1] as RequestInit).body as string,
      ) as Record<string, unknown>;
      expect(body.username).toBe('RunbookPilot');
    });

    it('omits channel from body when not provided', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('ok', { status: 200 }),
      );

      await adapter.execute(
        'notify_analyst',
        { message: 'No channel' },
        'production',
      );

      const body = JSON.parse(
        (mockFetch.mock.calls[0]![1] as RequestInit).body as string,
      ) as Record<string, unknown>;
      expect(body.channel).toBeUndefined();
    });
  });

  // ---- Execution: production with email ----------------------------------

  describe('execute() production with email', () => {
    it('returns success with smtp_not_implemented flag', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'send_email',
        { to: 'analyst@example.com', subject: 'Incident Report', body: 'Details here...' },
        'production',
      );

      expect(result.success).toBe(true);
      expect(result.action).toBe('send_email');
      expect(mockFetch).not.toHaveBeenCalled();

      const output = result.output as Record<string, unknown>;
      expect(output.mode).toBe('production');
      expect(output.delivered).toBe(false);
      expect(output.smtp_not_implemented).toBe(true);
      expect(output.message).toContain('not fully implemented');

      const email = output.email as Record<string, unknown>;
      expect(email.to).toBe('analyst@example.com');
      expect(email.subject).toBe('Incident Report');
      expect(email.body).toBe('Details here...');
      expect(email.from).toBe('alerts@example.com');
      expect(email.smtp_host).toBe('smtp.example.com');
      expect(email.smtp_port).toBe(587);
    });

    it('uses default from address when smtp_user is not configured', async () => {
      const adapter = await initAdapter(
        makeConfig({
          config: {
            slack_webhook_url: 'https://hooks.slack.com/services/T00/B00/xxxx',
            smtp_host: 'smtp.example.com',
          },
        }),
      );

      const result = await adapter.execute(
        'send_email',
        { to: 'a@b.com', subject: 'S', body: 'B' },
        'production',
      );

      expect(result.success).toBe(true);
      const email = (result.output as Record<string, unknown>).email as Record<string, unknown>;
      expect(email.from).toBe('runbookpilot@localhost');
    });

    it('returns MISSING_CONFIG when smtp_host is not configured', async () => {
      const adapter = await initAdapter(makeSlackOnlyConfig());

      const result = await adapter.execute(
        'send_email',
        { to: 'a@b.com', subject: 'S', body: 'B' },
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('MISSING_CONFIG');
      expect(result.error?.message).toContain('smtp_host');
    });

    it('includes v1 warning in metadata', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'send_email',
        { to: 'a@b.com', subject: 'S', body: 'B' },
        'production',
      );

      expect(result.metadata).toEqual({
        mode: 'production',
        warning: 'SMTP not fully implemented in v1',
      });
    });
  });

  // ---- Rollback ----------------------------------------------------------

  describe('rollback()', () => {
    it('returns ROLLBACK_NOT_SUPPORTED for notify_analyst', async () => {
      const adapter = await initAdapter();
      const result = await adapter.rollback('notify_analyst', { message: 'Test' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ROLLBACK_NOT_SUPPORTED');
      expect(result.error?.message).toContain('irreversible');
      expect(result.action).toBe('notify_analyst');
    });

    it('returns ROLLBACK_NOT_SUPPORTED for notify_oncall', async () => {
      const adapter = await initAdapter();
      const result = await adapter.rollback('notify_oncall', { message: 'Test' });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ROLLBACK_NOT_SUPPORTED');
    });

    it('returns ROLLBACK_NOT_SUPPORTED for send_email', async () => {
      const adapter = await initAdapter();
      const result = await adapter.rollback('send_email', {
        to: 'a@b.com',
        subject: 'S',
        body: 'B',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ROLLBACK_NOT_SUPPORTED');
    });

    it('has zero duration for rollback not-supported responses', async () => {
      const adapter = await initAdapter();
      const result = await adapter.rollback('notify_analyst', { message: 'Test' });

      expect(result.duration_ms).toBe(0);
    });

    it('throws when adapter is not initialized', async () => {
      const adapter = new NotificationAdapter();

      await expect(
        adapter.rollback('notify_analyst', { message: 'Test' }),
      ).rejects.toThrow('not initialized');
    });
  });

  // ---- Health Check ------------------------------------------------------

  describe('healthCheck()', () => {
    it('pings Slack webhook with HEAD and reports healthy on 200', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('', { status: 200 }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('Slack webhook reachable');
      expect(health.message).toContain('200');
      expect(health.latencyMs).toBeDefined();
      expect(health.checkedAt).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(1);

      const [url, options] = mockFetch.mock.calls[0]!;
      expect(url).toBe('https://hooks.slack.com/services/T00/B00/xxxx');
      expect((options as RequestInit).method).toBe('HEAD');
    });

    it('treats 405 (Method Not Allowed) as healthy since Slack may return it for HEAD', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('', { status: 405 }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('405');
    });

    it('returns degraded for non-ok, non-405 responses', async () => {
      const adapter = await initAdapter();

      mockFetch.mockResolvedValueOnce(
        new Response('Forbidden', { status: 403 }),
      );

      const health = await adapter.healthCheck();

      expect(health.status).toBe('degraded');
      expect(health.message).toContain('403');
    });

    it('returns unhealthy when fetch throws', async () => {
      const adapter = await initAdapter();

      mockFetch.mockRejectedValueOnce(new Error('Connection reset'));

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unhealthy');
      expect(health.message).toContain('Connection reset');
    });

    it('returns unknown when adapter is not initialized', async () => {
      const adapter = new NotificationAdapter();

      const health = await adapter.healthCheck();

      expect(health.status).toBe('unknown');
      expect(health.message).toBe('Adapter not initialized');
    });

    it('returns healthy when no slack_webhook_url is configured (email-only mode)', async () => {
      const adapter = await initAdapter(makeMinimalConfig());

      const health = await adapter.healthCheck();

      expect(health.status).toBe('healthy');
      expect(health.message).toContain('email-only');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ---- Validate Parameters -----------------------------------------------

  describe('validateParameters()', () => {
    let adapter: NotificationAdapter;

    beforeEach(async () => {
      adapter = await initAdapter();
    });

    it('validates notify_analyst with a valid message', async () => {
      const result = await adapter.validateParameters('notify_analyst', {
        message: 'Alert triggered',
      });
      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
    });

    it('rejects notify_analyst with missing message', async () => {
      const result = await adapter.validateParameters('notify_analyst', {});
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'message' parameter");
    });

    it('rejects notify_analyst with non-string message', async () => {
      const result = await adapter.validateParameters('notify_analyst', { message: 42 });
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'message' parameter");
    });

    it('validates notify_oncall with a valid message', async () => {
      const result = await adapter.validateParameters('notify_oncall', {
        message: 'Escalation needed',
      });
      expect(result.valid).toBe(true);
    });

    it('rejects notify_oncall with missing message', async () => {
      const result = await adapter.validateParameters('notify_oncall', {});
      expect(result.valid).toBe(false);
      expect(result.errors![0]).toContain("requires a string 'message' parameter");
    });

    it('validates send_email with all required parameters', async () => {
      const result = await adapter.validateParameters('send_email', {
        to: 'analyst@example.com',
        subject: 'Incident Report',
        body: 'Investigation details...',
      });
      expect(result.valid).toBe(true);
    });

    it('rejects send_email with missing to parameter', async () => {
      const result = await adapter.validateParameters('send_email', {
        subject: 'Subj',
        body: 'Body',
      });
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.some((e) => e.includes("'to'"))).toBe(true);
    });

    it('rejects send_email with missing subject parameter', async () => {
      const result = await adapter.validateParameters('send_email', {
        to: 'a@b.com',
        body: 'Body',
      });
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes("'subject'"))).toBe(true);
    });

    it('rejects send_email with missing body parameter', async () => {
      const result = await adapter.validateParameters('send_email', {
        to: 'a@b.com',
        subject: 'Subj',
      });
      expect(result.valid).toBe(false);
      expect(result.errors!.some((e) => e.includes("'body'"))).toBe(true);
    });

    it('collects all errors when multiple parameters are missing for send_email', async () => {
      const result = await adapter.validateParameters('send_email', {});
      expect(result.valid).toBe(false);
      expect(result.errors).toBeDefined();
      expect(result.errors!.length).toBe(3);
    });
  });

  // ---- getCapabilities ---------------------------------------------------

  describe('getCapabilities()', () => {
    it('returns correct capabilities', () => {
      const adapter = new NotificationAdapter();
      const caps = adapter.getCapabilities();

      expect(caps.supportedActions).toEqual([
        'notify_analyst',
        'notify_oncall',
        'send_email',
      ]);
      expect(caps.supportsSimulation).toBe(true);
      expect(caps.supportsRollback).toBe(false);
      expect(caps.supportsValidation).toBe(true);
      expect(caps.maxConcurrency).toBe(0);
    });
  });

  // ---- Edge Cases --------------------------------------------------------

  describe('edge cases', () => {
    it('throws when executing without initialization', async () => {
      const adapter = new NotificationAdapter();

      await expect(
        adapter.execute('notify_analyst', { message: 'Test' }, 'production'),
      ).rejects.toThrow('not initialized');
    });

    it('throws when action is not supported', async () => {
      const adapter = await initAdapter();

      await expect(
        adapter.execute('block_ip' as 'notify_analyst', {}, 'production'),
      ).rejects.toThrow('does not support action');
    });

    it('returns failure for unknown execution mode', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'notify_analyst',
        { message: 'Test' },
        'unknown-mode' as 'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_MODE');
    });

    it('returns validation error before making any fetch call in production', async () => {
      const adapter = await initAdapter();

      const result = await adapter.execute(
        'notify_analyst',
        {},
        'production',
      );

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('VALIDATION_ERROR');
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('uses fallback message when no message param is provided for simulation', async () => {
      const adapter = await initAdapter();

      // notify_analyst requires message param, so this will fail validation
      // Instead, test the fallback through send_email in simulation where body is the fallback
      const result = await adapter.execute(
        'send_email',
        { to: 'a@b.com', subject: 'S', body: 'Email body text' },
        'simulation',
      );

      expect(result.success).toBe(true);
      const output = result.output as Record<string, unknown>;
      // send_email falls back to body when message is not set
      expect(output.message).toBe('Email body text');
    });
  });
});
