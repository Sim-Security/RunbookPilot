/**
 * Notification Adapter
 *
 * Handles analyst/on-call notifications and email delivery.
 * Supports Slack webhook delivery and email (SMTP placeholder in v1).
 *
 * Supported actions: notify_analyst, notify_oncall, send_email
 *
 * @module adapters/notification/notification-adapter
 */

import {
  BaseAdapter,
  type AdapterCapabilities,
  type HealthCheckResult,
  type ValidationResult,
} from '../adapter-interface.ts';

import type {
  StepAction,
  ExecutionMode,
  AdapterResult,
  AdapterConfig,
} from '../../types/playbook.ts';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUPPORTED_ACTIONS: readonly StepAction[] = [
  'notify_analyst',
  'notify_oncall',
  'send_email',
] as const;

// ---------------------------------------------------------------------------
// Notification Adapter
// ---------------------------------------------------------------------------

export class NotificationAdapter extends BaseAdapter {
  readonly name = 'notification-adapter';
  readonly version = '1.0.0';
  readonly supportedActions: readonly StepAction[] = SUPPORTED_ACTIONS;

  // ---- Lifecycle -----------------------------------------------------------

  override async initialize(config: AdapterConfig): Promise<void> {
    await super.initialize(config);
  }

  // ---- Execute -------------------------------------------------------------

  override async execute(
    action: StepAction,
    params: Record<string, unknown>,
    mode: ExecutionMode,
  ): Promise<AdapterResult> {
    this.assertInitialized();
    this.assertSupportsAction(action);

    const start = Date.now();

    // Validate parameters first regardless of mode
    const validation = await this.validateParameters(action, params);
    if (!validation.valid) {
      return this.failureResult(
        action,
        Date.now() - start,
        'VALIDATION_ERROR',
        `Parameter validation failed: ${validation.errors?.join('; ')}`,
      );
    }

    switch (mode) {
      case 'dry-run':
        return this.executeDryRun(action, params, start);
      case 'simulation':
        return this.executeSimulation(action, params, start);
      case 'production':
        return this.executeProduction(action, params, start);
      default:
        return this.failureResult(
          action,
          Date.now() - start,
          'INVALID_MODE',
          `Unknown execution mode: ${String(mode)}`,
        );
    }
  }

  // ---- Rollback ------------------------------------------------------------

  override async rollback(
    action: StepAction,
    _params: Record<string, unknown>,
  ): Promise<AdapterResult> {
    this.assertInitialized();

    return {
      success: false,
      action,
      executor: this.name,
      duration_ms: 0,
      error: {
        code: 'ROLLBACK_NOT_SUPPORTED',
        message: `Notifications cannot be rolled back: action '${action}' is irreversible once delivered`,
        adapter: this.name,
        action,
        retryable: false,
      },
    };
  }

  // ---- Health Check --------------------------------------------------------

  override async healthCheck(): Promise<HealthCheckResult> {
    const checkedAt = new Date().toISOString();

    if (!this.initialized || !this.config) {
      return {
        status: 'unknown',
        message: 'Adapter not initialized',
        checkedAt,
      };
    }

    const webhookUrl = this.config.config.slack_webhook_url;

    // If no webhook URL is configured, consider it healthy (email-only mode)
    if (!webhookUrl || typeof webhookUrl !== 'string') {
      return {
        status: 'healthy',
        message: 'No Slack webhook configured; running in email-only or simulation mode',
        checkedAt,
      };
    }

    const start = Date.now();
    try {
      const response = await fetch(webhookUrl, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000),
      });

      const latencyMs = Date.now() - start;

      // Slack webhooks may return various codes for HEAD; 2xx/4xx means reachable
      if (response.ok || response.status === 405) {
        return {
          status: 'healthy',
          message: `Slack webhook reachable (HTTP ${response.status})`,
          latencyMs,
          checkedAt,
        };
      }

      return {
        status: 'degraded',
        message: `Slack webhook returned HTTP ${response.status}`,
        latencyMs,
        checkedAt,
      };
    } catch (error: unknown) {
      const latencyMs = Date.now() - start;
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        status: 'unhealthy',
        message: `Slack webhook unreachable: ${message}`,
        latencyMs,
        checkedAt,
      };
    }
  }

  // ---- Capabilities --------------------------------------------------------

  override getCapabilities(): AdapterCapabilities {
    return {
      supportedActions: this.supportedActions,
      supportsSimulation: true,
      supportsRollback: false,
      supportsValidation: true,
      maxConcurrency: 0, // Unlimited
    };
  }

  // ---- Validate Parameters -------------------------------------------------

  async validateParameters(
    action: StepAction,
    params: Record<string, unknown>,
  ): Promise<ValidationResult> {
    const errors: string[] = [];

    if (action === 'notify_analyst' || action === 'notify_oncall') {
      if (!params.message || typeof params.message !== 'string') {
        errors.push(`Action '${action}' requires a string 'message' parameter`);
      }
    }

    if (action === 'send_email') {
      if (!params.to || typeof params.to !== 'string') {
        errors.push("Action 'send_email' requires a string 'to' parameter");
      }
      if (!params.subject || typeof params.subject !== 'string') {
        errors.push("Action 'send_email' requires a string 'subject' parameter");
      }
      if (!params.body || typeof params.body !== 'string') {
        errors.push("Action 'send_email' requires a string 'body' parameter");
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  // ---- Private: Mode-specific execution ------------------------------------

  private executeDryRun(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    return this.successResult(
      action,
      Date.now() - start,
      {
        mode: 'dry-run',
        action,
        params,
        delivered: false,
        message: `Dry-run validation passed for '${action}'`,
      },
      { mode: 'dry-run' },
    );
  }

  private executeSimulation(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    return this.successResult(
      action,
      Date.now() - start,
      {
        mode: 'simulation',
        action,
        delivered: false,
        simulated: true,
        message: this.resolveMessage(action, params),
        notification_id: `sim-${crypto.randomUUID()}`,
      },
      { mode: 'simulation' },
    );
  }

  private async executeProduction(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    if (!this.config) {
      return this.failureResult(
        action,
        Date.now() - start,
        'NOT_CONFIGURED',
        'Adapter config is not available',
      );
    }

    if (action === 'send_email') {
      return this.executeEmail(action, params, start);
    }

    // notify_analyst and notify_oncall use Slack
    return this.executeSlack(action, params, start);
  }

  // ---- Private: Slack delivery ---------------------------------------------

  private async executeSlack(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): Promise<AdapterResult> {
    if (!this.config) {
      return this.failureResult(
        action,
        Date.now() - start,
        'NOT_CONFIGURED',
        'Adapter config is not available',
      );
    }

    const webhookUrl = this.config.config.slack_webhook_url;
    if (!webhookUrl || typeof webhookUrl !== 'string') {
      return this.failureResult(
        action,
        Date.now() - start,
        'MISSING_CONFIG',
        "Production mode requires 'slack_webhook_url' in adapter config for Slack notifications",
      );
    }

    const message = this.resolveMessage(action, params);
    const channel = typeof params.channel === 'string' ? params.channel : undefined;
    const username = typeof params.username === 'string' ? params.username : 'RunbookPilot';

    const body: Record<string, string> = {
      text: message,
      username,
    };
    if (channel) {
      body.channel = channel;
    }

    try {
      const timeoutMs = (this.config.timeout ?? 30) * 1000;
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });

      const durationMs = Date.now() - start;

      if (!response.ok) {
        const errorText = await response.text();
        return this.failureResult(
          action,
          durationMs,
          'SLACK_API_ERROR',
          `Slack webhook returned HTTP ${response.status}: ${errorText}`,
          response.status >= 500,
        );
      }

      return this.successResult(
        action,
        durationMs,
        {
          mode: 'production',
          action,
          delivered: true,
          channel: channel ?? 'default',
          message,
          notification_id: crypto.randomUUID(),
        },
        { mode: 'production', httpStatus: response.status },
      );
    } catch (error: unknown) {
      const durationMs = Date.now() - start;
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      return this.failureResult(
        action,
        durationMs,
        'NETWORK_ERROR',
        `Failed to reach Slack webhook: ${errorMsg}`,
        true,
      );
    }
  }

  // ---- Private: Email delivery (placeholder in v1) -------------------------

  private executeEmail(
    action: StepAction,
    params: Record<string, unknown>,
    start: number,
  ): AdapterResult {
    if (!this.config) {
      return this.failureResult(
        action,
        Date.now() - start,
        'NOT_CONFIGURED',
        'Adapter config is not available',
      );
    }

    const smtpHost = this.config.config.smtp_host;
    const smtpPort = this.config.config.smtp_port;
    const smtpUser = this.config.config.smtp_user;

    if (!smtpHost || typeof smtpHost !== 'string') {
      return this.failureResult(
        action,
        Date.now() - start,
        'MISSING_CONFIG',
        "send_email requires 'smtp_host' in adapter config",
      );
    }

    // Log that SMTP is not fully implemented in v1
    const emailPayload = {
      to: params.to as string,
      subject: params.subject as string,
      body: params.body as string,
      from: smtpUser ?? 'runbookpilot@localhost',
      smtp_host: smtpHost,
      smtp_port: smtpPort ?? 587,
    };

    // v1: SMTP transport is not wired up. Log the constructed email and
    // return success so the runbook execution flow is not blocked.
    return this.successResult(
      action,
      Date.now() - start,
      {
        mode: 'production',
        action,
        delivered: false,
        smtp_not_implemented: true,
        message:
          'SMTP transport is not fully implemented in v1. Email constructed but not sent.',
        email: emailPayload,
        notification_id: crypto.randomUUID(),
      },
      {
        mode: 'production',
        warning: 'SMTP not fully implemented in v1',
      },
    );
  }

  // ---- Private: Message helpers --------------------------------------------

  /**
   * Resolves the notification message from params.
   * Template patterns ({{ }}) are passed through as-is since template
   * resolution happens upstream in the execution engine.
   */
  private resolveMessage(
    action: StepAction,
    params: Record<string, unknown>,
  ): string {
    if (typeof params.message === 'string') {
      return params.message;
    }

    // Fallback for send_email where the body is the message
    if (action === 'send_email' && typeof params.body === 'string') {
      return params.body;
    }

    return `[RunbookPilot] Notification triggered by action '${action}'`;
  }
}
