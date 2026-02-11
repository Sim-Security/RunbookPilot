/**
 * DetectForge Webhook Receiver for RunbookPilot
 *
 * HTTP server (Bun.serve) that receives ECS-normalized alert events from
 * DetectForge (or any compatible alert source) via webhook POST requests.
 *
 * Endpoints:
 * - POST /api/v1/alerts  -- Ingest a single alert event
 * - GET  /health         -- Health check
 *
 * Security:
 * - Optional HMAC-SHA256 signature validation via `x-detectforge-signature` header
 * - Shared secret configured at server creation time
 *
 * @module ingest/webhook-receiver
 */

import { createHmac, timingSafeEqual as cryptoTimingSafeEqual } from 'crypto';
import { logger } from '../logging/logger.ts';
import { validateAlertEvent } from './alert-ingestor.ts';
import type { AlertEvent } from '../types/ecs.ts';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface WebhookServerOptions {
  port: number;
  host: string;
  /** HMAC-SHA256 shared secret for signature validation. If undefined, skip validation. */
  sharedSecret?: string;
  /** Callback invoked for each validated alert. Must return an execution_id. */
  onAlert: (alert: AlertEvent) => Promise<{ execution_id: string }> | { execution_id: string };
}

export interface WebhookServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  readonly port: number;
  readonly isRunning: boolean;
}

// ─── Internal Logger ────────────────────────────────────────────────────────

const log = logger.child({ module: 'webhook-receiver' });

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Build a JSON Response with the given status code.
 */
function jsonResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Compute HMAC-SHA256 hex digest of a raw body using the shared secret.
 */
function computeSignature(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

/**
 * Constant-time string comparison to prevent timing attacks on signature checks.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');

  return cryptoTimingSafeEqual(bufA, bufB);
}

// ─── Route Handlers ─────────────────────────────────────────────────────────

/**
 * Handle GET /health
 */
function handleHealthCheck(): Response {
  return jsonResponse(
    {
      status: 'ok',
      service: 'runbookpilot-webhook',
      timestamp: new Date().toISOString(),
    },
    200,
  );
}

/**
 * Handle POST /api/v1/alerts
 */
async function handleAlertIngestion(
  request: Request,
  options: WebhookServerOptions,
): Promise<Response> {
  // Read the raw body
  let rawBody: string;
  try {
    rawBody = await request.text();
  } catch (err) {
    log.error('Failed to read request body', {
      error: err instanceof Error ? err.message : String(err),
    });
    return jsonResponse({ success: false, error: 'Failed to read request body' }, 400);
  }

  // ── Signature validation ──────────────────────────────────────────────
  if (options.sharedSecret) {
    const signatureHeader = request.headers.get('x-detectforge-signature');

    if (!signatureHeader) {
      log.warn('Missing x-detectforge-signature header');
      return jsonResponse(
        { success: false, error: 'Missing x-detectforge-signature header' },
        401,
      );
    }

    const expectedSignature = computeSignature(rawBody, options.sharedSecret);

    if (!timingSafeEqual(signatureHeader, expectedSignature)) {
      log.warn('Invalid webhook signature');
      return jsonResponse({ success: false, error: 'Invalid signature' }, 401);
    }

    log.debug('Webhook signature validated');
  }

  // ── Parse JSON body ───────────────────────────────────────────────────
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch (err) {
    log.warn('Invalid JSON in request body', {
      error: err instanceof Error ? err.message : String(err),
    });
    return jsonResponse({ success: false, error: 'Invalid JSON in request body' }, 400);
  }

  // ── Validate as ECS AlertEvent ────────────────────────────────────────
  const validation = validateAlertEvent(parsed);

  if (!validation.valid || !validation.alert) {
    log.warn('Alert validation failed', { error: validation.error });
    return jsonResponse(
      { success: false, error: validation.error ?? 'Alert validation failed' },
      400,
    );
  }

  const alert = validation.alert;

  // ── Extract DetectForge metadata if present ───────────────────────────
  const detectForgeMetadata = alert['x-detectforge'];
  if (detectForgeMetadata) {
    log.info('DetectForge metadata found in alert', {
      rule_id: detectForgeMetadata.rule_id,
      rule_name: detectForgeMetadata.rule_name,
      confidence: detectForgeMetadata.confidence,
      suggested_runbook: detectForgeMetadata.suggested_runbook,
    });
  }

  // ── Invoke the alert callback ─────────────────────────────────────────
  try {
    const result = await options.onAlert(alert);

    log.info('Alert ingested successfully', {
      execution_id: result.execution_id,
      event_kind: alert.event.kind,
      event_severity: alert.event.severity,
      has_detectforge: !!detectForgeMetadata,
    });

    return jsonResponse(
      { success: true, execution_id: result.execution_id },
      200,
    );
  } catch (err) {
    log.error('Alert handler failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    return jsonResponse(
      { success: false, error: 'Internal error processing alert' },
      500,
    );
  }
}

// ─── Server Factory ─────────────────────────────────────────────────────────

/**
 * Create a webhook server instance.
 *
 * The server does not start until `start()` is called. Call `stop()` for
 * graceful shutdown.
 *
 * @param options - Server configuration and alert callback
 * @returns WebhookServer instance
 */
export function createWebhookServer(options: WebhookServerOptions): WebhookServer {
  let server: ReturnType<typeof Bun.serve> | null = null;
  let running = false;

  return {
    async start(): Promise<void> {
      if (running) {
        throw new Error('Webhook server is already running');
      }

      server = Bun.serve({
        port: options.port,
        hostname: options.host,

        async fetch(request: Request): Promise<Response> {
          const url = new URL(request.url);
          const method = request.method.toUpperCase();
          const pathname = url.pathname;

          log.debug('Incoming request', { method, pathname });

          // ── GET /health ──────────────────────────────────────────────
          if (pathname === '/health' && method === 'GET') {
            return handleHealthCheck();
          }

          // ── POST /api/v1/alerts ──────────────────────────────────────
          if (pathname === '/api/v1/alerts') {
            if (method !== 'POST') {
              return jsonResponse(
                { success: false, error: `Method ${method} not allowed. Use POST.` },
                405,
              );
            }
            return handleAlertIngestion(request, options);
          }

          // ── Health check: reject non-GET ─────────────────────────────
          if (pathname === '/health') {
            return jsonResponse(
              { success: false, error: `Method ${method} not allowed. Use GET.` },
              405,
            );
          }

          // ── Unknown route ────────────────────────────────────────────
          return jsonResponse(
            { success: false, error: `Not found: ${pathname}` },
            404,
          );
        },
      });

      running = true;

      log.info('Webhook server started', {
        port: options.port,
        host: options.host,
        hmac_enabled: !!options.sharedSecret,
      });
    },

    async stop(): Promise<void> {
      if (!running || !server) {
        return;
      }

      server.stop(true); // true = close idle connections immediately
      server = null;
      running = false;

      log.info('Webhook server stopped');
    },

    get port(): number {
      return options.port;
    },

    get isRunning(): boolean {
      return running;
    },
  };
}
