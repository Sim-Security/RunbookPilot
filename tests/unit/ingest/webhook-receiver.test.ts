import { describe, it, expect, afterEach, vi } from 'vitest';
import { createHmac } from 'crypto';
import { createWebhookServer } from '../../../src/ingest/webhook-receiver.ts';
import type { WebhookServer, WebhookServerOptions } from '../../../src/ingest/webhook-receiver.ts';

// Webhook receiver uses Bun.serve() — skip tests when running under Node/vitest
const isBun = typeof globalThis.Bun !== 'undefined';

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

/**
 * Build a valid ECS alert payload suitable for POST /api/v1/alerts.
 */
function makeValidAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@timestamp': '2026-02-11T10:00:00.000Z',
    event: {
      kind: 'alert',
      category: ['malware'],
      type: ['info'],
      severity: 80,
    },
    ...overrides,
  };
}

/**
 * Compute HMAC-SHA256 hex digest (mirrors the server's internal computeSignature).
 */
function computeHmac(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body).digest('hex');
}

/**
 * Generate a random high port to avoid collisions between test runs.
 */
function randomPort(): number {
  return 49000 + Math.floor(Math.random() * 10000);
}

// ---------------------------------------------------------------------------
// State managed across tests
// ---------------------------------------------------------------------------

let server: WebhookServer | null = null;
let baseUrl: string;

afterEach(async () => {
  if (server && server.isRunning) {
    await server.stop();
  }
  server = null;
});

/**
 * Create and start a webhook server with the given options, assigning
 * `server` and `baseUrl` for use in the test.
 */
async function startServer(
  overrides: Partial<WebhookServerOptions> = {},
): Promise<void> {
  const port = randomPort();
  const defaults: WebhookServerOptions = {
    port,
    host: '127.0.0.1',
    onAlert: vi.fn(async () => ({ execution_id: 'exec-test-001' })),
    ...overrides,
  };

  server = createWebhookServer(defaults);
  await server.start();
  baseUrl = `http://127.0.0.1:${port}`;
}

// ---------------------------------------------------------------------------
// createWebhookServer
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('createWebhookServer', () => {
  it('creates a server instance', () => {
    const port = randomPort();
    const srv = createWebhookServer({
      port,
      host: '127.0.0.1',
      onAlert: vi.fn(),
    });

    expect(srv).toBeDefined();
    expect(typeof srv.start).toBe('function');
    expect(typeof srv.stop).toBe('function');
  });

  it('server is not running initially', () => {
    const port = randomPort();
    const srv = createWebhookServer({
      port,
      host: '127.0.0.1',
      onAlert: vi.fn(),
    });

    expect(srv.isRunning).toBe(false);
  });

  it('returns the configured port', () => {
    const port = randomPort();
    const srv = createWebhookServer({
      port,
      host: '127.0.0.1',
      onAlert: vi.fn(),
    });

    expect(srv.port).toBe(port);
  });
});

// ---------------------------------------------------------------------------
// Server start / stop
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('server start / stop', () => {
  it('starts and listens on configured port', async () => {
    await startServer();

    expect(server!.isRunning).toBe(true);

    // Verify it actually accepts connections
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
  });

  it('stops gracefully', async () => {
    await startServer();
    expect(server!.isRunning).toBe(true);

    await server!.stop();
    expect(server!.isRunning).toBe(false);
  });

  it('stop is idempotent (calling stop when not running does nothing)', async () => {
    await startServer();
    await server!.stop();
    expect(server!.isRunning).toBe(false);

    // Second stop should not throw
    await expect(server!.stop()).resolves.toBeUndefined();
    expect(server!.isRunning).toBe(false);
  });

  it('throws when starting an already running server', async () => {
    await startServer();
    expect(server!.isRunning).toBe(true);

    await expect(server!.start()).rejects.toThrow('already running');
  });

  it('isRunning reflects actual state', async () => {
    await startServer();
    expect(server!.isRunning).toBe(true);

    await server!.stop();
    expect(server!.isRunning).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// POST /api/v1/alerts
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('POST /api/v1/alerts', () => {
  it('accepts valid ECS alert JSON and calls onAlert callback', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-abc-123' }));
    await startServer({ onAlert });

    const alert = makeValidAlert();
    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });

    expect(res.status).toBe(200);
    expect(onAlert).toHaveBeenCalledTimes(1);

    const calledWith = onAlert.mock.calls[0] as unknown[];
    const alertArg = calledWith[0] as Record<string, unknown>;
    expect(alertArg['@timestamp']).toBe('2026-02-11T10:00:00.000Z');
    expect((alertArg['event'] as Record<string, unknown>).kind).toBe('alert');
  });

  it('returns execution_id from onAlert callback', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-return-test' }));
    await startServer({ onAlert });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    const body = (await res.json()) as { success: boolean; execution_id: string };
    expect(body.success).toBe(true);
    expect(body.execution_id).toBe('exec-return-test');
  });

  it('returns 400 for invalid JSON body', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'this is { not valid JSON',
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('Invalid JSON');
  });

  it('returns 400 for invalid ECS alert (missing @timestamp)', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: { kind: 'alert' } }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('@timestamp');
  });

  it('returns 400 for invalid ECS alert (missing event field)', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ '@timestamp': '2026-02-11T10:00:00.000Z' }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('event');
  });

  it('returns 400 for empty @timestamp string', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ '@timestamp': '   ', event: { kind: 'alert' } }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
  });

  it('returns 500 when onAlert callback throws', async () => {
    const onAlert = vi.fn(async () => {
      throw new Error('Handler blew up');
    });
    await startServer({ onAlert });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(500);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('Internal error');
  });

  it('accepts alert with extra ECS fields', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-extra' }));
    await startServer({ onAlert });

    const alert = makeValidAlert({
      host: { hostname: 'ws-001' },
      source: { ip: '10.0.0.1' },
      user: { name: 'analyst' },
      tags: ['sigma', 'high-priority'],
    });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; execution_id: string };
    expect(body.success).toBe(true);
    expect(onAlert).toHaveBeenCalledTimes(1);
  });

  it('accepts alert with DetectForge metadata', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-df' }));
    await startServer({ onAlert });

    const alert = makeValidAlert({
      'x-detectforge': {
        rule_id: 'df-001',
        rule_name: 'Test Rule',
        rule_version: '1.0.0',
        generated_at: '2026-02-11T09:00:00.000Z',
        confidence: 'high',
        suggested_runbook: 'rb-malware-triage',
      },
    });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; execution_id: string };
    expect(body.success).toBe(true);
  });

  it('response has Content-Type application/json', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.headers.get('content-type')).toBe('application/json');
  });
});

// ---------------------------------------------------------------------------
// HMAC signature validation
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('HMAC signature validation', () => {
  const sharedSecret = 'super-secret-key-for-testing';

  it('returns 401 when signature validation is enabled and signature header is missing', async () => {
    await startServer({ sharedSecret });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('Missing x-detectforge-signature');
  });

  it('returns 401 when HMAC signature is invalid', async () => {
    await startServer({ sharedSecret });

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-detectforge-signature': 'deadbeefdeadbeefdeadbeefdeadbeef',
      },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('Invalid signature');
  });

  it('accepts request when HMAC signature is valid', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-hmac-ok' }));
    await startServer({ sharedSecret, onAlert });

    const alertBody = JSON.stringify(makeValidAlert());
    const signature = computeHmac(alertBody, sharedSecret);

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-detectforge-signature': signature,
      },
      body: alertBody,
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; execution_id: string };
    expect(body.success).toBe(true);
    expect(body.execution_id).toBe('exec-hmac-ok');
    expect(onAlert).toHaveBeenCalledTimes(1);
  });

  it('skips signature validation when sharedSecret is undefined', async () => {
    const onAlert = vi.fn(async () => ({ execution_id: 'exec-no-hmac' }));
    await startServer({ sharedSecret: undefined, onAlert });

    // No signature header provided, should still succeed
    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { success: boolean; execution_id: string };
    expect(body.success).toBe(true);
    expect(body.execution_id).toBe('exec-no-hmac');
  });

  it('rejects signature computed with wrong secret', async () => {
    await startServer({ sharedSecret });

    const alertBody = JSON.stringify(makeValidAlert());
    const wrongSignature = computeHmac(alertBody, 'wrong-secret');

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-detectforge-signature': wrongSignature,
      },
      body: alertBody,
    });

    expect(res.status).toBe(401);
  });

  it('rejects signature computed against different body', async () => {
    await startServer({ sharedSecret });

    const alertBody = JSON.stringify(makeValidAlert());
    const differentBody = JSON.stringify(makeValidAlert({ '@timestamp': '2020-01-01T00:00:00Z' }));
    const signatureForDifferentBody = computeHmac(differentBody, sharedSecret);

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-detectforge-signature': signatureForDifferentBody,
      },
      body: alertBody,
    });

    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('GET /health', () => {
  it('returns 200 with status: ok', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/health`);

    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string; service: string; timestamp: string };
    expect(body.status).toBe('ok');
  });

  it('returns service name in health response', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/health`);
    const body = (await res.json()) as { status: string; service: string };

    expect(body.service).toBe('runbookpilot-webhook');
  });

  it('returns a timestamp in health response', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/health`);
    const body = (await res.json()) as { status: string; timestamp: string };

    expect(body.timestamp).toBeDefined();
    // Verify it parses as a valid ISO date
    const date = new Date(body.timestamp);
    expect(date.getTime()).not.toBeNaN();
  });

  it('health response has Content-Type application/json', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/health`);
    expect(res.headers.get('content-type')).toBe('application/json');
  });
});

// ---------------------------------------------------------------------------
// Other routes / methods
// ---------------------------------------------------------------------------

describe.skipIf(!isBun)('other routes / methods', () => {
  it('returns 404 for unknown paths', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/nonexistent`);

    expect(res.status).toBe(404);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('Not found');
  });

  it('returns 404 for /api/v2/alerts (wrong version)', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v2/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(404);
  });

  it('returns 405 for GET to /api/v1/alerts', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`);

    expect(res.status).toBe(405);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('not allowed');
    expect(body.error).toContain('POST');
  });

  it('returns 405 for PUT to /api/v1/alerts', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(makeValidAlert()),
    });

    expect(res.status).toBe(405);
  });

  it('returns 405 for DELETE to /api/v1/alerts', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'DELETE',
    });

    expect(res.status).toBe(405);
  });

  it('returns 405 for POST to /health', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/health`, {
      method: 'POST',
      body: '{}',
    });

    expect(res.status).toBe(405);
    const body = (await res.json()) as { success: boolean; error: string };
    expect(body.success).toBe(false);
    expect(body.error).toContain('not allowed');
    expect(body.error).toContain('GET');
  });

  it('returns 404 for root path /', async () => {
    await startServer();

    const res = await fetch(`${baseUrl}/`);

    expect(res.status).toBe(404);
  });
});
