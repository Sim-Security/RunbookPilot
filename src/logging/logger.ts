import pino from 'pino';
import { v4 as uuidv4 } from 'uuid';

const SENSITIVE_KEYS = new Set([
  'apiKey',
  'api_key',
  'password',
  'secret',
  'token',
  'authorization',
  'credentials',
  'OPENROUTER_API_KEY',
]);

function redactValue(key: string, value: unknown): unknown {
  if (typeof value === 'string' && SENSITIVE_KEYS.has(key)) {
    return '***REDACTED***';
  }
  if (typeof value === 'object' && value !== null) {
    return redactObject(value as Record<string, unknown>);
  }
  return value;
}

function redactObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = redactValue(key, value);
  }
  return result;
}

const logLevel = process.env['LOG_LEVEL'] ?? 'info';

const baseLogger = pino({
  level: logLevel,
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      'apiKey',
      'api_key',
      'password',
      'secret',
      'token',
      'authorization',
      'credentials',
      'config.openRouter.apiKey',
    ],
    censor: '***REDACTED***',
  },
});

export interface Logger {
  trace(msg: string, data?: Record<string, unknown>): void;
  debug(msg: string, data?: Record<string, unknown>): void;
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
  fatal(msg: string, data?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

function wrapPinoLogger(pinoLogger: pino.Logger): Logger {
  return {
    trace(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.trace(data, msg);
      else pinoLogger.trace(msg);
    },
    debug(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.debug(data, msg);
      else pinoLogger.debug(msg);
    },
    info(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.info(data, msg);
      else pinoLogger.info(msg);
    },
    warn(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.warn(data, msg);
      else pinoLogger.warn(msg);
    },
    error(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.error(data, msg);
      else pinoLogger.error(msg);
    },
    fatal(msg: string, data?: Record<string, unknown>) {
      if (data) pinoLogger.fatal(data, msg);
      else pinoLogger.fatal(msg);
    },
    child(bindings: Record<string, unknown>): Logger {
      return wrapPinoLogger(pinoLogger.child(bindings));
    },
  };
}

/** Root application logger */
export const logger = wrapPinoLogger(baseLogger);

/** Create a child logger with an execution correlation ID */
export function createExecutionLogger(executionId?: string): Logger {
  const correlationId = executionId ?? uuidv4();
  return logger.child({ correlationId });
}

/** Redact sensitive data from an object for safe logging */
export { redactObject };
