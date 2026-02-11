import { describe, it, expect } from 'vitest';
import { logger, createExecutionLogger, redactObject } from '../../src/logging/logger.ts';

describe('Logger', () => {
  it('creates a root logger', () => {
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.debug).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.trace).toBe('function');
    expect(typeof logger.fatal).toBe('function');
  });

  it('creates a child logger with correlation ID', () => {
    const execLogger = createExecutionLogger('test-exec-123');
    expect(execLogger).toBeDefined();
    expect(typeof execLogger.info).toBe('function');
  });

  it('generates correlation ID when none provided', () => {
    const execLogger = createExecutionLogger();
    expect(execLogger).toBeDefined();
  });

  it('creates nested child loggers', () => {
    const child = logger.child({ component: 'test' });
    expect(child).toBeDefined();
    expect(typeof child.info).toBe('function');
  });

  it('logs at all levels without data', () => {
    expect(() => logger.trace('trace msg')).not.toThrow();
    expect(() => logger.debug('debug msg')).not.toThrow();
    expect(() => logger.info('info msg')).not.toThrow();
    expect(() => logger.warn('warn msg')).not.toThrow();
    expect(() => logger.error('error msg')).not.toThrow();
    expect(() => logger.fatal('fatal msg')).not.toThrow();
  });

  it('logs at all levels with data', () => {
    const data = { key: 'value' };
    expect(() => logger.trace('trace msg', data)).not.toThrow();
    expect(() => logger.debug('debug msg', data)).not.toThrow();
    expect(() => logger.info('info msg', data)).not.toThrow();
    expect(() => logger.warn('warn msg', data)).not.toThrow();
    expect(() => logger.error('error msg', data)).not.toThrow();
    expect(() => logger.fatal('fatal msg', data)).not.toThrow();
  });
});

describe('redactObject', () => {
  it('redacts sensitive keys', () => {
    const obj = {
      name: 'test',
      apiKey: 'sk-secret-123',
      password: 'hunter2',
      token: 'bearer-token',
    };
    const redacted = redactObject(obj);
    expect(redacted['name']).toBe('test');
    expect(redacted['apiKey']).toBe('***REDACTED***');
    expect(redacted['password']).toBe('***REDACTED***');
    expect(redacted['token']).toBe('***REDACTED***');
  });

  it('handles nested objects', () => {
    const obj = {
      config: {
        apiKey: 'secret',
        name: 'test',
      },
    };
    const redacted = redactObject(obj);
    const config = redacted['config'] as Record<string, unknown>;
    expect(config['apiKey']).toBe('***REDACTED***');
    expect(config['name']).toBe('test');
  });

  it('preserves non-sensitive values', () => {
    const obj = {
      host: 'localhost',
      port: 3000,
      enabled: true,
    };
    const redacted = redactObject(obj);
    expect(redacted['host']).toBe('localhost');
    expect(redacted['port']).toBe(3000);
    expect(redacted['enabled']).toBe(true);
  });

  it('handles empty objects', () => {
    const redacted = redactObject({});
    expect(redacted).toEqual({});
  });
});
