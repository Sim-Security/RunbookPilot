import { describe, it, expect } from 'vitest';
import {
  resolveTemplateString,
  resolveTemplates,
  resolveStepParameters,
} from '../../../src/engine/templating.ts';
import type { TemplateContext } from '../../../src/engine/templating.ts';

const baseContext: TemplateContext = {
  alert: {
    host: {
      hostname: 'workstation-042',
      ip: ['10.20.30.40'],
    },
    event: {
      severity: 85,
      category: ['malware'],
    },
    user: { name: 'jdoe', email: 'jdoe@example.com' },
    email: { message_id: 'msg-123', subject: 'Suspicious Activity' },
  },
  steps: {
    'step-01': {
      output: {
        score: 92,
        sender: { domain: 'evil.com', address: 'bad@evil.com' },
        file_count: 3,
      },
    },
  },
  context: {
    analyst_email: 'analyst@example.com',
    ticket_id: 'SOC-456',
  },
  env: {
    VIRUSTOTAL_API_KEY: 'vt-test-key-123',
  },
};

describe('Template String Resolution', () => {
  it('resolves alert field references', () => {
    const result = resolveTemplateString('{{ alert.host.hostname }}', baseContext);
    expect(result.resolved).toBe('workstation-042');
    expect(result.unresolvedPaths).toEqual([]);
  });

  it('resolves step output references', () => {
    const result = resolveTemplateString('{{ steps.step-01.output.score }}', baseContext);
    expect(result.resolved).toBe('92');
  });

  it('resolves nested step output', () => {
    const result = resolveTemplateString('{{ steps.step-01.output.sender.domain }}', baseContext);
    expect(result.resolved).toBe('evil.com');
  });

  it('resolves context variable references', () => {
    const result = resolveTemplateString('{{ context.analyst_email }}', baseContext);
    expect(result.resolved).toBe('analyst@example.com');
  });

  it('resolves env variable references', () => {
    const result = resolveTemplateString('{{ env.VIRUSTOTAL_API_KEY }}', baseContext);
    expect(result.resolved).toBe('vt-test-key-123');
  });

  it('resolves multiple templates in one string', () => {
    const template = 'Host {{ alert.host.hostname }} user {{ alert.user.name }}';
    const result = resolveTemplateString(template, baseContext);
    expect(result.resolved).toBe('Host workstation-042 user jdoe');
  });

  it('handles templates with surrounding text', () => {
    const result = resolveTemplateString(
      'Subject: {{ alert.email.subject }} [Score: {{ steps.step-01.output.score }}]',
      baseContext,
    );
    expect(result.resolved).toBe('Subject: Suspicious Activity [Score: 92]');
  });

  it('handles default values for missing paths', () => {
    const result = resolveTemplateString('{{ alert.missing | default: unknown }}', baseContext);
    expect(result.resolved).toBe('unknown');
    expect(result.unresolvedPaths).toEqual([]);
  });

  it('handles quoted default values', () => {
    const result = resolveTemplateString("{{ alert.missing | default: 'N/A' }}", baseContext);
    expect(result.resolved).toBe('N/A');
  });

  it('handles numeric default values', () => {
    const result = resolveTemplateString('{{ alert.missing | default: 300 }}', baseContext);
    expect(result.resolved).toBe('300');
  });

  it('tracks unresolved paths', () => {
    const result = resolveTemplateString('{{ alert.nonexistent.field }}', baseContext);
    expect(result.resolved).toBe('');
    expect(result.unresolvedPaths).toEqual(['alert.nonexistent.field']);
  });

  it('returns original string with no templates', () => {
    const result = resolveTemplateString('plain text', baseContext);
    expect(result.resolved).toBe('plain text');
    expect(result.unresolvedPaths).toEqual([]);
  });

  it('handles whitespace in template expressions', () => {
    const result = resolveTemplateString('{{  alert.host.hostname  }}', baseContext);
    expect(result.resolved).toBe('workstation-042');
  });
});

describe('Recursive Template Resolution', () => {
  it('resolves strings', () => {
    const result = resolveTemplates('{{ alert.host.hostname }}', baseContext);
    expect(result.resolved).toBe('workstation-042');
  });

  it('preserves non-template types for single-expression strings', () => {
    // When entire value is {{ expr }}, return the actual type, not string
    const result = resolveTemplates('{{ steps.step-01.output.score }}', baseContext);
    expect(result.resolved).toBe(92);
  });

  it('resolves objects recursively', () => {
    const params = {
      hostname: '{{ alert.host.hostname }}',
      severity: '{{ alert.event.severity }}',
      nested: {
        sender: '{{ steps.step-01.output.sender.address }}',
      },
    };
    const result = resolveTemplates(params, baseContext);
    const resolved = result.resolved as Record<string, unknown>;
    expect(resolved['hostname']).toBe('workstation-042');
    expect(resolved['severity']).toBe(85);
    const nested = resolved['nested'] as Record<string, unknown>;
    expect(nested['sender']).toBe('bad@evil.com');
  });

  it('resolves arrays', () => {
    const result = resolveTemplates(
      ['{{ alert.host.hostname }}', '{{ alert.user.name }}'],
      baseContext,
    );
    expect(result.resolved).toEqual(['workstation-042', 'jdoe']);
  });

  it('passes through numbers', () => {
    const result = resolveTemplates(42, baseContext);
    expect(result.resolved).toBe(42);
  });

  it('passes through booleans', () => {
    const result = resolveTemplates(true, baseContext);
    expect(result.resolved).toBe(true);
  });

  it('passes through null', () => {
    const result = resolveTemplates(null, baseContext);
    expect(result.resolved).toBe(null);
  });

  it('collects all unresolved paths from nested structures', () => {
    const params = {
      a: '{{ alert.missing1 }}',
      b: {
        c: '{{ alert.missing2 }}',
      },
    };
    const result = resolveTemplates(params, baseContext);
    expect(result.unresolvedPaths).toContain('alert.missing1');
    expect(result.unresolvedPaths).toContain('alert.missing2');
  });
});

describe('resolveStepParameters', () => {
  it('resolves all parameters in a step', () => {
    const params = {
      message_id: '{{ alert.email.message_id }}',
      analyst: '{{ context.analyst_email }}',
      api_key: '{{ env.VIRUSTOTAL_API_KEY }}',
      static_value: 'constant',
      count: 5,
    };

    const result = resolveStepParameters(params, baseContext);
    expect(result.resolved['message_id']).toBe('msg-123');
    expect(result.resolved['analyst']).toBe('analyst@example.com');
    expect(result.resolved['api_key']).toBe('vt-test-key-123');
    expect(result.resolved['static_value']).toBe('constant');
    expect(result.resolved['count']).toBe(5);
    expect(result.unresolvedPaths).toEqual([]);
  });
});

describe('Edge cases', () => {
  it('handles empty context', () => {
    const result = resolveTemplateString('{{ alert.host.hostname }}', {});
    expect(result.resolved).toBe('');
    expect(result.unresolvedPaths).toEqual(['alert.host.hostname']);
  });

  it('handles deeply nested access', () => {
    const ctx: TemplateContext = {
      alert: { a: { b: { c: { d: 'deep' } } } },
    };
    const result = resolveTemplateString('{{ alert.a.b.c.d }}', ctx);
    expect(result.resolved).toBe('deep');
  });

  it('handles array values in alert', () => {
    const result = resolveTemplates('{{ alert.host.ip }}', baseContext);
    // Single-expression template preserves original type (array stays array)
    expect(result.resolved).toEqual(['10.20.30.40']);
  });

  it('resolves process.env variables when env not provided', () => {
    process.env['TEST_RUNBOOK_VAR'] = 'from-process-env';
    const result = resolveTemplateString('{{ env.TEST_RUNBOOK_VAR }}', {});
    expect(result.resolved).toBe('from-process-env');
    delete process.env['TEST_RUNBOOK_VAR'];
  });
});
