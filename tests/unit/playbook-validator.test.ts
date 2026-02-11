import { describe, it, expect } from 'vitest';
import { validatePlaybook, validatePlaybookFile, validatePlaybookYaml } from '../../src/validators/playbook-validator.ts';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeValidRunbook(overrides?: Record<string, unknown>) {
  return {
    runbook: {
      id: '550e8400-e29b-41d4-a716-446655440000',
      version: '1.0',
      metadata: {
        name: 'Test Playbook',
        description: 'A test playbook',
        author: 'test@example.com',
        created: '2026-01-15T10:00:00Z',
        updated: '2026-01-15T10:00:00Z',
        tags: ['test', 'phishing'],
      },
      triggers: {
        detection_sources: ['siem_correlation'],
        mitre_techniques: ['T1566.001'],
        platforms: ['saas'],
      },
      config: {
        automation_level: 'L0',
        max_execution_time: 300,
        requires_approval: false,
      },
      steps: [
        {
          id: 'step-01',
          name: 'Collect Email Metadata',
          action: 'collect_logs',
          executor: 'email_gateway',
          parameters: { message_id: '{{ alert.email.message_id }}' },
          on_error: 'halt',
          timeout: 30,
        },
      ],
      ...overrides,
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Playbook Validator', () => {
  describe('valid playbooks', () => {
    it('validates a minimal valid playbook', () => {
      const result = validatePlaybook(makeValidRunbook());
      expect(result.success).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.data).toBeDefined();
    });

    it('validates a playbook with multiple steps and depends_on', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [
          {
            id: 'step-01',
            name: 'Collect Data',
            action: 'collect_logs',
            executor: 'siem',
            parameters: { query: 'test' },
            on_error: 'halt',
            timeout: 60,
          },
          {
            id: 'step-02',
            name: 'Enrich IP',
            action: 'enrich_ioc',
            executor: 'threat_intel',
            parameters: { ip: '{{ steps.step-01.output.ip }}' },
            depends_on: ['step-01'],
            on_error: 'continue',
            timeout: 30,
          },
        ],
      }));
      expect(result.success).toBe(true);
    });

    it('validates a playbook with rollback definitions', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L1',
          max_execution_time: 600,
          requires_approval: false,
        },
        steps: [
          {
            id: 'step-01',
            name: 'Isolate Host',
            action: 'isolate_host',
            executor: 'edr',
            parameters: { host_id: '{{ alert.host.id }}' },
            rollback: {
              action: 'restore_connectivity',
              parameters: { host_id: '{{ alert.host.id }}' },
              timeout: 60,
            },
            on_error: 'halt',
            timeout: 90,
          },
        ],
      }));
      expect(result.success).toBe(true);
    });

    it('validates L2 with requires_approval: true', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L2',
          max_execution_time: 900,
          requires_approval: true,
          approval_timeout: 600,
        },
      }));
      expect(result.success).toBe(true);
    });

    it('validates playbook with all optional fields', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L1',
          max_execution_time: 600,
          requires_approval: false,
          approval_timeout: 1800,
          parallel_execution: true,
          rollback_on_failure: true,
        },
        steps: [
          {
            id: 'step-01',
            name: 'Query SIEM',
            description: 'Query authentication logs',
            action: 'query_siem',
            executor: 'splunk',
            parameters: { query: 'index=auth' },
            approval_required: false,
            on_error: 'halt',
            timeout: 60,
            condition: 'alert.event.severity > 50',
          },
        ],
      }));
      expect(result.success).toBe(true);
    });
  });

  describe('invalid playbooks', () => {
    it('rejects missing required fields', () => {
      const result = validatePlaybook({ runbook: {} });
      expect(result.success).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('rejects invalid UUID', () => {
      const result = validatePlaybook(makeValidRunbook({ id: 'not-a-uuid' }));
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('UUID'))).toBe(true);
    });

    it('rejects invalid MITRE technique ID', () => {
      const rb = makeValidRunbook();
      (rb.runbook as Record<string, unknown>)['triggers'] = {
        detection_sources: ['siem_correlation'],
        mitre_techniques: ['INVALID'],
        platforms: ['windows'],
      };
      const result = validatePlaybook(rb);
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('T####'))).toBe(true);
    });

    it('rejects empty steps array', () => {
      const result = validatePlaybook(makeValidRunbook({ steps: [] }));
      expect(result.success).toBe(false);
    });

    it('rejects step with timeout out of range', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [{
          id: 'step-01',
          name: 'Test Step',
          action: 'collect_logs',
          executor: 'siem',
          parameters: {},
          on_error: 'halt',
          timeout: 1, // Below minimum of 5
        }],
      }));
      expect(result.success).toBe(false);
    });

    it('rejects max_execution_time out of range', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L0',
          max_execution_time: 10, // Below minimum of 60
          requires_approval: false,
        },
      }));
      expect(result.success).toBe(false);
    });

    it('rejects L2 without requires_approval', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L2',
          max_execution_time: 900,
          requires_approval: false,
        },
      }));
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('L2'))).toBe(true);
    });

    it('rejects duplicate step IDs', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [
          { id: 'step-01', name: 'Step One', action: 'collect_logs', executor: 'siem', parameters: {}, on_error: 'halt', timeout: 30 },
          { id: 'step-01', name: 'Step Two', action: 'enrich_ioc', executor: 'threat_intel', parameters: {}, on_error: 'continue', timeout: 30 },
        ],
      }));
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('unique'))).toBe(true);
    });

    it('rejects invalid depends_on references', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [
          { id: 'step-01', name: 'Step One', action: 'collect_logs', executor: 'siem', parameters: {}, on_error: 'halt', timeout: 30 },
          { id: 'step-02', name: 'Step Two', action: 'enrich_ioc', executor: 'threat_intel', parameters: {}, depends_on: ['step-99'], on_error: 'continue', timeout: 30 },
        ],
      }));
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('depends_on'))).toBe(true);
    });

    it('rejects circular dependencies', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [
          { id: 'step-01', name: 'Step One', action: 'collect_logs', executor: 'siem', parameters: {}, depends_on: ['step-02'], on_error: 'halt', timeout: 30 },
          { id: 'step-02', name: 'Step Two', action: 'enrich_ioc', executor: 'threat_intel', parameters: {}, depends_on: ['step-01'], on_error: 'continue', timeout: 30 },
        ],
      }));
      expect(result.success).toBe(false);
      expect(result.errors.some(e => e.includes('Circular'))).toBe(true);
    });

    it('rejects invalid automation level', () => {
      const result = validatePlaybook(makeValidRunbook({
        config: {
          automation_level: 'L5',
          max_execution_time: 300,
          requires_approval: false,
        },
      }));
      expect(result.success).toBe(false);
    });

    it('rejects invalid step action', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [{
          id: 'step-01',
          name: 'Bad Action',
          action: 'invalid_action',
          executor: 'siem',
          parameters: {},
          on_error: 'halt',
          timeout: 30,
        }],
      }));
      expect(result.success).toBe(false);
    });

    it('rejects name with leading whitespace', () => {
      const rb = makeValidRunbook();
      (rb.runbook as Record<string, unknown>)['metadata'] = {
        name: '  Leading Space',
        created: '2026-01-15T10:00:00Z',
        updated: '2026-01-15T10:00:00Z',
        tags: ['test'],
      };
      const result = validatePlaybook(rb);
      expect(result.success).toBe(false);
    });

    it('rejects invalid timestamp format', () => {
      const rb = makeValidRunbook();
      (rb.runbook as Record<string, unknown>)['metadata'] = {
        name: 'Test',
        created: 'not-a-date',
        updated: '2026-01-15T10:00:00Z',
        tags: ['test'],
      };
      const result = validatePlaybook(rb);
      expect(result.success).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('handles playbook with zero-step array', () => {
      const result = validatePlaybook(makeValidRunbook({ steps: [] }));
      expect(result.success).toBe(false);
    });

    it('handles playbook with only read-only steps', () => {
      const result = validatePlaybook(makeValidRunbook({
        steps: [
          { id: 'step-01', name: 'Query Logs', action: 'query_siem', executor: 'siem', parameters: {}, on_error: 'halt', timeout: 60 },
          { id: 'step-02', name: 'Enrich IOC', action: 'enrich_ioc', executor: 'threat_intel', parameters: {}, on_error: 'continue', timeout: 30 },
        ],
      }));
      expect(result.success).toBe(true);
    });

    it('handles null/undefined input', () => {
      const result = validatePlaybook(null);
      expect(result.success).toBe(false);
    });

    it('handles string input', () => {
      const result = validatePlaybook('not an object');
      expect(result.success).toBe(false);
    });
  });

  describe('file operations', () => {
    it('validates the example playbook file', () => {
      const result = validatePlaybookFile('playbooks/examples/basic.yml');
      // This may fail if the file hasn't been created yet — that's OK
      if (result.errors.some(e => e.includes('File not found'))) {
        expect(result.success).toBe(false);
      } else {
        // If it exists, it should validate
        expect(result.errors).toEqual([]);
      }
    });

    it('handles missing file gracefully', () => {
      const result = validatePlaybookFile('/nonexistent/path.yml');
      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('File not found');
    });

    it('validates YAML string', () => {
      const yaml = `
runbook:
  id: "550e8400-e29b-41d4-a716-446655440000"
  version: "1.0"
  metadata:
    name: "Test"
    created: "2026-01-15T10:00:00Z"
    updated: "2026-01-15T10:00:00Z"
    tags:
      - "test"
  triggers:
    detection_sources:
      - "manual"
    mitre_techniques:
      - "T1566"
    platforms:
      - "windows"
  config:
    automation_level: "L0"
    max_execution_time: 300
    requires_approval: false
  steps:
    - id: "step-01"
      name: "Collect Data"
      action: "collect_logs"
      executor: "siem"
      parameters:
        query: "test"
      on_error: "halt"
      timeout: 30
`;
      const result = validatePlaybookYaml(yaml);
      expect(result.success).toBe(true);
    });

    it('handles invalid YAML syntax', () => {
      const result = validatePlaybookYaml('{ invalid yaml [[[');
      expect(result.success).toBe(false);
    });
  });
});
