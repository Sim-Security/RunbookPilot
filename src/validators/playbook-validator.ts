import { z } from 'zod/v4';
import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';

// ---------------------------------------------------------------------------
// Zod Schemas matching TypeScript types in src/types/playbook.ts
// ---------------------------------------------------------------------------

const AutomationLevelSchema = z.enum(['L0', 'L1', 'L2']);

const StepActionSchema = z.enum([
  'isolate_host', 'restore_connectivity', 'block_ip', 'unblock_ip',
  'block_domain', 'unblock_domain',
  'collect_logs', 'query_siem', 'collect_network_traffic',
  'snapshot_memory', 'collect_file_metadata',
  'enrich_ioc', 'check_reputation', 'query_threat_feed',
  'create_ticket', 'update_ticket', 'notify_analyst', 'notify_oncall', 'send_email',
  'disable_account', 'enable_account', 'reset_password', 'revoke_session',
  'quarantine_file', 'restore_file', 'delete_file', 'calculate_hash',
  'kill_process', 'start_edr_scan', 'retrieve_edr_data',
  'execute_script', 'http_request', 'wait',
]);

const OnErrorSchema = z.enum(['halt', 'continue', 'skip']);

const DetectionSourceSchema = z.enum([
  'sigma', 'edr_alert', 'siem_correlation', 'webhook', 'manual', 'detectforge',
]);

const PlatformSchema = z.enum([
  'windows', 'linux', 'macos', 'cloud', 'network', 'saas',
]);

const SeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);

const ISO8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const UUIDRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MITRERegex = /^T\d{4}(\.\d{3})?$/;

// Rollback definition
const RollbackSchema = z.object({
  action: StepActionSchema,
  executor: z.string().optional(),
  parameters: z.record(z.string(), z.unknown()),
  timeout: z.number().int().min(5).max(600),
  on_error: OnErrorSchema.optional(),
});

// Individual step
const StepSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(3).max(100),
  description: z.string().optional(),
  action: StepActionSchema,
  executor: z.string().min(1),
  parameters: z.record(z.string(), z.unknown()),
  approval_required: z.boolean().optional(),
  rollback: RollbackSchema.optional(),
  on_error: OnErrorSchema,
  timeout: z.number().int().min(5).max(600),
  depends_on: z.array(z.string()).optional(),
  condition: z.string().optional(),
});

// Metadata
const MetadataSchema = z.object({
  name: z.string().min(3).max(100).refine(
    (s) => s === s.trim(),
    'Name must not have leading or trailing whitespace',
  ),
  description: z.string().optional(),
  author: z.string().optional(),
  created: z.string().regex(ISO8601Regex, 'Must be a valid ISO8601 timestamp'),
  updated: z.string().regex(ISO8601Regex, 'Must be a valid ISO8601 timestamp'),
  tags: z.array(z.string().min(2).max(50)).min(1).max(20),
  references: z.array(z.string().url()).optional(),
});

// Triggers
const TriggersSchema = z.object({
  detection_sources: z.array(DetectionSourceSchema).min(1),
  mitre_techniques: z.array(
    z.string().regex(MITRERegex, 'Must match pattern T####(.###)'),
  ).min(1),
  platforms: z.array(PlatformSchema).min(1),
  severity: z.array(SeveritySchema).optional(),
});

// Config
const ConfigSchema = z.object({
  automation_level: AutomationLevelSchema,
  max_execution_time: z.number().int().min(60).max(3600),
  requires_approval: z.boolean(),
  approval_timeout: z.number().int().min(300).max(7200).optional(),
  parallel_execution: z.boolean().optional(),
  rollback_on_failure: z.boolean().optional(),
});

// Full Runbook
const RunbookSchema = z.object({
  id: z.string().regex(UUIDRegex, 'Must be a valid UUID v4'),
  version: z.string().min(1),
  metadata: MetadataSchema,
  triggers: TriggersSchema,
  config: ConfigSchema,
  steps: z.array(StepSchema).min(1).max(50),
}).refine(
  (rb) => {
    // L2 must require approval
    if (rb.config.automation_level === 'L2' && !rb.config.requires_approval) {
      return false;
    }
    return true;
  },
  'L2 runbooks must have requires_approval: true',
).refine(
  (rb) => {
    // Check step ID uniqueness
    const ids = rb.steps.map((s) => s.id);
    return new Set(ids).size === ids.length;
  },
  'Step IDs must be unique within the runbook',
).refine(
  (rb) => {
    // Check depends_on references exist
    const stepIds = new Set(rb.steps.map((s) => s.id));
    for (const step of rb.steps) {
      if (step.depends_on) {
        for (const dep of step.depends_on) {
          if (!stepIds.has(dep)) {
            return false;
          }
        }
      }
    }
    return true;
  },
  'All depends_on references must point to existing step IDs',
).refine(
  (rb) => {
    // Check for circular dependencies
    const graph = new Map<string, string[]>();
    for (const step of rb.steps) {
      graph.set(step.id, step.depends_on ?? []);
    }

    const visited = new Set<string>();
    const inStack = new Set<string>();

    function hasCycle(nodeId: string): boolean {
      if (inStack.has(nodeId)) return true;
      if (visited.has(nodeId)) return false;

      visited.add(nodeId);
      inStack.add(nodeId);

      for (const dep of graph.get(nodeId) ?? []) {
        if (hasCycle(dep)) return true;
      }

      inStack.delete(nodeId);
      return false;
    }

    for (const stepId of graph.keys()) {
      if (hasCycle(stepId)) return false;
    }
    return true;
  },
  'Circular dependencies detected in step depends_on',
);

// The YAML wraps it in a `runbook:` key
const PlaybookFileSchema = z.object({
  runbook: RunbookSchema,
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ValidationResult {
  success: boolean;
  errors: string[];
  data?: z.infer<typeof RunbookSchema>;
}

/**
 * Validate a playbook object (already parsed from YAML).
 */
export function validatePlaybook(data: unknown): ValidationResult {
  const result = PlaybookFileSchema.safeParse(data);

  if (result.success) {
    return {
      success: true,
      errors: [],
      data: result.data.runbook,
    };
  }

  const errors = result.error.issues.map((issue) => {
    const path = issue.path.join('.');
    return path ? `${path}: ${issue.message}` : issue.message;
  });

  return { success: false, errors };
}

/**
 * Validate a playbook YAML file from the filesystem.
 */
export function validatePlaybookFile(filePath: string): ValidationResult {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const parsed = parseYaml(content);
    return validatePlaybook(parsed);
  } catch (error) {
    if (error instanceof Error && 'code' in error && (error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {
        success: false,
        errors: [`File not found: ${filePath}`],
      };
    }
    return {
      success: false,
      errors: [
        `Failed to parse YAML: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

/**
 * Validate a YAML string directly.
 */
export function validatePlaybookYaml(yamlContent: string): ValidationResult {
  try {
    const parsed = parseYaml(yamlContent);
    return validatePlaybook(parsed);
  } catch (error) {
    return {
      success: false,
      errors: [
        `Failed to parse YAML: ${error instanceof Error ? error.message : String(error)}`,
      ],
    };
  }
}

// Export schemas for reuse in tests
export { RunbookSchema, PlaybookFileSchema, StepSchema, MetadataSchema };
