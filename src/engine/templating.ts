/**
 * Parameter Templating Engine
 *
 * Resolves {{ variable }} placeholders in playbook step parameters.
 * Supports dot-notation paths into alert data, step outputs,
 * context variables, and environment variables.
 *
 * Template syntax:
 *   {{ alert.host.hostname }}         - Alert field reference
 *   {{ steps.step-01.output.score }}  - Previous step output
 *   {{ context.analyst_email }}       - Context variable
 *   {{ env.VIRUSTOTAL_API_KEY }}      - Environment variable
 *   {{ value | default: fallback }}   - Default values
 *
 * @module engine/templating
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TemplateContext {
  alert?: Record<string, unknown>;
  steps?: Record<string, { output?: unknown }>;
  context?: Record<string, unknown>;
  env?: Record<string, string | undefined>;
}

export interface TemplateResult {
  resolved: unknown;
  unresolvedPaths: string[];
}

// ---------------------------------------------------------------------------
// Template Pattern
// ---------------------------------------------------------------------------

/**
 * Matches {{ path }} and {{ path | default: value }}
 */
const TEMPLATE_REGEX = /\{\{\s*([^}|]+?)(?:\s*\|\s*default:\s*(.+?))?\s*\}\}/g;

// ---------------------------------------------------------------------------
// Deep Access
// ---------------------------------------------------------------------------

/**
 * Access a nested value via dot-notation path.
 * Returns undefined if any segment is missing.
 */
function deepGet(obj: unknown, path: string): unknown {
  const segments = path.split('.');
  let current: unknown = obj;

  for (const segment of segments) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

/**
 * Resolve a variable path against the template context.
 */
function resolveVariable(path: string, ctx: TemplateContext): unknown {
  const trimmed = path.trim();

  // Route by prefix
  if (trimmed.startsWith('alert.')) {
    return deepGet(ctx.alert, trimmed.slice('alert.'.length));
  }
  if (trimmed.startsWith('steps.')) {
    return deepGet(ctx.steps, trimmed.slice('steps.'.length));
  }
  if (trimmed.startsWith('context.')) {
    return deepGet(ctx.context, trimmed.slice('context.'.length));
  }
  if (trimmed.startsWith('env.')) {
    const envKey = trimmed.slice('env.'.length);
    return ctx.env?.[envKey] ?? process.env[envKey];
  }

  // Fall through: try alert, then context, then steps
  const fromAlert = deepGet(ctx.alert, trimmed);
  if (fromAlert !== undefined) return fromAlert;

  const fromContext = deepGet(ctx.context, trimmed);
  if (fromContext !== undefined) return fromContext;

  return undefined;
}

/**
 * Parse a default value string to a typed value.
 */
function parseDefault(value: string): unknown {
  const trimmed = value.trim();

  // Quoted string
  if (
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('"') && trimmed.endsWith('"'))
  ) {
    return trimmed.slice(1, -1);
  }

  // Number
  const num = Number(trimmed);
  if (!isNaN(num) && trimmed !== '') return num;

  // Boolean
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (trimmed === 'null') return null;

  // Plain string
  return trimmed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve all {{ }} templates in a string.
 * Returns the resolved string and any unresolved paths.
 */
export function resolveTemplateString(
  template: string,
  ctx: TemplateContext,
): TemplateResult {
  const unresolvedPaths: string[] = [];

  const resolved = template.replace(TEMPLATE_REGEX, (_match, path: string, defaultValue?: string) => {
    const value = resolveVariable(path, ctx);

    if (value !== undefined && value !== null) {
      return String(value);
    }

    if (defaultValue !== undefined) {
      const parsed = parseDefault(defaultValue);
      return String(parsed);
    }

    unresolvedPaths.push(path.trim());
    return '';
  });

  return { resolved, unresolvedPaths };
}

/**
 * Recursively resolve templates in any value (string, object, array).
 * Non-string values pass through unchanged.
 */
export function resolveTemplates(
  value: unknown,
  ctx: TemplateContext,
): TemplateResult {
  if (typeof value === 'string') {
    // Check if the entire string is a single template expression
    const singleMatch = /^\{\{\s*([^}|]+?)(?:\s*\|\s*default:\s*(.+?))?\s*\}\}$/.exec(value);
    if (singleMatch) {
      const path = singleMatch[1]!;
      const defaultValue = singleMatch[2];
      const resolved = resolveVariable(path, ctx);

      if (resolved !== undefined && resolved !== null) {
        return { resolved, unresolvedPaths: [] };
      }
      if (defaultValue !== undefined) {
        return { resolved: parseDefault(defaultValue), unresolvedPaths: [] };
      }
      return { resolved: '', unresolvedPaths: [path.trim()] };
    }

    return resolveTemplateString(value, ctx);
  }

  if (Array.isArray(value)) {
    const allUnresolved: string[] = [];
    const resolvedArray = value.map((item) => {
      const result = resolveTemplates(item, ctx);
      allUnresolved.push(...result.unresolvedPaths);
      return result.resolved;
    });
    return { resolved: resolvedArray, unresolvedPaths: allUnresolved };
  }

  if (value !== null && typeof value === 'object') {
    const allUnresolved: string[] = [];
    const resolvedObj: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      const result = resolveTemplates(val, ctx);
      allUnresolved.push(...result.unresolvedPaths);
      resolvedObj[key] = result.resolved;
    }
    return { resolved: resolvedObj, unresolvedPaths: allUnresolved };
  }

  // Primitives (number, boolean, null) pass through
  return { resolved: value, unresolvedPaths: [] };
}

/**
 * Resolve templates in step parameters.
 * Convenience wrapper that returns just the resolved parameters.
 */
export function resolveStepParameters(
  parameters: Record<string, unknown>,
  ctx: TemplateContext,
): { resolved: Record<string, unknown>; unresolvedPaths: string[] } {
  const result = resolveTemplates(parameters, ctx);
  return {
    resolved: result.resolved as Record<string, unknown>,
    unresolvedPaths: result.unresolvedPaths,
  };
}
