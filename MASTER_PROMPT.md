# RunbookPilot: Build to Completion

## Context & Motivation

RunbookPilot is an open-source, AI-assisted SOC runbook automation platform with graduated autonomy (L0/L1/L2) and mandatory human-in-the-loop controls. It is the **response half** of a detection-to-response pipeline — its companion project, DetectForge (complete, 1,617 tests, production-ready), handles detection rule generation from threat intelligence.

Together, these projects demonstrate end-to-end detection engineering capability: threat report → validated detection rules → automated incident response. This is a portfolio-grade project that showcases senior detection engineer skills.

**Why this matters:** The SOAR market is dying (Gartner discontinued the Magic Quadrant in 2024). Small SOC teams need affordable automation between manual runbooks and $250K/yr enterprise SOAR. RunbookPilot fills that gap with safety-first design: deterministic state machine execution, LLM enrichment only (never decisions), mandatory approval gates, and mandatory rollback definitions.

**Repository:** https://github.com/Sim-Security/RunbookPilot.git

---

## Background

### Current State
- All specification documents complete: PRD (1,023 lines), Architecture (2,710 lines), Sprint Backlog (1,367 lines, 73 tickets), Technical Reference (3,000+ lines)
- Six research documents validated: DetectForge architecture review, SOAR competitive analysis, runbook best practices, HITL optimization, red team analysis, council debate
- **Zero source code exists** — ready for S0 Foundation Sprint

### Architecture Decisions (Locked)
- **Runtime:** Bun + TypeScript (strict mode) + Vitest
- **CLI:** Commander.js
- **Database:** SQLite (operational.db, audit.db, metrics.db)
- **Schema Validation:** Zod
- **LLM Gateway:** OpenRouter (model-agnostic, any model via single API)
- **Event Format:** ECS (Elastic Common Schema)
- **Deployment:** Docker Compose
- **State Machine:** Deterministic, no ML/LLM in execution path
- **Autonomy:** L0 (manual checklist) → L1 (semi-auto, approval-gated writes) → L2 (simulation-only in v1)

### Reference Documents
Read these documents before implementing each sprint. They contain the complete specification:
- `docs/PRD.md` — User stories, personas, functional requirements
- `docs/ARCHITECTURE.md` — Component design, data flows, state machine, security architecture
- `docs/SPRINT_BACKLOG.md` — All 73 tickets with acceptance criteria
- `docs/TECHNICAL_REFERENCE.md` — TypeScript types, YAML schema, SQLite schemas, CLI commands, error codes

### Research Documents
These contain validated analysis that informs implementation decisions:
- `research/01_detectforge_architecture_review.md` — DetectForge design patterns to mirror, integration checklist
- `research/02_soar_competitive_analysis.md` — SOAR landscape analysis (Palo Alto, Splunk, Swimlane), market positioning
- `research/03_runbook_best_practices.md` — CACAO, MITRE, incident response patterns
- `research/04_hitl_gap9_research.md` — Human-in-the-loop security operations literature, approval fatigue mitigation
- `research/05_redteam_analysis.md` — 8 engineer adversarial perspectives on 24 claims, technical viability
- `research/06_council_debate.md` — Hiring manager perspective, architectural tradeoff decisions

---

## Execution Engine: THE ALGORITHM (DETERMINED + RALPH Mode)

### Effort Level: DETERMINED
All capabilities unlocked. Unlimited iterations until success. Use every available resource.

### RALPH Mode: Persistent Iteration
Activate a Ralph Loop for each sprint. The loop re-executes the sprint prompt until the completion promise is met. Heavier sprints get more iterations:

| Sprint | Tickets | Max Iterations |
|--------|---------|----------------|
| S0 | 12 | 25 |
| S1 | 14 | 50 |
| S2 | 12 | 25 |
| S3 | 11 | 25 |
| S4 | 14 | 50 |
| S5 | 11 | 30 |

```bash
bun run ~/.claude/skills/THEALGORITHM/Tools/RalphLoopExecutor.ts \
  --prompt "Complete Sprint S{N} for RunbookPilot" \
  --completion-promise "All S{N} tests pass, coverage >80%, all acceptance criteria met" \
  --max-iterations {see table above}
```

### ISC Scale: 200-1000+ Rows
This is a DETERMINED-level project. The ISC expands with every research finding, edge case, and verification criterion. Each sprint generates 30-50+ ISC rows from explicit requirements, inferred standards, implicit quality bars, and discovered edge cases.

### Seven Phases Per Sprint

| Phase | Action | Gate |
|-------|--------|------|
| OBSERVE | Read sprint tickets from SPRINT_BACKLOG.md, read ARCHITECTURE.md and TECHNICAL_REFERENCE.md for relevant specs | All ticket acceptance criteria captured in ISC? |
| CONSIDER | First Principles analysis on sprint scope. Council debate on architectural tradeoffs. Red Team the sprint deliverables. | ISC refined with edge cases, anti-patterns, security concerns? |
| PLAN | Sequence tickets by dependency. Assign parallel agent groups. Map verification methods. | Dependencies mapped? Capabilities assigned? |
| BUILD | Refine ISC rows to be individually testable | Each row has specific verification criteria? |
| EXECUTE | Implement using parallel agents. Write code, tests, and documentation. | Every ISC row has a final status? |
| VERIFY | Run all tests. Skeptical verification agent reviews each completion. Run `bun run test`. | All tests pass? Coverage >80%? |
| LEARN | Commit sprint. Tag release. Report results for rating. | Sprint gate checklist complete? |

---

## Instructions

Execute these sprints sequentially. Each sprint is a RALPH loop that iterates until all acceptance criteria pass.

### Sprint S0: Foundation (12 Tickets)

1. **Initialize project** with `bun init`, TypeScript strict mode, folder structure: `src/`, `tests/`, `docs/`, `scripts/`, `adapters/`, `playbooks/`
2. **Configure Vitest** with `@vitest/coverage-v8`, 80%+ coverage threshold, scripts: `test`, `test:watch`, `test:coverage`
3. **Set up Commander.js CLI** with commands: `run`, `validate`, `list`, `version` and global flags: `--verbose`, `--dry-run`, `--automation-level`, `--enable-l2`
4. **Define YAML playbook schema** covering metadata, triggers, steps, actions, rollback, approval_policy. Document in `docs/PLAYBOOK_SCHEMA.md`. Create example playbook at `playbooks/examples/basic.yml`
5. **Create TypeScript types** in `src/types/`: Playbook, Metadata, Trigger, Step, Action, RollbackConfig, ApprovalPolicy, AutomationLevel, ErrorHandlingMode, StepStatus
6. **Implement Zod schema validator** in `src/validators/playbook-validator.ts` matching TypeScript types with detailed error messages
7. **Define ECS event types** in `src/types/ecs.ts`: core ECS fields, alert-specific fields, DetectForge metadata (`x-detectforge.*`)
8. **Build configuration system** in `src/config/index.ts`: load from env + optional `config.yml`, validate at startup, redact secrets from logs
9. **Implement structured logging** with pino: JSON format, log levels, correlation IDs, sensitive data redaction
10. **Set up SQLite** with better-sqlite3: schema for `executions`, `audit_logs`, `approval_queue`, migration system, configurable path
11. **Configure GitHub Actions CI** in `.github/workflows/ci.yml`: checkout, install Bun, lint, test, coverage upload
12. **Create Docker setup**: multi-stage Dockerfile with Bun base, `docker-compose.yml` with volume mounts

**S0 Completion Promise:** `bun run test` passes, all 12 ticket acceptance criteria met, foundation infrastructure operational.

**S0 Gate Checklist:**
- [ ] `bun run test` — all tests pass
- [ ] `bun run test:coverage` — >80% coverage
- [ ] `bun run cli -- --help` — CLI displays help
- [ ] `bun run cli -- validate playbooks/examples/basic.yml` — validates example playbook
- [ ] SQLite databases initialize without errors
- [ ] Docker builds successfully
- [ ] CI pipeline runs green

### Sprint S1: Execution Engine L0-L1 (14 Tickets)

1. **State machine** in `src/engine/state-machine.ts`: states (idle, planning, awaiting_approval, executing, completed, failed, rolled_back), transition guards, persistence to SQLite, event emitter
2. **Execution context manager** in `src/engine/context.ts`: stores input event, step outputs, metadata. Copy-on-write immutability. JSON serialization. Resume from database.
3. **Parameter templating engine** in `src/engine/templating.ts`: `{{ alert.host_id }}` interpolation, filters, conditionals, missing variable handling
4. **L0 executor** in `src/engine/executors/l0-executor.ts`: display checklist, show templated action details, prompt for manual confirmation, record in audit log
5. **Action classifier** in `src/engine/action-classifier.ts`: read-only (query, enrich, display, log) vs write (isolate, block, quarantine, delete, modify). Unknown defaults to write.
6. **L1 executor** in `src/engine/executors/l1-executor.ts`: auto-execute read-only, prompt approval for writes, display context before approval, configurable timeout
7. **Approval gate manager** in `src/engine/approval-gate.ts`: configurable timeout (default 5 min), timeout behavior (skip/halt/auto-approve), audit trail
8. **Step executor** in `src/engine/step-executor.ts`: execute via adapter, apply templating, error handling modes (halt/continue/skip), timeout per step
9. **Rollback engine** in `src/engine/rollback.ts`: reverse-order execution, best-effort error handling, status tracking, separate audit logging
10. **Playbook loader** in `src/engine/playbook-loader.ts`: YAML loading, schema validation, parsing to typed Playbook object, error handling
11. **Orchestrator** in `src/engine/orchestrator.ts`: coordinates loading, validation, context init, executor selection (L0/L1/L2), state machine transitions, lifecycle management (start/pause/resume/cancel), persistence
12. **Audit log writer** in `src/engine/audit-logger.ts`: append-only with SHA-256 chain hashing, logs every action/approval/state transition, export to JSON/CSV
13. **Execution history storage** in `src/db/execution-repository.ts`: CRUD operations, query by playbook/date/status
14. **Integration tests**: full L0 execution, full L1 with read/write actions, approval flows (approve/reject/timeout), error handling modes, rollback, resume after pause, concurrent execution

**S1 Completion Promise:** All state machine transitions verified, L0 and L1 executors functional end-to-end, approval gates enforce human oversight, rollback works correctly.

**S1 Gate Checklist:**
- [ ] State machine handles all valid transitions and rejects invalid ones
- [ ] L0 displays checklist and records manual completions
- [ ] L1 auto-executes read-only actions and gates write actions
- [ ] Approval timeouts trigger configured behavior
- [ ] Rollback executes in reverse order on failure
- [ ] Execution state persists to SQLite and recovers from crash
- [ ] `bun run test` — all tests pass, coverage >80%

### Sprint S2: Adapter Layer (12 Tickets)

1. **Adapter interface** in `src/adapters/adapter-interface.ts`: methods `execute()`, `validate()`, `getCapabilities()`, `healthCheck()`, with result types and timeout/retry config
2. **Adapter registry** in `src/adapters/registry.ts`: auto-discover from `adapters/` directory, lazy loading, CLI listing
3. **Mock adapter framework** in `src/adapters/mock/`: configurable success/failure, latency simulation, call recording for assertions
4. **IP block adapter** (firewall): `block_ip`, `unblock_ip`, `check_ip_status` — mock and real API modes
5. **Host isolation adapter** (EDR): `isolate_host`, `unisolate_host`, `get_isolation_status` — hostname-to-ID resolution
6. **Log collection adapter** (SIEM): `query_logs`, `get_events_by_id` — time range and field filters, ECS format output
7. **VirusTotal enrichment adapter**: `enrich_hash`, `enrich_domain`, `enrich_ip`, `enrich_url` — VT API v3, rate limiting
8. **Process tree adapter** (EDR): `get_process_tree`, `get_process_details` — parent/child relationships, command lines, hashes
9. **Notification adapter** (Slack/Email): `send_slack_message`, `send_email` — webhook and SMTP, message templating
10. **Adapter error handling** in `src/adapters/error-handler.ts`: typed errors (Auth, Timeout, RateLimit, NotFound, API), exponential backoff retry, circuit breaker
11. **Adapter configuration**: per-adapter config from `config.yml` or env vars, namespaced settings, secret management
12. **Integration tests**: each adapter action success, error handling (auth/timeout/rate limit), retry logic, registration/discovery, concurrent calls

**S2 Completion Promise:** All adapters implement the interface, mock mode works for all actions, error handling covers all failure modes, registry discovers and manages adapters.

**S2 Gate Checklist:**
- [ ] All adapters implement `ActionAdapter` interface
- [ ] Mock adapters return configurable responses
- [ ] Error handler retries transient failures with backoff
- [ ] Circuit breaker opens after repeated failures
- [ ] Adapter registry auto-discovers adapters
- [ ] `bun run test` — all tests pass, coverage >80%

### Sprint S3: L2 Simulation Mode (11 Tickets)

1. **SimulationResult types** in `src/types/simulation.ts`: distinct from ExecutionResult, includes impact_assessment, confidence, risk_score
2. **L2 executor** in `src/engine/executors/l2-executor.ts`: read-only actions normal, write actions dry-run via adapter, impact assessment, approval queue storage, requires `--enable-l2` flag
3. **Approval queue storage** in `src/db/approval-queue-repository.ts`: CRUD, status lifecycle (pending/approved/rejected/executed/expired), TTL for auto-expiry
4. **Dry-run mode for all adapters**: validate parameters without executing, return simulated results, estimate impact
5. **Impact assessment engine** in `src/engine/impact-assessor.ts`: blast radius, risk score (1-10), dependency identification, human-readable summary
6. **Policy enforcement** in `src/engine/policy-enforcer.ts`: automation level checks per step, L2 blocked without `--enable-l2`, approval validation, policy violation logging
7. **Confidence scoring display**: extract `x-detectforge.confidence`, color-code, include detection provenance, graceful fallback
8. **One-click execution from queue**: `runbookpilot approve <id>` command, retrieve simulation, execute in L1 mode, update queue status, bulk approve
9. **Simulation metrics**: total simulations, approval rate, average latency, action type distribution, false positive tracking
10. **Simulation audit logging**: distinguishes simulation from real execution, logs all simulated actions and approval decisions
11. **Integration tests**: full L2 simulation, approval queue population, one-click execution, dry-run for all adapters, impact assessment, policy enforcement, concurrent simulations

**S3 Completion Promise:** L2 simulation generates complete action plans without executing, approval queue enables one-click execution, policy enforcement prevents unauthorized execution.

**S3 Gate Checklist:**
- [ ] L2 executor simulates write actions without side effects
- [ ] Approval queue stores simulations with correct lifecycle (pending→approved→executed)
- [ ] `--enable-l2` flag required — execution blocked without it
- [ ] Impact assessment produces risk scores and human-readable summaries
- [ ] One-click approval converts simulation to real L1 execution
- [ ] Policy enforcer blocks unauthorized automation level escalation
- [ ] Dry-run mode works for all write adapters
- [ ] `bun run test` — all tests pass, coverage >80%

### Sprint S4: Reference Runbooks & Integration (14 Tickets)

1. **LSASS Credential Dumping playbook (L0)**: `playbooks/lsass-credential-dumping-l0.yml` — T1003.001, manual checklist mode
2. **WMI Lateral Movement playbook (L1)**: `playbooks/wmi-lateral-movement-l1.yml` — T1047, semi-auto with approval gates, rollback (un-isolate)
3. **Cobalt Strike C2 playbook (L2)**: `playbooks/cobalt-strike-c2-l2.yml` — T1071.001, full simulation with one-click approval
4. **Webhook receiver** in `src/ingest/webhook-receiver.ts`: HTTP server, `POST /api/v1/alerts`, validate `x-detectforge` metadata, parse ECS, trigger playbook execution
5. **ATT&CK technique-to-playbook mapping** in `src/engine/playbook-matcher.ts`: mapping file `config/technique-playbook-map.yml`, multi-playbook per technique, fallback
6. **STDIN/file ingestion**: `--input <file>` and piped STDIN, ECS validation, batch processing
7. **Docker Compose integration**: `docker-compose.integration.yml` with DetectForge + RunbookPilot, shared volumes, documentation
8. **Trigger condition evaluator** in `src/engine/trigger-evaluator.ts`: operators (==, !=, >, <, in, contains, matches), boolean logic (and, or, not)
9. **Playbook metadata enrichment**: name, description, version, ATT&CK techniques, MITRE D3FEND, searchable, included in execution logs
10. **Playbook library CLI**: `list`, `show <playbook>`, `search <term>`, `validate <playbook>` — table and JSON output
11. **Alert enrichment pipeline** in `src/engine/enrichment-pipeline.ts`: GeoIP, asset inventory, user directory, threat intel — failures non-blocking
12. **Execution timeout/cancellation**: configurable per-playbook timeout, `cancel <execution-id>` command, triggers rollback, graceful adapter termination
13. **Playbook documentation**: `docs/playbooks/` for each reference playbook — threat description, logic, rationale, rollback strategy, sample alerts
14. **Integration tests**: E2E for each playbook, webhook ingestion, STDIN ingestion, technique mapping, Docker Compose integration

**S4 Completion Promise:** Three reference playbooks execute end-to-end (L0, L1, L2), DetectForge integration works via webhook and file handoff, playbook matching selects correct response.

**S4 Gate Checklist:**
- [ ] LSASS playbook (L0) runs end-to-end with sample ECS alert
- [ ] WMI playbook (L1) auto-enriches and gates isolation with approval
- [ ] Cobalt Strike playbook (L2) simulates block/quarantine with one-click execution
- [ ] Webhook receiver accepts `POST /api/v1/alerts` and triggers matching playbook
- [ ] STDIN ingestion: `echo '{"alert":...}' | runbookpilot run` works
- [ ] ATT&CK technique mapping resolves T1003.001, T1047, T1071.001 to correct playbooks
- [ ] Trigger evaluator filters alerts by severity/platform conditions
- [ ] `runbookpilot list` and `runbookpilot search` return playbook metadata
- [ ] Execution timeout and `cancel` command work with rollback
- [ ] `bun run test` — all tests pass, coverage >80%

### Sprint S5: Dashboard & Polish (11 Tickets)

1. **Execution metrics** in `src/metrics/collector.ts`: total executions, success rate, avg duration, MTTD/MTTR, aggregated by playbook/technique/level
2. **Approval latency metrics**: avg/median/P95 latency, breakdown by action type and playbook
3. **Playbook coverage metrics**: techniques with playbooks / total techniques, gap identification, usage frequency
4. **CLI metrics dashboard**: `runbookpilot metrics` command, sections (Execution Stats, MTTD/MTTR, Approval Latency, Coverage), time range filters, JSON/CSV export
5. **Approval queue CLI**: `runbookpilot queue` command, interactive approve/reject, bulk operations, filtering, pagination
6. **LLM enrichment summarization** via OpenRouter: summarize process trees, VT results, log queries — 2-3 sentence summaries, graceful fallback when unavailable
7. **LLM playbook suggestion**: suggest playbooks from alert context when no technique match, provide justification, accept/reject
8. **LLM investigation notes**: auto-generate markdown notes from execution context — timeline, actions, findings, recommendations
9. **Error handling polish**: clear actionable messages, network retry, rate limit handling, sanitized user-facing errors
10. **Performance optimization**: parallel independent steps, adapter pooling/caching, DB index optimization, <30s typical playbook execution
11. **README.md generation**: quick start guide, architecture overview diagram, CLI usage examples, DetectForge integration instructions, contributing guide, badge for CI status and coverage

**S5 Completion Promise:** Metrics dashboard displays operational data, LLM enrichment provides analyst assistance with graceful degradation, all error messages are actionable, performance targets met, README.md complete.

**S5 Gate Checklist:**
- [ ] `runbookpilot metrics` displays execution stats, MTTD/MTTR, approval latency, coverage
- [ ] `runbookpilot queue` lists pending approvals with interactive approve/reject
- [ ] LLM summarization produces 2-3 sentence enrichment summaries via OpenRouter
- [ ] LLM gracefully degrades when OpenRouter is unavailable (deterministic fallback)
- [ ] All error messages are actionable with remediation steps (no raw stack traces)
- [ ] Typical playbook execution completes in <30 seconds
- [ ] README.md contains quick start, architecture diagram, CLI reference, integration guide
- [ ] `bun run test` — all tests pass, coverage >80%
- [ ] `bun run typecheck` — zero type errors
- [ ] `bun run lint` — zero warnings

---

## Multi-Agent Strategy

### Parallel Agent Deployment Per Sprint

Use Task tool with specialized subagent types for parallel work within each sprint:

| Agent Role | Responsibility | Parallel? |
|------------|---------------|-----------|
| **Architect** | Review sprint scope, identify cross-cutting concerns, validate interface contracts | First (blocking) |
| **Engineer x3** | Implement tickets in parallel groups based on dependency graph | Yes (parallel) |
| **QA** | Write tests for each ticket as implementation completes | Parallel with Engineers |
| **Security Reviewer** | Review adapter code, credential handling, input validation, audit trail integrity | After implementation |
| **Skeptical Verifier** | Run all tests, verify each acceptance criterion independently, challenge completions | After QA |

### Agent Coordination Pattern

```
Sprint Start
├─ Architect: Review scope, plan parallelization
├─ Parallel Group A: Independent tickets (no dependencies)
├─ Parallel Group B: Tickets depending on Group A
├─ QA: Tests written alongside implementation
├─ Security Review: Post-implementation security scan
├─ Skeptical Verifier: Independently verify all claims
└─ Sprint Gate: All checks pass → next sprint
```

---

## Quality Gates

### Per-Sprint Verification

After each sprint, before proceeding:

1. **Test Execution**: Run `bun run test` — all tests pass
2. **Coverage Check**: Run `bun run test:coverage` — >80% threshold
3. **Type Safety**: Run `bun run typecheck` (tsc --noEmit) — zero errors
4. **Lint Check**: Run `bun run lint` — zero warnings
5. **Integration Test**: Run sprint-specific E2E scenarios
6. **Security Review**: Check for injection, credential exposure, audit trail gaps
7. **Git Commit**: Commit sprint with descriptive message, push to remote

### Red Team Gate (After S1, S3, S5)

Invoke Red Team analysis at three critical junctures:
- **After S1** (Execution Engine): Can the state machine be bypassed? Can approvals be circumvented? Can audit logs be tampered with?
- **After S3** (L2 Simulation): Can simulation mode accidentally execute real actions? Can the approval queue be manipulated? Can policy enforcement be bypassed?
- **After S5** (Final): Full adversarial review of the complete system. OWASP Top 10 for CLI tools. Credential handling audit.

### Council Debate Gate (After S0, S2, S4)

Invoke Council debate at three design junctures:
- **After S0** (Foundation): Are the schema decisions correct? Is the type system complete? Are there missing configuration options?
- **After S2** (Adapters): Is the adapter interface flexible enough? Are error handling patterns consistent? Is the mock framework sufficient for testing?
- **After S4** (Integration): Does the DetectForge integration work cleanly? Are the reference playbooks realistic? Is the trigger evaluation robust?

### First Principles Analysis (Every Sprint)

Before each sprint begins, challenge assumptions:
- What is the root cause of each design decision?
- Can we solve this by removing complexity rather than adding it?
- Are we building the minimum viable implementation?
- Does every component earn its complexity cost?

---

## Testing Strategy

### Coverage Requirements
- **Unit tests**: Every public function, every branch, every error path
- **Integration tests**: Each sprint ends with integration test ticket
- **E2E tests**: S4 includes full end-to-end testing with all three reference playbooks
- **Edge cases**: Empty inputs, malformed YAML, missing fields, concurrent execution, timeout scenarios, rollback failures, database corruption recovery
- **Target**: >80% coverage enforced, >90% target

### Test Patterns

**State Machine Testing:**
- Every valid transition
- Every invalid transition (reject gracefully)
- State persistence and recovery
- Concurrent state modifications

**Adapter Testing:**
- Success paths for all actions
- Auth failures, timeouts, rate limits, not-found
- Retry with exponential backoff
- Circuit breaker behavior
- Dry-run mode returns simulated results

**Approval Gate Testing:**
- Approve, reject, timeout flows
- Expired approvals auto-transition
- Bulk approval operations
- Policy enforcement blocks unauthorized actions

**Audit Trail Testing:**
- Append-only verification
- SHA-256 chain integrity
- Tamper detection
- Export to all formats

### Edge Cases to Cover

- Playbook with zero steps
- Playbook with only read-only steps (no approval gates needed)
- Playbook with circular dependencies in `depends_on`
- Playbook with duplicate step IDs (reject with clear error)
- Template variable referencing undefined context
- Adapter returns after step timeout
- Adapter throws during `healthCheck()` initialization
- Rollback fails during rollback (double-failure)
- SQLite database locked during concurrent writes
- OpenRouter API unavailable (LLM graceful degradation)
- ECS alert with minimal fields (only required)
- ECS alert with all optional fields populated
- Approval granted after approval timeout expired
- L2 simulation with adapter that has no dry-run mode
- Config file missing, all values from env vars
- Config file with invalid YAML
- Docker container startup with missing env vars
- Webhook receiver receives malformed JSON body (400 response, not crash)
- Webhook receiver receives oversized payload (>10MB rejection)
- Playbook YAML with YAML bomb (excessive nesting/anchors — depth limit enforcement)

Store all test fixtures in `tests/fixtures/` with subdirectories per domain: `tests/fixtures/playbooks/`, `tests/fixtures/ecs-alerts/`, `tests/fixtures/adapter-responses/`.

---

## OpenRouter LLM Integration

All LLM calls go through OpenRouter for model-agnostic operation:

```typescript
// src/llm/openrouter-client.ts
const OPENROUTER_CONFIG = {
  baseUrl: process.env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1",
  apiKey: process.env.OPENROUTER_API_KEY,  // Required — same env var as DetectForge
  models: {
    fast: process.env.OPENROUTER_MODEL_FAST || "google/gemini-2.0-flash-001",
    standard: process.env.OPENROUTER_MODEL_STANDARD || "anthropic/claude-3.5-haiku",
    quality: process.env.OPENROUTER_MODEL_QUALITY || "anthropic/claude-sonnet-4-5-20250929"
  },
  timeout: Number(process.env.OPENROUTER_TIMEOUT) || 30000,
  maxTokens: Number(process.env.OPENROUTER_MAX_TOKENS) || 2048,
  temperature: 0.3,
  retries: 2
};
```

**Environment Variables (.env):**
```bash
OPENROUTER_API_KEY=sk-or-...          # Required — shared with DetectForge
OPENROUTER_MODEL_FAST=                 # Optional — defaults to Gemini 2.0 Flash
OPENROUTER_MODEL_STANDARD=            # Optional — defaults to Claude 3.5 Haiku
OPENROUTER_MODEL_QUALITY=             # Optional — defaults to Claude Sonnet 4.5
OPENROUTER_TIMEOUT=30000              # Optional — request timeout in ms
OPENROUTER_MAX_TOKENS=2048            # Optional — max response tokens
```

**LLM is enrichment only. It is never in the execution path.** When OpenRouter is unavailable, the system continues with deterministic-only mode. All LLM responses are optional enhancements. The `OPENROUTER_API_KEY` env var is shared with DetectForge for consistency across the pipeline.

---

## Git Operations

### Repository Setup
```bash
cd /home/ranomis/Security-Projects/RunbookPilot
git init
git remote add origin https://github.com/Sim-Security/RunbookPilot.git
```

### Branching Strategy
Match DetectForge pattern — commit directly to `main` per sprint. No feature branches for solo development. Each sprint is a single atomic commit with all tickets completed and tests passing.

```
main ──S0──S1──S2──S3──S4──S5──v1.0
```

If a sprint requires experimental work, use a local branch and squash merge back to `main` before pushing. Verify `git remote -v` points to the correct repo before every push.

### Commit Pattern
Commit after each sprint completion with descriptive messages:
```
S0: Foundation - project scaffolding, types, CLI, schema, validators, SQLite, Docker
S1: Execution engine - state machine, L0/L1 executors, approval gates, rollback
S2: Adapter layer - interface, registry, mock framework, 6 adapters, error handling
S3: L2 simulation - simulation executor, approval queue, dry-run, impact assessment
S4: Reference playbooks + DetectForge integration - 3 playbooks, webhook, mapping
S5: Dashboard & polish - metrics, LLM enrichment, README, error polish, performance
```

### Push after each sprint passes its gate checklist. Tag each sprint: `git tag s0-foundation`, `git tag s1-engine`, etc.

---

## Success Criteria

The project is complete when:

- [ ] 74 tickets implemented across 6 sprints (73 original + README.md)
- [ ] >500 passing tests (matching DetectForge quality bar)
- [ ] >80% code coverage (>90% target)
- [ ] 3 working reference playbooks (L0, L1, L2)
- [ ] DetectForge integration functional (webhook + file handoff)
- [ ] All CLI commands operational
- [ ] Docker Compose deployment works
- [ ] LLM enrichment works via OpenRouter with graceful degradation
- [ ] Audit trail immutable with SHA-256 chain verification
- [ ] Zero type errors (`tsc --noEmit`)
- [ ] README.md with quick start, architecture overview, and usage examples
- [ ] Red Team found no critical vulnerabilities
- [ ] Council validated all architectural decisions

---

## Constraints

- **Success:** All gate checklists pass, all tests green, all acceptance criteria from SPRINT_BACKLOG.md met, code pushed to GitHub.
- **Failure:** Any sprint gate fails, tests below 80% coverage, type errors exist, security vulnerabilities in Red Team review.

## Action Bias

Implement changes rather than suggesting. Read specification documents to discover exact requirements. Write code, write tests, verify with `bun run test`. Commit when green. Move to next sprint.

---

## Completion Promise

When ALL of the following are true, output: `<promise>RunbookPilot build complete: all 6 sprints pass, >500 tests green, 3 reference playbooks functional, DetectForge integration verified</promise>`

Until then, continue iterating.
