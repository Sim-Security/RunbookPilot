/**
 * Live LLM Integration Tests
 *
 * Tests the three LLM modules (summarizer, playbook-suggester, note-generator)
 * against real OpenRouter API calls. Uses the API key from .env.
 *
 * Run with: bun run test -- tests/integration/llm-live.test.ts
 *
 * These tests are SKIPPED by default in CI (no API key). To run locally,
 * ensure OPENROUTER_API_KEY is set in your .env file.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  EnrichmentSummarizer,
  type EnrichmentData,
} from '../../src/llm/summarizer.ts';
import {
  PlaybookSuggester,
  type PlaybookDescriptor,
} from '../../src/llm/playbook-suggester.ts';
import { InvestigationNoteGenerator } from '../../src/llm/note-generator.ts';
import type { AlertEvent } from '../../src/types/ecs.ts';
import type { ExecutionResult, StepResult } from '../../src/types/playbook.ts';

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

// dotenv is loaded by vitest.config or the shell — read directly from process.env
const API_KEY = process.env.OPENROUTER_API_KEY ?? '';
const BASE_URL = process.env.OPENROUTER_BASE_URL ?? 'https://openrouter.ai/api/v1';
const MODEL = process.env.OPENROUTER_MODEL_FAST ?? 'x-ai/grok-4.1-fast';
const TIMEOUT = 30000;
const MAX_TOKENS = 1024;

const hasApiKey = API_KEY.length > 5;

// Load the real test fixture
const fixtureRaw = readFileSync(
  resolve(process.cwd(), 'tests/fixtures/ecs-alerts/basic-alert.json'),
  'utf-8',
);
const TEST_ALERT: AlertEvent = JSON.parse(fixtureRaw) as AlertEvent;

// ---------------------------------------------------------------------------
// Enrichment data (simulating what adapters would return)
// ---------------------------------------------------------------------------

const ENRICHMENTS: EnrichmentData[] = [
  {
    source: 'geoip',
    data: {
      ip: '203.0.113.50',
      country: 'Russia',
      city: 'Moscow',
      isp: 'Suspicious Hosting LLC',
      risk_score: 85,
    },
  },
  {
    source: 'virustotal',
    data: {
      hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      detections: 42,
      total_engines: 70,
      threat_label: 'Trojan.GenericKD.46842315',
      first_seen: '2026-02-09T12:00:00Z',
      tags: ['trojan', 'downloader', 'powershell'],
    },
  },
  {
    source: 'asset_inventory',
    data: {
      hostname: 'WKSTN-FIN-042',
      department: 'Finance',
      owner: 'Jane Doe (jdoe@acme.com)',
      classification: 'PCI-DSS Scope',
      last_patch: '2026-02-01',
      installed_software: ['Microsoft Office 2024', 'Chrome 122', 'Citrix Workspace'],
    },
  },
];

// ---------------------------------------------------------------------------
// Available playbooks for suggester
// ---------------------------------------------------------------------------

const PLAYBOOKS: PlaybookDescriptor[] = [
  {
    id: 'pb-powershell-001',
    name: 'Suspicious PowerShell Execution Response',
    description: 'Investigate and contain suspicious PowerShell activity including encoded commands, download cradles, and script execution from unexpected parent processes.',
    techniques: ['T1059.001', 'T1059.003'],
  },
  {
    id: 'pb-malware-001',
    name: 'Malware Containment and Eradication',
    description: 'Isolate affected host, collect forensic artifacts, quarantine malicious files, and restore from clean state.',
    techniques: ['T1204', 'T1059'],
  },
  {
    id: 'pb-phishing-001',
    name: 'Phishing Email Investigation',
    description: 'Investigate phishing emails, check sender reputation, analyze attachments, and block malicious URLs.',
    techniques: ['T1566.001', 'T1566.002'],
  },
  {
    id: 'pb-lateral-001',
    name: 'Lateral Movement Investigation',
    description: 'Investigate lateral movement activity via RDP, WMI, PsExec, or other remote execution methods.',
    techniques: ['T1021', 'T1076', 'T1047'],
  },
  {
    id: 'pb-exfil-001',
    name: 'Data Exfiltration Response',
    description: 'Detect and respond to data exfiltration attempts via DNS, HTTP, or cloud storage channels.',
    techniques: ['T1048', 'T1567'],
  },
];

// ---------------------------------------------------------------------------
// Mock execution result for note generator
// ---------------------------------------------------------------------------

const MOCK_STEPS: StepResult[] = [
  {
    step_id: 'step-01',
    step_name: 'Collect SIEM logs',
    action: 'query_siem',
    success: true,
    started_at: '2026-02-11T14:32:10.000Z',
    completed_at: '2026-02-11T14:32:25.000Z',
    duration_ms: 15000,
    output: { events_found: 47, earliest: '2026-02-11T14:30:00Z' },
  },
  {
    step_id: 'step-02',
    step_name: 'Check file reputation',
    action: 'check_reputation',
    success: true,
    started_at: '2026-02-11T14:32:25.000Z',
    completed_at: '2026-02-11T14:32:40.000Z',
    duration_ms: 15000,
    output: { verdict: 'malicious', detections: 42, engines: 70 },
  },
  {
    step_id: 'step-03',
    step_name: 'Isolate host',
    action: 'isolate_host',
    success: true,
    started_at: '2026-02-11T14:32:40.000Z',
    completed_at: '2026-02-11T14:33:10.000Z',
    duration_ms: 30000,
    output: { isolated: true, host: 'WKSTN-FIN-042' },
  },
  {
    step_id: 'step-04',
    step_name: 'Create incident ticket',
    action: 'create_ticket',
    success: true,
    started_at: '2026-02-11T14:33:10.000Z',
    completed_at: '2026-02-11T14:33:45.000Z',
    duration_ms: 35000,
    output: { ticket_id: 'INC-2026-0211-001' },
  },
];

const MOCK_EXECUTION_RESULT: ExecutionResult = {
  execution_id: 'exec-live-test-001',
  runbook_id: 'pb-powershell-001',
  success: true,
  state: 'completed',
  started_at: '2026-02-11T14:32:10.000Z',
  completed_at: '2026-02-11T14:33:45.000Z',
  duration_ms: 95000,
  steps_executed: MOCK_STEPS,
  metrics: {
    total_steps: 4,
    successful_steps: 4,
    failed_steps: 0,
    skipped_steps: 0,
    rollbacks_triggered: 0,
    duration_ms: 95000,
  },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!hasApiKey)('Live LLM Integration', () => {
  // ── Summarizer ──────────────────────────────────────────────────────────

  describe('EnrichmentSummarizer (real API)', () => {
    it('summarizes enrichment data for a real alert', async () => {
      const summarizer = new EnrichmentSummarizer({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });

      const result = await summarizer.summarize(TEST_ALERT, ENRICHMENTS);

      console.log('\n--- Summarizer Result ---');
      console.log('Success:', result.success);
      console.log('Duration:', result.duration_ms, 'ms');
      console.log('Summary:', result.summary);
      console.log('Key Findings:', result.key_findings);
      if (result.error) console.log('Error:', result.error);
      console.log('------------------------\n');

      expect(result.success).toBe(true);
      expect(result.summary).toBeDefined();
      expect(result.summary!.length).toBeGreaterThan(20);
      expect(result.duration_ms).toBeGreaterThan(0);
      expect(result.error).toBeUndefined();
    }, TIMEOUT + 5000);
  });

  // ── Playbook Suggester ────────────────────────────────────────────────

  describe('PlaybookSuggester (real API)', () => {
    it('suggests relevant playbooks for a real alert', async () => {
      const suggester = new PlaybookSuggester({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });

      const result = await suggester.suggest(TEST_ALERT, PLAYBOOKS);

      console.log('\n--- Suggester Result ---');
      console.log('Success:', result.success);
      console.log('Duration:', result.duration_ms, 'ms');
      if (result.suggestions) {
        for (const s of result.suggestions) {
          console.log(
            `  ${s.playbook_id}: ${(s.confidence * 100).toFixed(0)}% — ${s.justification}`,
          );
        }
      }
      if (result.error) console.log('Error:', result.error);
      console.log('------------------------\n');

      expect(result.success).toBe(true);
      expect(result.suggestions).toBeDefined();
      expect(result.suggestions!.length).toBeGreaterThan(0);

      // The top suggestion should be the PowerShell playbook (T1059.001 match)
      const topSuggestion = result.suggestions![0]!;
      expect(topSuggestion.playbook_id).toBe('pb-powershell-001');
      expect(topSuggestion.confidence).toBeGreaterThan(0.5);
      expect(topSuggestion.justification.length).toBeGreaterThan(5);

      // All suggestions should have valid playbook IDs
      for (const s of result.suggestions!) {
        expect(PLAYBOOKS.some((p) => p.id === s.playbook_id)).toBe(true);
        expect(s.confidence).toBeGreaterThanOrEqual(0);
        expect(s.confidence).toBeLessThanOrEqual(1);
      }
    }, TIMEOUT + 5000);
  });

  // ── Note Generator ────────────────────────────────────────────────────

  describe('InvestigationNoteGenerator (real API)', () => {
    it('generates investigation notes from real execution data', async () => {
      const generator = new InvestigationNoteGenerator({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });

      const enrichmentSummary =
        'GeoIP shows destination IP 203.0.113.50 is in Moscow, Russia (Suspicious Hosting LLC). ' +
        'VirusTotal reports 42/70 detections for the payload hash, classified as Trojan.GenericKD. ' +
        'The affected host WKSTN-FIN-042 is in the Finance department under PCI-DSS scope.';

      const result = await generator.generate(
        TEST_ALERT,
        MOCK_EXECUTION_RESULT,
        enrichmentSummary,
      );

      console.log('\n--- Note Generator Result ---');
      console.log('Success:', result.success);
      console.log('Duration:', result.duration_ms, 'ms');
      if (result.notes) {
        console.log('Notes (first 500 chars):', result.notes.substring(0, 500));
      }
      console.log('Timeline items:', result.timeline?.length ?? 0);
      console.log('Recommendations:', result.recommendations?.length ?? 0);
      if (result.error) console.log('Error:', result.error);
      console.log('----------------------------\n');

      expect(result.success).toBe(true);
      expect(result.notes).toBeDefined();
      expect(result.notes!.length).toBeGreaterThan(50);
      expect(result.duration_ms).toBeGreaterThan(0);
      expect(result.error).toBeUndefined();
    }, TIMEOUT + 5000);
  });

  // ── Full pipeline: summarize → suggest → generate notes ───────────────

  describe('Full LLM Pipeline (real API)', () => {
    it('runs all three LLM modules sequentially on the same alert', async () => {
      // 1. Summarize enrichments
      const summarizer = new EnrichmentSummarizer({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });
      const summaryResult = await summarizer.summarize(TEST_ALERT, ENRICHMENTS);
      expect(summaryResult.success).toBe(true);

      // 2. Suggest playbooks
      const suggester = new PlaybookSuggester({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });
      const suggestResult = await suggester.suggest(TEST_ALERT, PLAYBOOKS);
      expect(suggestResult.success).toBe(true);

      // 3. Generate investigation notes (using the real summary from step 1)
      const generator = new InvestigationNoteGenerator({
        baseUrl: BASE_URL,
        apiKey: API_KEY,
        model: MODEL,
        timeout: TIMEOUT,
        maxTokens: MAX_TOKENS,
      });
      const notesResult = await generator.generate(
        TEST_ALERT,
        MOCK_EXECUTION_RESULT,
        summaryResult.summary,
      );
      expect(notesResult.success).toBe(true);

      // Print the full pipeline results
      console.log('\n========== FULL LLM PIPELINE RESULTS ==========');
      console.log('\n[1] ENRICHMENT SUMMARY:');
      console.log(summaryResult.summary);
      if (summaryResult.key_findings?.length) {
        console.log('\nKey findings:');
        for (const f of summaryResult.key_findings) {
          console.log(`  - ${f}`);
        }
      }

      console.log('\n[2] PLAYBOOK SUGGESTIONS:');
      for (const s of suggestResult.suggestions!) {
        console.log(
          `  ${(s.confidence * 100).toFixed(0)}%  ${s.playbook_id} — ${s.justification}`,
        );
      }

      console.log('\n[3] INVESTIGATION NOTES:');
      console.log(notesResult.notes);

      console.log('\n[TIMING]');
      console.log(`  Summarizer:  ${summaryResult.duration_ms}ms`);
      console.log(`  Suggester:   ${suggestResult.duration_ms}ms`);
      console.log(`  Notes:       ${notesResult.duration_ms}ms`);
      console.log(
        `  Total:       ${summaryResult.duration_ms + suggestResult.duration_ms + notesResult.duration_ms}ms`,
      );
      console.log('================================================\n');

      // Validate the complete pipeline produced meaningful output
      expect(summaryResult.summary!.length).toBeGreaterThan(20);
      expect(suggestResult.suggestions!.length).toBeGreaterThan(0);
      expect(notesResult.notes!.length).toBeGreaterThan(50);
    }, TIMEOUT * 3 + 10000);
  });
});
