import { describe, it, expect } from 'vitest';
import {
  classifyAction,
  isReadOnly,
  isWriteAction,
  getReadActions,
  getWriteActions,
} from '../../../src/engine/action-classifier.ts';
import type { StepAction } from '../../../src/types/playbook.ts';

describe('Action Classifier', () => {
  describe('read-only actions', () => {
    const readActions: StepAction[] = [
      'collect_logs', 'query_siem', 'collect_network_traffic',
      'snapshot_memory', 'collect_file_metadata',
      'enrich_ioc', 'check_reputation', 'query_threat_feed',
      'retrieve_edr_data', 'calculate_hash',
      'http_request', 'wait',
    ];

    for (const action of readActions) {
      it(`classifies "${action}" as read`, () => {
        expect(classifyAction(action)).toBe('read');
        expect(isReadOnly(action)).toBe(true);
        expect(isWriteAction(action)).toBe(false);
      });
    }
  });

  describe('write actions', () => {
    const writeActions: StepAction[] = [
      'isolate_host', 'restore_connectivity', 'block_ip', 'unblock_ip',
      'block_domain', 'unblock_domain',
      'create_ticket', 'update_ticket', 'notify_analyst', 'notify_oncall', 'send_email',
      'disable_account', 'enable_account', 'reset_password', 'revoke_session',
      'quarantine_file', 'restore_file', 'delete_file',
      'kill_process', 'start_edr_scan',
      'execute_script',
    ];

    for (const action of writeActions) {
      it(`classifies "${action}" as write`, () => {
        expect(classifyAction(action)).toBe('write');
        expect(isWriteAction(action)).toBe(true);
        expect(isReadOnly(action)).toBe(false);
      });
    }
  });

  describe('completeness', () => {
    it('read + write actions cover all known StepAction values', () => {
      const allActions = [...getReadActions(), ...getWriteActions()];
      // 33 total actions from StepAction type (12 read + 21 write)
      expect(allActions.length).toBe(33);
    });

    it('no overlap between read and write sets', () => {
      const readSet = new Set(getReadActions());
      const writeSet = new Set(getWriteActions());
      for (const action of readSet) {
        expect(writeSet.has(action)).toBe(false);
      }
    });
  });
});
