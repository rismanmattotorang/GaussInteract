// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('GaussCore agent surface (stub)', () {
    test('starts unauthenticated with a version', () {
      final core = GaussCore.stub();
      expect(core.isAuthenticated, isFalse);
      expect(core.version, isNotEmpty);
    });

    test('approval flow is recorded and audited', () {
      final core = GaussCore.stub();
      final id = core.requestApproval(
        agent: '@assistant:example.org',
        tool: 'send_external_email',
        proposedAction: 'Email the Q3 summary to finance@corp',
      );
      expect(core.pendingApprovals.length, 1);

      expect(core.resolveApproval(id, GaussApprovalDecision.approve), isTrue);
      expect(core.pendingApprovals, isEmpty);
      expect(core.auditLog.length, 2);
      expect(core.verifyAudit(), isTrue);
    });

    test('resolving an unknown approval is a no-op', () {
      final core = GaussCore.stub();
      expect(core.resolveApproval(999, GaussApprovalDecision.deny), isFalse);
    });

    test('agent event types are namespaced', () {
      expect(GaussAgentEvents.toolCall, 'm.gauss.agent.tool_call');
      expect(GaussAgentEvents.toolResult, 'm.gauss.agent.tool_result');
    });
  });
}
