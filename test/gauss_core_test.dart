// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter_test/flutter_test.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';

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

  group('Server shape reconciliation', () {
    // Exactly the content gm-agent's CapabilityGrant::to_content emits.
    final capabilityContent = <String, Object?>{
      'agent': '@gauss_agent_x:gaussian.tech',
      'rate_limit_per_min': 30,
      'default_class': 'forbidden',
      'allowed_tools': ['search', 'send_email'],
      'accessible_rooms': ['!r:gaussian.tech'],
      'overrides': [
        ['send_email', 'review'],
      ],
    };

    test('parses m.gauss.agent.capability content and classifies', () {
      final grant = GaussCapabilityGrant.fromContent(capabilityContent);
      expect(grant, isNotNull);
      expect(grant!.agent, '@gauss_agent_x:gaussian.tech');
      expect(grant.rateLimitPerMin, 30);
      // send_email carries a "review" override in the content above.
      expect(
        grant.classify('send_email', '!r:gaussian.tech'),
        GaussActionClass.review,
      );
      // search is allowed but has no override, so it takes default_class
      // (forbidden here).
      expect(
        grant.classify('search', '!r:gaussian.tech'),
        GaussActionClass.forbidden,
      );
    });

    test('classification matches the gateway for allowed/override/denied', () {
      final content = Map<String, Object?>.from(capabilityContent)
        ..['default_class'] = 'auto';
      final grant = GaussCapabilityGrant.fromContent(content)!;
      expect(grant.classify('search', '!r:gaussian.tech'), GaussActionClass.auto);
      expect(
        grant.classify('send_email', '!r:gaussian.tech'),
        GaussActionClass.review,
      );
      expect(grant.classify('rm_rf', '!r:gaussian.tech'), GaussActionClass.forbidden);
      expect(grant.classify('search', '!other:gaussian.tech'), GaussActionClass.forbidden);
    });

    test('rejects malformed capability content', () {
      final missingAgent = Map<String, Object?>.from(capabilityContent)
        ..remove('agent');
      expect(GaussCapabilityGrant.fromContent(missingAgent), isNull);

      final badClass = Map<String, Object?>.from(capabilityContent)
        ..['default_class'] = 'sudo';
      expect(GaussCapabilityGrant.fromContent(badClass), isNull);
    });

    test('parses a gm-obs audit record JSON object', () {
      final record = GaussAuditRecord.fromJson(<String, Object?>{
        'seq': 0,
        'actor': '@gauss_agent_x:gaussian.tech',
        'action': 'auto_allowed: search',
        'prev_hash': 0,
        'hash': 42,
      });
      expect(record, isNotNull);
      expect(record!.action, 'auto_allowed: search');
      expect(record.seq, 0);
      // Malformed records are rejected.
      expect(GaussAuditRecord.fromJson(<String, Object?>{'seq': 'nope'}), isNull);
    });
  });
}
