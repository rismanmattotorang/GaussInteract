// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';

import 'package:go_router/go_router.dart';

import 'package:gaussinteract/config/themes.dart';
import 'package:gaussinteract/pages/agent/agent_approval_card.dart';
import 'package:gaussinteract/pages/agent/agent_audit_view.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';

/// The supervisor surface for AI agents (GaussInteract-SPECS §IV, §V.F):
/// inline human-in-the-loop approval cards over the tamper-evident audit log.
///
/// It runs against the in-app [GaussCore.stub] so the agentic flows are
/// exercisable today; once the `uniffi` bindings land (roadmap Phase 2) the
/// same screen drives the real Rust core unchanged. The "Simulate tool call"
/// button stands in for inbound `m.gauss.agent.tool_call` events from the
/// server `gm-agent` gateway.
class AgentConsole extends StatefulWidget {
  const AgentConsole({super.key});

  @override
  State<AgentConsole> createState() => _AgentConsoleState();
}

class _AgentConsoleState extends State<AgentConsole> {
  final GaussCore _core = GaussCore.stub();
  int _sampleIndex = 0;

  static const List<({String agent, String tool, String action})> _samples = [
    (
      agent: '@assistant:gaussian.tech',
      tool: 'send_external_email',
      action: 'Email the Q3 revenue summary to finance@corp.example.',
    ),
    (
      agent: '@scheduler:gaussian.tech',
      tool: 'invite_user',
      action: 'Invite @auditor:partner.example to the room “Board — Q3”.',
    ),
    (
      agent: '@ops-bot:gaussian.tech',
      tool: 'set_power_level',
      action: 'Promote @oncall:gaussian.tech to Moderator in “Incident #4821”.',
    ),
  ];

  @override
  void initState() {
    super.initState();
    // Seed two pending review-class actions to make the surface legible.
    _enqueue(_samples[0]);
    _enqueue(_samples[1]);
    _sampleIndex = 2;
  }

  void _enqueue(({String agent, String tool, String action}) sample) {
    _core.requestApproval(
      agent: sample.agent,
      tool: sample.tool,
      proposedAction: sample.action,
    );
  }

  void _simulateToolCall() {
    setState(() {
      _enqueue(_samples[_sampleIndex % _samples.length]);
      _sampleIndex++;
    });
  }

  void _resolve(int id, GaussApprovalDecision decision) {
    setState(() => _core.resolveApproval(id, decision));
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final pending = _core.pendingApprovals;

    return Scaffold(
      appBar: AppBar(
        leading: BackButton(onPressed: () => context.go('/')),
        title: const Text('Agent console'),
        automaticallyImplyLeading: !FluffyThemes.isColumnMode(context),
        centerTitle: FluffyThemes.isColumnMode(context),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _simulateToolCall,
        icon: const Icon(Icons.bolt_outlined),
        label: const Text('Simulate tool call'),
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(
            maxWidth: FluffyThemes.columnWidth * 1.5,
          ),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              Text('Timeline', style: theme.textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(
                'Agent actions classified as “review” wait here for a human '
                'decision. Every choice is written to the audit log below.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 8),
              if (pending.isEmpty)
                _EmptyTimeline(theme: theme)
              else
                for (final request in pending)
                  AgentApprovalCard(
                    request: request,
                    onApprove: () =>
                        _resolve(request.id, GaussApprovalDecision.approve),
                    onDeny: () =>
                        _resolve(request.id, GaussApprovalDecision.deny),
                  ),
              const SizedBox(height: 24),
              AgentAuditView(
                entries: _core.auditLog,
                verified: _core.verifyAudit(),
              ),
              const SizedBox(height: 80),
            ],
          ),
        ),
      ),
    );
  }
}

class _EmptyTimeline extends StatelessWidget {
  const _EmptyTimeline({required this.theme});

  final ThemeData theme;

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      color: theme.colorScheme.surfaceContainerHigh,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Row(
          children: [
            Icon(Icons.check_circle_outline, color: theme.colorScheme.primary),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                'No pending approvals. Agents are operating within their '
                'auto-approved capabilities.',
                style: theme.textTheme.bodyMedium,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
