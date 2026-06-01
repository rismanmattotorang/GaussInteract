// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';

import 'package:gaussinteract/config/app_config.dart';
import 'package:gaussinteract/l10n/l10n.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';

/// Read-only view of an agent's capability grant (GaussInteract-SPECS §IV.C),
/// parsed from the `m.gauss.agent.capability` room state the GaussMatrix gateway
/// publishes. It lets a supervisor see exactly what an agent is permitted to do
/// — which tools (and how each is classified) and which rooms.
class AgentCapabilityView extends StatelessWidget {
  const AgentCapabilityView({super.key, required this.grant});

  /// The grant to render.
  final GaussCapabilityGrant grant;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final l10n = L10n.of(context);
    final rateLimit = grant.rateLimitPerMin == 0
        ? l10n.agentUnlimited
        : '${grant.rateLimitPerMin}/min';
    final dailyCalls = grant.dailyCallLimit == 0
        ? l10n.agentUnlimited
        : '${grant.dailyCallLimit}/day';
    final tokenBudget = grant.dailyTokenBudget == 0
        ? l10n.agentUnlimited
        : l10n.agentTokensPerDay(grant.dailyTokenBudget);

    return Card(
      elevation: 0,
      color: colors.surfaceContainerHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppConfig.borderRadius),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.verified_user_outlined, color: colors.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    l10n.agentPermissions,
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                _ClassChip(grant.defaultClass, prefix: '${l10n.agentDefault}: '),
              ],
            ),
            const SizedBox(height: 4),
            Text(
              grant.agent,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.bodySmall?.copyWith(
                color: colors.onSurfaceVariant,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 4),
            Text(
              '${l10n.agentRateLimit}: $rateLimit'
              '  ·  ${l10n.agentDailyCalls}: $dailyCalls'
              '  ·  ${l10n.agentTokenBudget}: $tokenBudget',
              style: theme.textTheme.bodySmall?.copyWith(
                color: colors.onSurfaceVariant,
              ),
            ),
            const Divider(height: 24),
            Text(l10n.agentAllowedTools, style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final tool in grant.allowedTools)
                  _ToolChip(
                    tool: tool,
                    actionClass: grant.classify(tool, _anyAccessibleRoom()),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            Text(l10n.agentAccessibleRooms, style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            for (final room in grant.accessibleRooms)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Row(
                  children: [
                    Icon(
                      Icons.meeting_room_outlined,
                      size: 16,
                      color: colors.onSurfaceVariant,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        room,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodyMedium?.copyWith(
                          fontFamily: 'monospace',
                        ),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  // Tools are classified per (tool, room); a tool's class is the same in any
  // accessible room, so classify against the first granted room (or a sentinel
  // that is intentionally not in the grant, yielding the override/default).
  String _anyAccessibleRoom() =>
      grant.accessibleRooms.isEmpty ? '' : grant.accessibleRooms.first;
}

class _ToolChip extends StatelessWidget {
  const _ToolChip({required this.tool, required this.actionClass});

  final String tool;
  final GaussActionClass actionClass;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            tool,
            style: theme.textTheme.labelMedium?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(width: 6),
          _ClassChip(actionClass),
        ],
      ),
    );
  }
}

class _ClassChip extends StatelessWidget {
  const _ClassChip(this.actionClass, {this.prefix = ''});

  final GaussActionClass actionClass;
  final String prefix;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final (bg, fg, label) = switch (actionClass) {
      GaussActionClass.auto => (
        colors.primaryContainer,
        colors.onPrimaryContainer,
        L10n.of(context).agentClassAuto,
      ),
      GaussActionClass.review => (
        colors.tertiaryContainer,
        colors.onTertiaryContainer,
        L10n.of(context).agentClassReview,
      ),
      GaussActionClass.forbidden => (
        colors.errorContainer,
        colors.onErrorContainer,
        L10n.of(context).agentClassForbidden,
      ),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Text(
        '$prefix$label',
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: fg,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
