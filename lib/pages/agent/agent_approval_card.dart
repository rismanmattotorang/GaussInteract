// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';

import 'package:gaussinteract/config/app_config.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';

/// An inline, first-class timeline item rendering a human-in-the-loop approval
/// prompt for a `review`-class agent action (GaussInteract-SPECS §IV.C, §V.F).
///
/// The agent is visually distinguished, the proposed action is shown in full,
/// and a single-tap approve/deny choice is offered — the legibility principle
/// from the specification.
class AgentApprovalCard extends StatelessWidget {
  const AgentApprovalCard({
    super.key,
    required this.request,
    required this.onApprove,
    required this.onDeny,
  });

  /// The pending approval to render.
  final GaussApprovalRequest request;

  /// Called when the human approves the action.
  final VoidCallback onApprove;

  /// Called when the human denies the action.
  final VoidCallback onDeny;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;

    return Card(
      elevation: 0,
      margin: const EdgeInsets.symmetric(vertical: 6),
      color: colors.surfaceContainerHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(AppConfig.borderRadius),
        side: BorderSide(color: colors.tertiary, width: 1.5),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  backgroundColor: colors.tertiaryContainer,
                  child: Icon(
                    Icons.smart_toy_outlined,
                    color: colors.onTertiaryContainer,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        request.agent,
                        style: theme.textTheme.titleSmall,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        'wants to run a tool',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: colors.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                _Badge(
                  label: 'Needs approval',
                  color: colors.tertiary,
                  onColor: colors.onTertiary,
                ),
              ],
            ),
            const SizedBox(height: 14),
            Row(
              children: [
                Icon(
                  Icons.build_outlined,
                  size: 18,
                  color: colors.onSurfaceVariant,
                ),
                const SizedBox(width: 8),
                Text(
                  request.tool,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: colors.surfaceContainerLowest,
                borderRadius: BorderRadius.circular(AppConfig.borderRadius / 2),
                border: Border.all(color: colors.outlineVariant),
              ),
              child: Text(
                request.proposedAction,
                style: theme.textTheme.bodyMedium,
              ),
            ),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                OutlinedButton.icon(
                  onPressed: onDeny,
                  icon: const Icon(Icons.close),
                  label: const Text('Deny'),
                  style: OutlinedButton.styleFrom(foregroundColor: colors.error),
                ),
                const SizedBox(width: 12),
                FilledButton.icon(
                  onPressed: onApprove,
                  icon: const Icon(Icons.check),
                  label: const Text('Approve'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge({
    required this.label,
    required this.color,
    required this.onColor,
  });

  final String label;
  final Color color;
  final Color onColor;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: onColor,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
