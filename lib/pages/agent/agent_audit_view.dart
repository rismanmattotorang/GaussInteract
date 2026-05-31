// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';

import 'package:gaussinteract/config/app_config.dart';
import 'package:gaussinteract/l10n/l10n.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';

/// Read-only view of the hash-chained, tamper-evident agent audit log
/// (GaussInteract-SPECS §IV.D, §V.F). A supervisor can inspect exactly what
/// every agent saw and did; the integrity badge reflects [verified], i.e. the
/// result of the core's chain verification.
class AgentAuditView extends StatelessWidget {
  const AgentAuditView({
    super.key,
    required this.entries,
    required this.verified,
  });

  /// The audit records, oldest first (the same shape the server emits).
  final List<GaussAuditRecord> entries;

  /// Whether the chain currently verifies intact.
  final bool verified;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final l10n = L10n.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.receipt_long_outlined, color: colors.onSurfaceVariant),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                l10n.agentAuditLogTitle,
                style: theme.textTheme.titleMedium,
              ),
            ),
            _IntegrityBadge(verified: verified),
          ],
        ),
        const SizedBox(height: 8),
        if (entries.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Text(
              l10n.agentAuditEmpty,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: colors.onSurfaceVariant,
              ),
            ),
          )
        else
          Card(
            elevation: 0,
            color: colors.surfaceContainerHigh,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(AppConfig.borderRadius),
            ),
            child: Column(
              children: [
                for (var i = 0; i < entries.length; i++) ...[
                  if (i > 0) Divider(height: 1, color: colors.outlineVariant),
                  _AuditTile(index: i, entry: entries[i]),
                ],
              ],
            ),
          ),
      ],
    );
  }
}

class _AuditTile extends StatelessWidget {
  const _AuditTile({required this.index, required this.entry});

  final int index;
  final GaussAuditRecord entry;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    return ListTile(
      dense: true,
      leading: CircleAvatar(
        radius: 14,
        backgroundColor: colors.primaryContainer,
        child: Text(
          '${index + 1}',
          style: theme.textTheme.labelSmall?.copyWith(
            color: colors.onPrimaryContainer,
          ),
        ),
      ),
      title: Text(entry.action, style: theme.textTheme.bodyMedium),
      subtitle: Text(
        entry.actor,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: theme.textTheme.bodySmall?.copyWith(
          color: colors.onSurfaceVariant,
        ),
      ),
      trailing: Text(
        _shortHash(entry.hash),
        style: theme.textTheme.labelSmall?.copyWith(
          fontFamily: 'monospace',
          color: colors.onSurfaceVariant,
        ),
      ),
    );
  }

  // Display the low 32 bits of the chain hash as 8 hex digits. The production
  // core uses a cryptographic hash; this mirrors the scaffold's placeholder.
  static String _shortHash(int hash) =>
      '#${(hash & 0xFFFFFFFF).toRadixString(16).padLeft(8, '0')}';
}

class _IntegrityBadge extends StatelessWidget {
  const _IntegrityBadge({required this.verified});

  final bool verified;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final l10n = L10n.of(context);
    final color = verified ? Colors.green : colors.error;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          verified ? Icons.verified_outlined : Icons.gpp_bad_outlined,
          size: 18,
          color: color,
        ),
        const SizedBox(width: 4),
        Text(
          verified ? l10n.agentAuditVerified : l10n.agentAuditTampered,
          style: theme.textTheme.labelMedium?.copyWith(
            color: color,
            fontWeight: FontWeight.bold,
          ),
        ),
      ],
    );
  }
}
