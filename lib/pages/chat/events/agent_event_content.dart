// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';
import 'package:gaussinteract/l10n/l10n.dart';
import 'package:gaussinteract/utils/gauss_core/gauss_core.dart';
import 'package:matrix/matrix.dart';

/// Renders an agent's `m.gauss.agent.tool_call` / `m.gauss.agent.tool_result`
/// event as a first-class, inline timeline bubble (GaussInteract-SPECS §IV.B,
/// §V.D): the agent's tool calls and results are visible, legible and replayable
/// in-band, not hidden behind chrome.
class AgentEventContent extends StatelessWidget {
  const AgentEventContent({
    super.key,
    required this.event,
    required this.textColor,
    required this.fontSize,
  });

  final Event event;
  final Color textColor;
  final double fontSize;

  @override
  Widget build(BuildContext context) {
    final l10n = L10n.of(context);
    final isResult = event.type == GaussAgentEvents.toolResult;
    final tool = event.content.tryGet<String>('tool') ?? '';
    final summary = isResult
        ? event.content.tryGet<String>('summary') ?? ''
        : event.content.tryGet<String>('args_summary') ?? '';
    final ok = event.content.tryGet<bool>('ok') ?? true;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              isResult ? Icons.bolt_outlined : Icons.build_outlined,
              size: fontSize + 2,
              color: textColor,
            ),
            const SizedBox(width: 6),
            Text(
              isResult ? l10n.agentToolResult : l10n.agentToolCall,
              style: TextStyle(
                color: textColor,
                fontSize: fontSize - 2,
                fontWeight: FontWeight.bold,
                letterSpacing: 0.5,
              ),
            ),
            if (isResult) ...[
              const SizedBox(width: 8),
              _StatusChip(
                ok: ok,
                label: ok ? l10n.agentToolSucceeded : l10n.agentToolFailed,
              ),
            ],
          ],
        ),
        const SizedBox(height: 4),
        if (tool.isNotEmpty)
          Text(
            tool,
            style: TextStyle(
              color: textColor,
              fontSize: fontSize,
              fontFamily: 'monospace',
              fontWeight: FontWeight.w600,
            ),
          ),
        if (summary.isNotEmpty) ...[
          const SizedBox(height: 2),
          Text(summary, style: TextStyle(color: textColor, fontSize: fontSize)),
        ],
      ],
    );
  }
}

class _StatusChip extends StatelessWidget {
  const _StatusChip({required this.ok, required this.label});

  final bool ok;
  final String label;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: ok ? colors.primaryContainer : colors.errorContainer,
        borderRadius: BorderRadius.circular(100),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: ok ? colors.onPrimaryContainer : colors.onErrorContainer,
          fontSize: 11,
          fontWeight: FontWeight.bold,
        ),
      ),
    );
  }
}
