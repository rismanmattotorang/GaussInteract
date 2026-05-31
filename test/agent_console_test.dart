// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:gaussinteract/l10n/l10n.dart';
import 'package:gaussinteract/pages/agent/agent_console.dart';

void main() {
  Widget host() => MaterialApp(
    localizationsDelegates: L10n.localizationsDelegates,
    supportedLocales: L10n.supportedLocales,
    locale: const Locale('en'),
    home: const AgentConsole(),
  );

  group('AgentConsole', () {
    testWidgets('renders seeded approval cards and the audit view', (
      tester,
    ) async {
      await tester.pumpWidget(host());
      await tester.pumpAndSettle();

      expect(find.text('Agent console'), findsOneWidget);
      // The capability grant (parsed from server-shaped content) is shown.
      expect(find.text('Agent permissions'), findsOneWidget);
      expect(find.text('Allowed tools'), findsOneWidget);
      expect(find.text('search_knowledge_base'), findsOneWidget);
      // Two review-class actions are seeded on init.
      expect(find.widgetWithText(FilledButton, 'Approve'), findsNWidgets(2));
      expect(find.text('Tamper-evident audit log'), findsOneWidget);
      expect(find.text('Verified'), findsOneWidget);
    });

    testWidgets('approving a card resolves it', (tester) async {
      await tester.pumpWidget(host());
      await tester.pumpAndSettle();

      await tester.tap(
        find.widgetWithText(FilledButton, 'Approve').first,
      );
      await tester.pumpAndSettle();

      // One approval consumed; one remains.
      expect(find.widgetWithText(FilledButton, 'Approve'), findsNWidgets(1));
      // Chain still verifies after the decision is recorded.
      expect(find.text('Verified'), findsOneWidget);
    });
  });
}
