// SPDX-FileCopyrightText: 2019-Present Christian Kußowski
// SPDX-FileCopyrightText: 2019-Present Contributors to FluffyChat
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'package:gaussinteract/utils/file_selector.dart';
import 'package:gaussinteract/widgets/future_loading_dialog.dart';
import 'package:gaussinteract/widgets/matrix.dart';
import 'package:flutter/material.dart';

Future<void> restoreBackupFlow(BuildContext context) async {
  final matrix = Matrix.of(context);
  final picked = await selectFiles(context);
  final file = picked.firstOrNull;
  if (file == null) return;

  if (!context.mounted) return;
  await showFutureLoadingDialog(
    context: context,
    future: () async {
      final client = await matrix.getLoginClient();
      await client.importDump(String.fromCharCodes(await file.readAsBytes()));
      matrix.initMatrix();
    },
  );
}
