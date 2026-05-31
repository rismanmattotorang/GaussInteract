// SPDX-FileCopyrightText: 2019-Present Christian Kußowski
// SPDX-FileCopyrightText: 2019-Present Contributors to FluffyChat
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import 'dart:ui';

abstract class AppConfig {
  static const Color primaryColor = Color(0xFF295d9f);

  static const Color chatColor = primaryColor;
  static const double messageFontSize = 16.0;
  static const bool allowOtherHomeservers = true;
  static const bool enableRegistration = true;
  static const bool hideTypingUsernames = false;

  static const String inviteLinkPrefix = 'https://matrix.to/#/';
  static const String deepLinkPrefix = 'tech.gaussian.gaussinteract://chat/';
  static const String schemePrefix = 'matrix:';
  static const String pushNotificationsChannelId = 'gaussinteract_push';
  static const String pushNotificationsAppId = 'tech.gaussian.gaussinteract';
  static const double borderRadius = 16.0;
  static const double spaceBorderRadius = 11.0;
  static const double columnWidth = 360.0;

  static const String enablePushTutorial =
      'https://gaussian.tech/faq/#push_without_google_services';
  static const String encryptionTutorial =
      'https://gaussian.tech/faq/#how_to_use_end_to_end_encryption';
  static const String startChatTutorial =
      'https://gaussian.tech/faq/#how_do_i_find_other_users';
  static const String howDoIGetStickersTutorial =
      'https://gaussian.tech/faq/#how_do_i_get_stickers';
  static const String appId = 'tech.gaussian.GaussInteract';
  static const String appOpenUrlScheme = 'tech.gaussian.gaussinteract';
  static const String appSsoUrlScheme = 'tech.gaussian.gaussinteract.auth';

  static const String sourceCodeUrl =
      'https://github.com/rismanmattotorang/gaussinteract';
  static const String supportUrl =
      'https://github.com/rismanmattotorang/gaussinteract/issues';
  static const String changelogUrl = 'https://gaussian.tech/changelog/';

  static const Set<String> defaultReactions = {'👍', '❤️', '😂', '😮', '😢'};

  static final Uri newIssueUrl = Uri(
    scheme: 'https',
    host: 'github.com',
    path: '/rismanmattotorang/gaussinteract/issues/new',
  );

  static final Uri homeserverList = Uri(
    scheme: 'https',
    host: 'raw.githubusercontent.com',
    path: 'rismanmattotorang/gaussinteract/refs/heads/main/recommended_homeservers.json',
  );

  static const String mainIsolatePortName = 'main_isolate';
  static const String pushIsolatePortName = 'push_isolate';
  static const String pushHelperCrashReportKey = 'push_helper_crash_report';
}
