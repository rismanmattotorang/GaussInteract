#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2019-Present Christian Kußowski
# SPDX-FileCopyrightText: 2019-Present Contributors to FluffyChat
#
# SPDX-License-Identifier: AGPL-3.0-or-later

git apply ./scripts/enable-android-google-services.patch
GAUSSINTERACT_ORIG_GROUP="tech.gaussian.gaussinteract"
GAUSSINTERACT_ORIG_TEAM=""
#GAUSSINTERACT_NEW_GROUP="com.example.gaussinteract"
#GAUSSINTERACT_NEW_TEAM="ABCDE12345"

# In some cases (ie: running beta XCode releases) some pods haven't updated their minimum version
# but XCode will reject the package for using too old of a minimum version. 
# This will fix that, but. Well. Use at your own risk.
# export I_PROMISE_IM_REALLY_SMART=1

# If you want to automatically install the app
# export GAUSSINTERACT_INSTALL_IPA=1

### Rotate IDs ###
[ -n "${GAUSSINTERACT_NEW_GROUP}" ] && {
	# App group IDs
	sed -i "" "s/group.${GAUSSINTERACT_ORIG_GROUP}.app/group.${GAUSSINTERACT_NEW_GROUP}.app/g" "macos/Runner/Runner.entitlements"
	sed -i "" "s/group.${GAUSSINTERACT_ORIG_GROUP}.app/group.${GAUSSINTERACT_NEW_GROUP}.app/g" "macos/Runner.xcodeproj/project.pbxproj"
	# Bundle identifiers
	sed -i "" "s/${GAUSSINTERACT_ORIG_GROUP}.app/${GAUSSINTERACT_NEW_GROUP}.app/g" "macos/Runner.xcodeproj/project.pbxproj"
}

[ -n "${GAUSSINTERACT_NEW_TEAM}" ] && {
	# Code signing team
	sed -i "" "s/${GAUSSINTERACT_ORIG_TEAM}/${GAUSSINTERACT_NEW_TEAM}/g" "macos/Runner.xcodeproj/project.pbxproj"
}

### Make release build ###
flutter build macos --release

echo "Build build/macos/Build/Products/Release/GaussInteract.app"
