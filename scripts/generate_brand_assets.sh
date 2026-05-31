#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Generates all GaussInteract brand raster assets (app icons, launcher icons,
# notification icons, splash, web icons, store/vector logos) from a single
# source mark: a message bubble ("Interact") containing a Gaussian bell curve
# ("Gauss"), rendered in the GaussInteract blue->teal gradient.
#
# Requires: rsvg-convert (librsvg2-bin), ImageMagick (convert/identify).
# Run from the repository root:  ./scripts/generate_brand_assets.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

# ---- brand tokens --------------------------------------------------------
GRAD='<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
  <stop offset="0" stop-color="#2C68AA"/>
  <stop offset="1" stop-color="#37A4BD"/>
</linearGradient>'
BUBBLE='<rect x="232" y="232" width="560" height="470" rx="120" ry="120" fill="#FFFFFF"/>
  <path d="M 384 644 L 300 802 L 476 644 Z" fill="#FFFFFF"/>'
CURVE_D='M 288 596 C 360 596 396 584 432 508 C 470 428 486 384 512 384 C 538 384 554 428 592 508 C 628 584 664 596 736 596'
CURVE_COLOR="<path d=\"$CURVE_D\" fill=\"none\" stroke=\"#20528C\" stroke-width=\"42\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
# mask that knocks the bell curve out of a white shape (for monochrome use)
CUTMASK="<mask id=\"cut\" maskUnits=\"userSpaceOnUse\" x=\"-512\" y=\"-512\" width=\"2048\" height=\"2048\">
  <rect x=\"-512\" y=\"-512\" width=\"2048\" height=\"2048\" fill=\"#FFFFFF\"/>
  <path d=\"$CURVE_D\" fill=\"none\" stroke=\"#000000\" stroke-width=\"42\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>
</mask>"
BGRECT='<rect x="-512" y="-512" width="2048" height="2048" fill="url(#g)"/>'

svg() { # svg <file> <viewBox> <body...>
  local file="$1"; shift; local vb="$1"; shift
  cat > "$BUILD/$file" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="$vb" width="1024" height="1024">
<defs>$GRAD
$CUTMASK</defs>
$*
</svg>
EOF
}

# ---- source variants -----------------------------------------------------
# Full-bleed square colour icon (iOS / web): mark ~70%
svg icon_fullbleed.svg "105 110 814 814" "$BGRECT $BUBBLE $CURVE_COLOR"
# Rounded colour icon (Android legacy launcher / store logo): mark with padding
svg icon_rounded.svg "0 0 1024 1024" \
  '<rect x="0" y="0" width="1024" height="1024" rx="208" ry="208" fill="url(#g)"/>'" $BUBBLE $CURVE_COLOR"
# macOS card: rounded squircle inset with transparent margin
svg icon_macos.svg "0 0 1024 1024" \
  '<rect x="92" y="92" width="840" height="840" rx="188" ry="188" fill="url(#g)"/>'" $BUBBLE $CURVE_COLOR"
# Adaptive background layer (full-bleed gradient only)
svg bg_gradient.svg "0 0 1024 1024" "$BGRECT"
# Adaptive foreground (colour mark, transparent, in safe zone ~55%)
svg fg_color.svg "0 0 1024 1024" "$BUBBLE $CURVE_COLOR"
# Standalone colour mark (transparent, ~85%)
svg mark_color.svg "177 182 670 670" "$BUBBLE $CURVE_COLOR"
# Monochrome mark (white bubble, curve knocked out, transparent) ~85%
svg mark_mono.svg "177 182 670 670" "<g mask=\"url(#cut)\">$BUBBLE</g>"
# Adaptive monochrome layer (safe zone)
svg mono_safe.svg "0 0 1024 1024" "<g mask=\"url(#cut)\">$BUBBLE</g>"
# Notification icon (white, tighter zoom ~80%)
svg notif.svg "150 155 720 720" "<g mask=\"url(#cut)\">$BUBBLE</g>"

# Wordmark: mark + "GaussInteract"
cat > "$BUILD/wordmark.svg" <<EOF
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2400 460" width="2400" height="460">
<defs>$GRAD
$CUTMASK</defs>
<g transform="translate(40 56) scale(0.34)"><rect x="0" y="0" width="1024" height="1024" rx="208" ry="208" fill="url(#g)"/>$BUBBLE $CURVE_COLOR</g>
<text x="470" y="318" font-family="DejaVu Sans, Liberation Sans, sans-serif" font-size="240" font-weight="700">
  <tspan fill="#20528C">Gauss</tspan><tspan fill="#37A4BD">Interact</tspan>
</text>
</svg>
EOF
# Rasterise wordmark, trim to content, then letterbox into each fixed slot (no distortion)
rsvg-convert -w 2400 -h 460 "$BUILD/wordmark.svg" -o "$BUILD/wordmark_full.png"
convert "$BUILD/wordmark_full.png" -trim +repage "$BUILD/wordmark_trim.png"
wordmark_slot() { convert "$BUILD/wordmark_trim.png" -resize "${2}x${3}" -background none -gravity center -extent "${2}x${3}" "$1"; }

png() { rsvg-convert -w "$2" -h "$3" "$BUILD/$1" -o "$4"; }   # png <src> <w> <h> <out>

echo ">> assets/logo (vector + raster)"
cp "$BUILD/icon_rounded.svg"   assets/logo/vector/logo.svg
cp "$BUILD/bg_gradient.svg"    assets/logo/vector/logo_background.svg
cp "$BUILD/mark_color.svg"     assets/logo/vector/logo_standalone.svg
cp "$BUILD/icon_fullbleed.svg" assets/logo/vector/logo_favicon.svg
cp "$BUILD/mark_mono.svg"      assets/logo/vector/logo_mono.svg
cp "$BUILD/wordmark.svg"       assets/logo/vector/logo_font.svg
png icon_rounded.svg   2000 2000 assets/logo/img/logo.png
png bg_gradient.svg    2000 2000 assets/logo/img/logo_background.png
png mark_color.svg     2000 2000 assets/logo/img/logo_standalone.png
png icon_fullbleed.svg 2000 2000 assets/logo/img/logo_favicon.png
png mark_mono.svg      2000 2000 assets/logo/img/logo_mono.png
wordmark_slot          assets/logo/img/logo_font.png 1455 282
png icon_fullbleed.svg  624  624 assets/logo/mini/logo_favicon_mini.png
png mark_mono.svg       800  800 assets/logo/mini/logo_mono_mini.png
wordmark_slot          assets/logo/mini/logo_font_mini.png 624 117

echo ">> Android launcher / adaptive / notification / splash"
for f in $(find android/app/src/main/res -name "ic_launcher.png"); do d=$(identify -format '%w' "$f"); png icon_rounded.svg "$d" "$d" "$f"; done
for f in $(find android/app/src/main/res -name "ic_launcher_foreground.png"); do d=$(identify -format '%w' "$f"); png fg_color.svg "$d" "$d" "$f"; done
for f in $(find android/app/src/main/res -name "ic_launcher_background.png"); do d=$(identify -format '%w' "$f"); png bg_gradient.svg "$d" "$d" "$f"; done
for f in $(find android/app/src/main/res -name "ic_launcher_monochrome.png"); do d=$(identify -format '%w' "$f"); png mono_safe.svg "$d" "$d" "$f"; done
for f in $(find android/app/src/main/res -name "notifications_icon.png"); do d=$(identify -format '%w' "$f"); png notif.svg "$d" "$d" "$f"; done
for f in $(find android/app/src/main/res -name "splash.png"); do d=$(identify -format '%w' "$f"); png icon_rounded.svg "$d" "$d" "$f"; done
# 1x1 background colour pixels: day = light, night = dark slate
for f in $(find android/app/src/main/res -path "*night*background.png"); do convert -size 1x1 xc:'#0E1B2A' "$f"; done
for f in $(find android/app/src/main/res -name "background.png" -not -path "*night*"); do convert -size 1x1 xc:'#FFFFFF' "$f"; done

echo ">> iOS app icons (opaque, square)"
for f in $(find ios/Runner/Assets.xcassets/AppIcon.appiconset -name "*.png"); do
  d=$(identify -format '%w' "$f"); png icon_fullbleed.svg "$d" "$d" "$f"
  convert "$f" -background '#2C68AA' -alpha remove -alpha off "$f"  # ensure no alpha
done

echo ">> macOS app icons"
for f in $(find macos/Runner/Assets.xcassets/AppIcon.appiconset -name "*.png"); do d=$(identify -format '%w' "$f"); png icon_macos.svg "$d" "$d" "$f"; done

echo ">> Web icons + favicon"
for f in $(find web/icons -name "Icon-maskable-*.png"); do d=$(identify -format '%w' "$f"); png icon_fullbleed.svg "$d" "$d" "$f"; done
for f in $(find web/icons -name "Icon-*.png" -not -name "Icon-maskable-*"); do d=$(identify -format '%w' "$f"); png icon_rounded.svg "$d" "$d" "$f"; done
png icon_rounded.svg 256 256 web/favicon.png

echo ">> snap icon"
for f in $(find snap -name "*.png"); do png icon_rounded.svg 512 512 "$f"; done

echo ">> Windows .ico"
if [ -f windows/runner/resources/app_icon.ico ]; then
  for s in 16 24 32 48 64 128 256; do png icon_rounded.svg "$s" "$s" "$BUILD/ico_$s.png"; done
  convert "$BUILD"/ico_16.png "$BUILD"/ico_24.png "$BUILD"/ico_32.png "$BUILD"/ico_48.png \
          "$BUILD"/ico_64.png "$BUILD"/ico_128.png "$BUILD"/ico_256.png windows/runner/resources/app_icon.ico
fi

echo "Done. Brand assets regenerated."
