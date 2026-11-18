#!/usr/bin/env bash
# Builds the iOS host app (SwiftUI, iOS 15+, Swift 6 language mode) without an
# Xcode project: cargo for the Rust static library, uniffi-bindgen for the Swift
# bindings, swiftc for the app.
#
#   ios/build.sh sim       -> $OUT/sim/MoussePhoneSpike.app (ad-hoc signed)
#   ios/build.sh device    -> $OUT/device/MoussePhoneSpike.app, signed with
#                             SIGN_IDENTITY and PROVISIONING_PROFILE (a .mobileprovision
#                             whose app id matches BUNDLE_ID, default work.mousse.netspike)
#
# CARGO_TARGET_DIR defaults to spikes/phone/target; OUT defaults to $CARGO_TARGET_DIR/ios.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
KIND=${1:-sim}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
OUT=${OUT:-$CARGO_TARGET_DIR/ios}
BUNDLE_ID=${BUNDLE_ID:-work.mousse.netspike}
export IPHONEOS_DEPLOYMENT_TARGET=15.0

case $KIND in
  sim) RT=aarch64-apple-ios-sim; SDK=iphonesimulator; TRIPLE=arm64-apple-ios15.0-simulator; PLAT=iPhoneSimulator ;;
  device) RT=aarch64-apple-ios; SDK=iphoneos; TRIPLE=arm64-apple-ios15.0; PLAT=iPhoneOS ;;
  *) echo "usage: $0 sim|device" >&2; exit 2 ;;
esac

cd "$ROOT"
cargo build --release --locked -p mousse-phone-spike --lib --target "$RT"
cargo build --release --locked -p uniffi-bindgen
LIB="$CARGO_TARGET_DIR/$RT/release/libmousse_phone_spike.a"

GEN="$OUT/$KIND/gen"
APP="$OUT/$KIND/MoussePhoneSpike.app"
rm -rf "$GEN" "$APP"
mkdir -p "$GEN" "$APP"
"$CARGO_TARGET_DIR/release/uniffi-bindgen" generate --library "$LIB" --language swift --out-dir "$GEN"

xcrun -sdk "$SDK" swiftc \
  -target "$TRIPLE" -swift-version 6 -O -parse-as-library \
  -module-name MoussePhoneSpike \
  -Xcc -fmodule-map-file="$GEN/mousse_phone_spikeFFI.modulemap" -I "$GEN" \
  "$GEN/mousse_phone_spike.swift" "$HERE"/Sources/*.swift \
  "$LIB" \
  -o "$APP/MoussePhoneSpike"

cp "$HERE/Info.plist" "$APP/Info.plist"
plutil -replace CFBundleIdentifier -string "$BUNDLE_ID" "$APP/Info.plist"
plutil -replace CFBundleSupportedPlatforms -json "[\"$PLAT\"]" "$APP/Info.plist"
cp "$ROOT/web/bytepath.html" "$APP/bytepath.html"

if [ "$KIND" = sim ]; then
  codesign --force --sign - --timestamp=none "$APP"
else
  : "${SIGN_IDENTITY:?set SIGN_IDENTITY (security find-identity -v -p codesigning)}"
  : "${PROVISIONING_PROFILE:?set PROVISIONING_PROFILE to a .mobileprovision for $BUNDLE_ID}"
  cp "$PROVISIONING_PROFILE" "$APP/embedded.mobileprovision"
  security cms -D -i "$PROVISIONING_PROFILE" > "$OUT/$KIND/profile.plist"
  plutil -extract Entitlements xml1 -o "$OUT/$KIND/entitlements.plist" "$OUT/$KIND/profile.plist"
  codesign --force --sign "$SIGN_IDENTITY" --entitlements "$OUT/$KIND/entitlements.plist" --timestamp=none "$APP"
fi

# The deployment target the binary actually carries (must be 15.0).
MINOS=$(xcrun vtool -show-build "$APP/MoussePhoneSpike" | awk '/minos/ {print $2; exit}')
echo "built $APP (minos $MINOS, lib $RT)"
