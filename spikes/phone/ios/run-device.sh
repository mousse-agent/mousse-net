#!/usr/bin/env bash
# Runs the host app on a physical iPhone and writes the results.
#
#   SIGN_IDENTITY=... PROVISIONING_PROFILE=... [BUNDLE_ID=...] \
#   ios/run-device.sh --device <udid> [--tool devicectl|ios-deploy] [--runs N]
#                     [--control cancel|token] [--check all|lifecycle|byte-path]
#
# devicectl (Xcode 15+) drives iOS 17 and later; iOS 15 and 16 need ios-deploy
# (brew install ios-deploy). Both stream the app's console into
# scripts/collect-results.mjs. The phone must be unlocked, trusted, and in
# Developer Mode (iOS 16+).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
DEVICE=""
TOOL=devicectl
RUNS=20
CONTROL=""
CHECK=all
while [ $# -gt 0 ]; do
  case $1 in
    --device) DEVICE=$2; shift ;;
    --tool) TOOL=$2; shift ;;
    --runs) RUNS=$2; shift ;;
    --control) CONTROL=$2; shift ;;
    --check) CHECK=$2; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$DEVICE" ] || { echo "--device is required (xcrun devicectl list devices, or ios-deploy -c)" >&2; exit 2; }

"$HERE/build.sh" device
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
APP="${OUT:-$CARGO_TARGET_DIR/ios}/device/MoussePhoneSpike.app"
BUNDLE_ID=$(plutil -extract CFBundleIdentifier raw "$APP/Info.plist")
EXPECT=pass
[ -n "$CONTROL" ] && EXPECT=fail
LOG="$CARGO_TARGET_DIR/ios/device-$(date +%Y%m%d-%H%M%S)${CONTROL:+-break-$CONTROL}.log"
ARGS=(-MOUSSE_PHONE_RUNS "$RUNS" -MOUSSE_PHONE_CHECK "$CHECK" -MOUSSE_PHONE_BREAK "${CONTROL:-}")

set +e
if [ "$TOOL" = devicectl ]; then
  xcrun devicectl device install app --device "$DEVICE" "$APP"
  perl -e 'alarm shift; exec @ARGV' 900 \
    xcrun devicectl device process launch --device "$DEVICE" --console --terminate-existing \
      "$BUNDLE_ID" "${ARGS[@]}" 2>&1 \
    | node "$ROOT/scripts/collect-results.mjs" --out "$ROOT/results" --expect "$EXPECT" --log "$LOG"
else
  perl -e 'alarm shift; exec @ARGV' 900 \
    ios-deploy --id "$DEVICE" --bundle "$APP" --debug --noninteractive --args "${ARGS[*]}" 2>&1 \
    | node "$ROOT/scripts/collect-results.mjs" --out "$ROOT/results" --expect "$EXPECT" --log "$LOG"
fi
STATUS=${PIPESTATUS[1]}
set -e
echo "log: $LOG"
exit "$STATUS"
