#!/usr/bin/env bash
# Runs the host app on a fresh iOS Simulator and writes the results.
#
#   ios/run-sim.sh [--runtime <runtime id>] [--device-type <type id>] [--runs N]
#                  [--control cancel|token] [--check all|lifecycle|byte-path] [--keep]
#
# Creates its own simulator, deletes it afterwards (unless --keep), and pipes the
# app's console through scripts/collect-results.mjs into results/ (normal runs must
# PASS) or results/controls/ (control runs must FAIL).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
RUNTIME=""
DEVTYPE="com.apple.CoreSimulator.SimDeviceType.iPhone-16"
RUNS=20
CONTROL=""
CHECK=all
KEEP=0
while [ $# -gt 0 ]; do
  case $1 in
    --runtime) RUNTIME=$2; shift ;;
    --device-type) DEVTYPE=$2; shift ;;
    --runs) RUNS=$2; shift ;;
    --control) CONTROL=$2; shift ;;
    --check) CHECK=$2; shift ;;
    --keep) KEEP=1 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$RUNTIME" ]; then
  # Newest installed iOS runtime.
  RUNTIME=$(xcrun simctl list runtimes -j | node -e '
    const r = JSON.parse(require("fs").readFileSync(0, "utf8")).runtimes
      .filter(x => x.platform === "iOS" && x.isAvailable);
    r.sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }));
    process.stdout.write(r.length ? r[r.length - 1].identifier : "");')
fi
[ -n "$RUNTIME" ] || { echo "no iOS simulator runtime installed" >&2; exit 1; }

"$HERE/build.sh" sim
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
APP="${OUT:-$CARGO_TARGET_DIR/ios}/sim/MoussePhoneSpike.app"
BUNDLE_ID=$(plutil -extract CFBundleIdentifier raw "$APP/Info.plist")

UDID=$(xcrun simctl create "mousse-phone-spike" "$DEVTYPE" "$RUNTIME")
cleanup() {
  xcrun simctl shutdown "$UDID" >/dev/null 2>&1 || true
  [ "$KEEP" = 1 ] || xcrun simctl delete "$UDID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
echo "simulator $UDID ($DEVTYPE, $RUNTIME)"
xcrun simctl boot "$UDID"
xcrun simctl bootstatus "$UDID" -b >/dev/null
xcrun simctl install "$UDID" "$APP"

EXPECT=pass
[ -n "$CONTROL" ] && EXPECT=fail
LOG="$CARGO_TARGET_DIR/ios/run-$(date +%Y%m%d-%H%M%S)${CONTROL:+-break-$CONTROL}.log"
export SIMCTL_CHILD_MOUSSE_PHONE_RUNS=$RUNS
export SIMCTL_CHILD_MOUSSE_PHONE_CHECK=$CHECK
export SIMCTL_CHILD_MOUSSE_PHONE_BREAK=$CONTROL
# The app exits after printing MOUSSE_DONE; the timeout only guards a hang.
set +e
perl -e 'alarm shift; exec @ARGV' 900 \
  xcrun simctl launch --console-pty --terminate-running-process "$UDID" "$BUNDLE_ID" 2>&1 \
  | node "$ROOT/scripts/collect-results.mjs" --out "$ROOT/results" --expect "$EXPECT" --log "$LOG"
STATUS=${PIPESTATUS[1]}
set -e
echo "log: $LOG"
exit "$STATUS"
