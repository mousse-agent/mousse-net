#!/usr/bin/env bash
# Installs and runs the host app on one adb device (emulator or phone) and writes
# the results. Build first with android/build.sh.
#
#   ANDROID_SERIAL=<serial> android/run.sh [--runs N] [--control cancel|token]
#                                          [--check all|lifecycle|byte-path]
#                                          [--unroutable a:p]
#
# Normal runs write results/<check>__<target>.json and must PASS; control runs write
# results/controls/... and must FAIL.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
: "${ANDROID_SERIAL:?set ANDROID_SERIAL (adb devices)}"
export ANDROID_SERIAL
ADB=${ADB:-adb}
PKG=work.mousse.netspike
APK=${APK:-$HERE/app/build/outputs/apk/debug/app-debug.apk}
RUNS=20
CONTROL=""
CHECK=all
UNROUTABLE=""
while [ $# -gt 0 ]; do
  case $1 in
    --runs) RUNS=$2; shift ;;
    --control) CONTROL=$2; shift ;;
    --check) CHECK=$2; shift ;;
    --unroutable) UNROUTABLE=$2; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done

"$ADB" install -r -t "$APK" >/dev/null
"$ADB" shell am force-stop "$PKG"
"$ADB" shell run-as "$PKG" rm -rf files/results >/dev/null 2>&1 || true
"$ADB" logcat -c
EXTRAS=(--ei runs "$RUNS" --es check "$CHECK")
[ -n "$CONTROL" ] && EXTRAS+=(--es break "$CONTROL")
[ -n "$UNROUTABLE" ] && EXTRAS+=(--es unroutable "$UNROUTABLE")
"$ADB" shell am start -W -n "$PKG/.MainActivity" "${EXTRAS[@]}" >/dev/null

LOGDIR=${CARGO_TARGET_DIR:-$ROOT/target}/android
mkdir -p "$LOGDIR"
LOG="$LOGDIR/run-$ANDROID_SERIAL-$(date +%Y%m%d-%H%M%S)${CONTROL:+-break-$CONTROL}.log"
# Follow the app's log until MOUSSE_DONE (or a 15 minute guard).
set +e
(perl -e 'alarm shift; exec @ARGV' 900 "$ADB" -s "$ANDROID_SERIAL" logcat -v brief -s MousseSpike:I AndroidRuntime:E \
  | while IFS= read -r line; do
      echo "$line" >> "$LOG"
      case $line in
        *"page:"*|*lifecycle:*|*FATAL*|*Exception*) echo "$line" ;;
      esac
      case $line in *MOUSSE_DONE*) pkill -f -- "-s $ANDROID_SERIAL logcat -v brief" 2>/dev/null; break ;; esac
    done) 2>/dev/null
set -e

EXPECT=pass
[ -n "$CONTROL" ] && EXPECT=fail
STATUS=0
FILES=$(sed -n 's/.*MOUSSE_RESULT_FILE \(.*\)$/\1/p' "$LOG" | tr -d '\r')
{
  for f in $FILES; do
    printf 'MOUSSE_RESULT %s\n' "$("$ADB" exec-out run-as "$PKG" cat "files/results/$f")"
  done
} | node "$ROOT/scripts/collect-results.mjs" --out "$ROOT/results" --expect "$EXPECT" || STATUS=$?
"$ADB" shell am force-stop "$PKG"
echo "log: $LOG"
exit "$STATUS"
