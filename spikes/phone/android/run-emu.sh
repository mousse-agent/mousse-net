#!/usr/bin/env bash
# Boots a throwaway headless emulator, runs android/run.sh on it, then deletes it.
#
#   ANDROID_HOME=<sdk> android/run-emu.sh --image "system-images;android-35;google_apis;arm64-v8a"
#                      [--keep] [run.sh arguments ...]
#
# The system image must be installed in ANDROID_HOME. AVDs go to ANDROID_AVD_HOME
# (default $CARGO_TARGET_DIR/avd). On Apple silicon only arm64-v8a images run.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
: "${ANDROID_HOME:?set ANDROID_HOME}"
export ANDROID_SDK_ROOT=$ANDROID_HOME
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
export ANDROID_AVD_HOME=${ANDROID_AVD_HOME:-$CARGO_TARGET_DIR/avd}
IMAGE=""
KEEP=0
PASS=()
while [ $# -gt 0 ]; do
  case $1 in
    --image) IMAGE=$2; shift ;;
    --keep) KEEP=1 ;;
    *) PASS+=("$1") ;;
  esac
  shift
done
[ -n "$IMAGE" ] || { echo "--image is required" >&2; exit 2; }
ADB="$ANDROID_HOME/platform-tools/adb"
export ADB
API=$(echo "$IMAGE" | sed -n 's/.*android-\([0-9]*\);.*/\1/p')
NAME="mousse-phone-spike-$API"
PORT=${EMU_PORT:-5584}
SERIAL="emulator-$PORT"
mkdir -p "$ANDROID_AVD_HOME"

# The AVD is written directly (avdmanager only sees the SDK it was installed in).
IFS=';' read -r _ PLATFORM TAG ABI <<< "$IMAGE"
SYSDIR="system-images/$PLATFORM/$TAG/$ABI/"
[ -d "$ANDROID_HOME/$SYSDIR" ] || { echo "system image $IMAGE is not installed in $ANDROID_HOME" >&2; exit 1; }
AVD="$ANDROID_AVD_HOME/$NAME.avd"
rm -rf "$AVD"
mkdir -p "$AVD"
printf 'avd.ini.encoding=UTF-8\npath=%s\ntarget=%s\n' "$AVD" "$PLATFORM" > "$ANDROID_AVD_HOME/$NAME.ini"
cat > "$AVD/config.ini" <<EOF
AvdId=$NAME
avd.ini.displayname=$NAME
abi.type=$ABI
hw.cpu.arch=$([ "$ABI" = arm64-v8a ] && echo arm64 || echo x86_64)
image.sysdir.1=$SYSDIR
tag.id=$TAG
hw.ramSize=3072
disk.dataPartition.size=4G
hw.lcd.width=1080
hw.lcd.height=2340
hw.lcd.density=440
hw.keyboard=yes
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
PlayStore.enabled=false
EOF
EMU_PID=""
cleanup() {
  [ -n "$EMU_PID" ] && { "$ADB" -s "$SERIAL" emu kill >/dev/null 2>&1 || true; sleep 2; kill "$EMU_PID" 2>/dev/null || true; wait "$EMU_PID" 2>/dev/null || true; }
  [ "$KEEP" = 1 ] || rm -rf "$AVD" "$ANDROID_AVD_HOME/$NAME.ini"
}
trap cleanup EXIT

"$ANDROID_HOME/emulator/emulator" -avd "$NAME" -port "$PORT" -no-window -no-audio -no-boot-anim \
  -no-snapshot -gpu swiftshader_indirect -memory 3072 > "$CARGO_TARGET_DIR/emulator-$API.log" 2>&1 &
EMU_PID=$!
echo "emulator $SERIAL ($IMAGE), pid $EMU_PID"
"$ADB" -s "$SERIAL" wait-for-device
for _ in $(seq 1 180); do
  [ "$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 2
done
[ "$("$ADB" -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')" = 1 ] || { echo "emulator did not boot" >&2; exit 1; }
"$ADB" -s "$SERIAL" shell input keyevent 82 >/dev/null 2>&1 || true
echo "booted: Android $("$ADB" -s "$SERIAL" shell getprop ro.build.version.release | tr -d '\r'), API $API," \
  "WebView $("$ADB" -s "$SERIAL" shell dumpsys webviewupdate 2>/dev/null | sed -n 's/.*Current WebView package.*(\(.*\)).*/\1/p' | head -1 | tr -d '\r')"

ANDROID_SERIAL=$SERIAL "$HERE/run.sh" "${PASS[@]+"${PASS[@]}"}"
