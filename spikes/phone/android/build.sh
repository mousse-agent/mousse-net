#!/usr/bin/env bash
# Builds the Android host app: the Rust library for each ABI with the NDK's clang,
# the Kotlin bindings with uniffi-bindgen, then the debug APK with Gradle.
#
#   ANDROID_HOME=<sdk> ANDROID_NDK_HOME=<ndk> android/build.sh [abi ...]
#
# ABIs default to arm64-v8a and x86_64. MIN_API (default 24) is the API level the
# Rust code links against and must match minSdk in app/build.gradle.kts. GRADLE
# defaults to ./gradlew; JAVA_HOME must be a JDK 17 or 21.
# Output: android/app/build/outputs/apk/debug/app-debug.apk
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an NDK (r28 tested)}"
MIN_API=${MIN_API:-24}
ABIS=("$@")
[ ${#ABIS[@]} -gt 0 ] || ABIS=(arm64-v8a x86_64)
HOST_TAG=darwin-x86_64
[ "$(uname -s)" = Linux ] && HOST_TAG=linux-x86_64
TC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
OUTDIR="$HERE/app/build/rust"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR/kotlin"

cd "$ROOT"
for ABI in "${ABIS[@]}"; do
  case $ABI in
    arm64-v8a) T=aarch64-linux-android ;;
    x86_64) T=x86_64-linux-android ;;
    armeabi-v7a) T=armv7-linux-androideabi ;;
    x86) T=i686-linux-android ;;
    *) echo "unknown ABI $ABI" >&2; exit 2 ;;
  esac
  CLANG_T=$T
  [ "$ABI" = armeabi-v7a ] && CLANG_T=armv7a-linux-androideabi
  U=$(echo "$T" | tr 'a-z-' 'A-Z_')
  L=$(echo "$T" | tr '-' '_')
  env "CARGO_TARGET_${U}_LINKER=$TC/${CLANG_T}${MIN_API}-clang" \
      "CC_${L}=$TC/${CLANG_T}${MIN_API}-clang" \
      "AR_${L}=$TC/llvm-ar" \
      cargo build --release --locked -p mousse-phone-spike --lib --target "$T"
  mkdir -p "$OUTDIR/jniLibs/$ABI"
  cp "$CARGO_TARGET_DIR/$T/release/libmousse_phone_spike.so" "$OUTDIR/jniLibs/$ABI/"
  FIRST_LIB=${FIRST_LIB:-$CARGO_TARGET_DIR/$T/release/libmousse_phone_spike.so}
done

cargo build --release --locked -p uniffi-bindgen
"$CARGO_TARGET_DIR/release/uniffi-bindgen" generate --library "$FIRST_LIB" --language kotlin \
  --no-format --out-dir "$OUTDIR/kotlin"

cd "$HERE"
${GRADLE:-./gradlew} --console=plain -q assembleDebug
echo "built $HERE/app/build/outputs/apk/debug/app-debug.apk (${ABIS[*]}, min API $MIN_API)"
