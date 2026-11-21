#!/bin/sh
# Reproducible release build, run inside the pinned builder image
# (release/toolchain.env). Called by release/build.sh and by the
# phase3.reproducible check; see docs/release.md.
#
# Inputs (environment):
#   SRC                 the source tree (read-only is fine): a `git archive` of
#                       the release commit, never a working checkout
#   VENDOR              `cargo vendor --locked --versioned-dirs` output for
#                       that Cargo.lock (read-only is fine)
#   OUT                 where the artifacts and SHA256SUMS go
#   PACKAGES            packages to build (default: mousse-relay)
#   SOURCE_DATE_EPOCH   the release commit's time
#   MOUSSE_BUILD_ID     the build id baked in (`<commit>+release`)
#
# Every path the compiler can see is fixed here (/build/...), whatever the
# mounts are called, and then remapped, so two builds on two machines see the
# same paths. The build runs offline (--locked --offline) from the vendored
# sources, as root in a throwaway container.
set -eu

: "${SRC:?}" "${VENDOR:?}" "${OUT:?}" "${SOURCE_DATE_EPOCH:?}" "${MOUSSE_BUILD_ID:?}"
PACKAGES=${PACKAGES:-mousse-relay}

case $(uname -m) in
  x86_64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "build-in-container: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac
host=$(rustc -vV | sed -n 's/^host: //p')
[ "$host" = "$TARGET" ] || { echo "build-in-container: builder host is $host, expected $TARGET" >&2; exit 1; }

ROOT=/build
rm -rf "$ROOT"
mkdir -p "$ROOT/cargo" "$ROOT/target" "$OUT"
cp -a "$SRC" "$ROOT/mousse-net"
cp -a "$VENDOR" "$ROOT/vendor"

export CARGO_HOME="$ROOT/cargo"
export CARGO_TARGET_DIR="$ROOT/target"
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
cat >"$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "$ROOT/vendor"
[net]
offline = true
EOF

export TZ=UTC LC_ALL=C LANG=C
remap="--remap-path-prefix=$ROOT/mousse-net=/mousse-net --remap-path-prefix=$ROOT/vendor=/cargo/vendor --remap-path-prefix=$ROOT/cargo=/cargo"
export RUSTFLAGS="-C target-feature=+crt-static $remap"
# C sources (aws-lc) see the same fixed paths.
cflags="-ffile-prefix-map=$ROOT/mousse-net=/mousse-net -ffile-prefix-map=$ROOT/vendor=/cargo/vendor -ffile-prefix-map=$ROOT/target=/target"
export CFLAGS="$cflags" CXXFLAGS="$cflags"
export ZERO_AR_DATE=1

cd "$ROOT/mousse-net"
args=
for p in $PACKAGES; do args="$args -p $p"; done
# shellcheck disable=SC2086
cargo build --release --locked --offline --target "$TARGET" $args

: >"$OUT/SHA256SUMS.$TARGET"
for p in $PACKAGES; do
  bin="$CARGO_TARGET_DIR/$TARGET/release/$p"
  # A static binary has no interpreter (no dynamic loader).
  if readelf -l "$bin" 2>/dev/null | awk '/INTERP/ { found = 1 } END { exit !found }'; then
    echo "build-in-container: $p is not statically linked" >&2
    exit 1
  fi
  name="$p-$TARGET"
  cp "$bin" "$OUT/$name"
  touch -d "@$SOURCE_DATE_EPOCH" "$OUT/$name"
  (cd "$OUT" && sha256sum "$name") >>"$OUT/SHA256SUMS.$TARGET"
done
cat "$OUT/SHA256SUMS.$TARGET"
