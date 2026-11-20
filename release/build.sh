#!/bin/sh
# Build a relay release from the current commit, reproducibly (docs/release.md).
#
#   release/build.sh [--out DIR] [--platform linux/amd64] [--vendor DIR] [--allow-dirty]
#
# Needs git and Docker with BuildKit. The source is `git archive HEAD`, the
# crates are vendored from Cargo.lock, and each platform builds offline
# (`--network none`) in the pinned builder image (release/toolchain.env), so
# anyone with the same commit gets the same bytes. Writes to DIR (default
# dist/):
#   mousse-relay-<target>          static musl binaries
#   SHA256SUMS                     their checksums
#   mousse-relay-image.oci.tar     the relay image (all platforms), OCI layout
#   mousse-relay-image.digest      the image's index digest
#   BUILD                          commit, version, epoch and builder
# Signing is a separate, offline step: release/sign.sh.
#
# --vendor DIR uses crates already vendored for this Cargo.lock
# (`cargo vendor --locked --versioned-dirs DIR`) instead of vendoring them in
# the builder with network access; cargo checks them against the lock either
# way.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=$root/dist
platforms=
allow_dirty=
vendor=
while [ $# -gt 0 ]; do
  case $1 in
    --out) out=$2; shift 2 ;;
    --platform) platforms="$platforms $2"; shift 2 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    --vendor) vendor=$(cd "$2" && pwd); shift 2 ;;
    *) echo "usage: release/build.sh [--out DIR] [--platform P]... [--vendor DIR] [--allow-dirty]" >&2; exit 2 ;;
  esac
done

conf() { sed -n "s/^$1=//p" "$here/toolchain.env"; }
builder=$(conf BUILDER_IMAGE)
buildkit=$(conf BUILDKIT_IMAGE)
packages=$(conf PACKAGES)
[ -n "$platforms" ] || platforms=$(conf PLATFORMS)

# Docker on Windows (Git Bash) wants Windows paths and no path rewriting.
export MSYS_NO_PATHCONV=1
hostpath() { (cd "$1" && { pwd -W 2>/dev/null || pwd; }); }

cd "$root"
if [ -z "$allow_dirty" ] && [ -n "$(git status --porcelain)" ]; then
  echo "release/build.sh: the tree has uncommitted changes; a release builds a commit" >&2
  exit 1
fi
commit=$(git rev-parse HEAD)
epoch=$(git log -1 --format=%ct HEAD)
version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
[ -n "$version" ] || { echo "release/build.sh: no workspace version in Cargo.toml" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/src" "$work/vendor" "$out"
git archive --format=tar "$commit" | tar -x -C "$work/src"

if [ -n "$vendor" ]; then
  rmdir "$work/vendor"
  cp -R "$vendor" "$work/vendor"
else
  echo "Vendoring crates for $commit"
  docker run --rm -v "$(hostpath "$work/src"):/in/src:ro" -v "$(hostpath "$work/vendor"):/in/vendor" \
    -w /in/src "$builder" sh -c 'cargo vendor --locked --versioned-dirs /in/vendor >/dev/null'
fi

: >"$out/SHA256SUMS.all"
for platform in $platforms; do
  echo "Building $packages for $platform"
  docker run --rm --platform "$platform" --network none \
    -v "$(hostpath "$work/src"):/in/src:ro" -v "$(hostpath "$work/vendor"):/in/vendor:ro" \
    -v "$(hostpath "$out"):/out" \
    -e SRC=/in/src -e VENDOR=/in/vendor -e OUT=/out -e PACKAGES="$packages" \
    -e SOURCE_DATE_EPOCH="$epoch" -e MOUSSE_BUILD_ID="$commit+release" \
    "$builder" sh /in/src/release/build-in-container.sh
  cat "$out"/SHA256SUMS.*-linux-musl >>"$out/SHA256SUMS.all"
  rm -f "$out"/SHA256SUMS.*-linux-musl
done
sort -k2 "$out/SHA256SUMS.all" >"$out/SHA256SUMS"
rm -f "$out/SHA256SUMS.all"

echo "Building the relay image"
plats=$(printf '%s' "$platforms" | sed 's/^ *//; s/ \{1,\}/,/g')
mkdir -p "$work/image/state"
cp "$out"/mousse-relay-*-linux-musl "$work/image/"
# A throwaway builder on the pinned BuildKit, with no network.
bx="mousse-release-$$"
docker buildx create --name "$bx" --driver docker-container \
  --driver-opt "image=$buildkit,network=none" --bootstrap >/dev/null
trap 'docker buildx rm -f "$bx" >/dev/null 2>&1; rm -rf "$work"' EXIT INT TERM
docker buildx build --builder "$bx" --platform "$plats" --network none --no-cache \
  --provenance=false --sbom=false \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --output "type=oci,dest=$(hostpath "$out")/mousse-relay-image.oci.tar,rewrite-timestamp=true" \
  -f "$(hostpath "$here")/relay.Dockerfile" "$(hostpath "$work/image")"
digest=$(tar -xOf "$out/mousse-relay-image.oci.tar" index.json |
  sed -n 's/.*"digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | head -n 1)
[ -n "$digest" ] || { echo "release/build.sh: no digest in the image's index.json" >&2; exit 1; }
printf '%s  mousse-relay:%s\n' "$digest" "$version" >"$out/mousse-relay-image.digest"

cat >"$out/BUILD" <<EOF
commit=$commit
version=$version
source_date_epoch=$epoch
builder=$builder
buildkit=$buildkit
platforms=$platforms
EOF
echo "Done: $out"
cat "$out/SHA256SUMS" "$out/mousse-relay-image.digest"
