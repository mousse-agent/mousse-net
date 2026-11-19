#!/bin/sh
# Sign a relay release with the offline minisign key (docs/release.md).
#
#   release/sign.sh --key <minisign secret key> --pubkey <minisign public key> [--dist DIR]
#
# Run on the offline signing machine after release/build.sh and
# release/package.sh. Signs every artifact, SHA256SUMS, the image digest,
# install.sh and the cloud-init template (those present), each with the trusted comment
# "mousse-relay <version> <file name>" that install.sh checks, then verifies
# every signature with the public key. minisign asks for the key's password
# once per file.
set -eu

dist=dist
key=
pub=
while [ $# -gt 0 ]; do
  case $1 in
    --key) key=$2; shift 2 ;;
    --pubkey) pub=$2; shift 2 ;;
    --dist) dist=$2; shift 2 ;;
    *) echo "usage: release/sign.sh --key SECRET --pubkey PUBLIC [--dist DIR]" >&2; exit 2 ;;
  esac
done
[ -n "$key" ] && [ -n "$pub" ] || { echo "release/sign.sh: --key and --pubkey are required" >&2; exit 2; }
command -v minisign >/dev/null 2>&1 || { echo "release/sign.sh: needs minisign" >&2; exit 1; }

version=$(sed -n 's/^version=//p' "$dist/BUILD")
[ -n "$version" ] || { echo "release/sign.sh: no version in $dist/BUILD" >&2; exit 1; }

# The checksums must match the artifacts before anything is signed.
(cd "$dist" && sha256sum -c SHA256SUMS >/dev/null)
ls "$dist"/mousse-relay-*-linux-musl >/dev/null 2>&1 || { echo "release/sign.sh: no artifacts in $dist" >&2; exit 1; }

for f in "$dist"/mousse-relay-*-linux-musl "$dist/SHA256SUMS" "$dist/mousse-relay-image.digest" \
  "$dist/install.sh" "$dist/cloud-init.yaml"; do
  name=$(basename "$f")
  if [ ! -f "$f" ]; then
    echo "release/sign.sh: $name is not in $dist; not signed"
    continue
  fi
  rm -f "$f.minisig"
  minisign -S -s "$key" -m "$f" -x "$f.minisig" -t "mousse-relay $version $name" -c "mousse-relay release signature"
  minisign -V -q -p "$pub" -m "$f" -x "$f.minisig"
done
echo "Signed mousse-relay $version in $dist"
