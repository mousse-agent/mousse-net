#!/bin/sh
# Stamp the release version and public key into install.sh and the cloud-init
# template (docs/release.md).
#
#   release/package.sh [--pubkey FILE] [--dist DIR]
#
# FILE is a minisign public key file (default: release/minisign.pub, the
# release key; tests pass a throwaway one). Writes DIR/install.sh and
# DIR/cloud-init.yaml. The template carries the whole stamped installer, so it
# trusts nothing it downloads that is not signed by the key.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dist=dist
pub=$here/minisign.pub
while [ $# -gt 0 ]; do
  case $1 in
    --pubkey) pub=$2; shift 2 ;;
    --dist) dist=$2; shift 2 ;;
    *) echo "usage: release/package.sh [--pubkey FILE] [--dist DIR]" >&2; exit 2 ;;
  esac
done
[ -f "$pub" ] || { echo "release/package.sh: no public key at $pub" >&2; exit 1; }
version=$(sed -n 's/^version=//p' "$dist/BUILD")
[ -n "$version" ] || { echo "release/package.sh: no version in $dist/BUILD" >&2; exit 1; }

key=$(sed -n 2p "$pub" | tr -d '\r')
case $key in
  RW*) ;;
  *) echo "release/package.sh: $pub is not a minisign public key" >&2; exit 1 ;;
esac
case $version in
  *[!0-9A-Za-z.+-]*) echo "release/package.sh: bad version $version" >&2; exit 1 ;;
esac

sed -e "s|@MOUSSE_RELEASE_VERSION@|$version|" -e "s|@MOUSSE_RELEASE_PUBKEY@|$key|" \
  "$here/install.sh" >"$dist/install.sh"
if [ -n "$(sed -n '/@MOUSSE_RELEASE_/p' "$dist/install.sh")" ]; then
  echo "release/package.sh: install.sh still has a placeholder" >&2
  exit 1
fi

# The template: everything before the marker line, the installer indented
# into the write_files block, then everything after it.
awk -v version="$version" '
  FNR == NR { script = script "      " $0 "\n"; next }
  /^      @MOUSSE_INSTALL_SH@$/ { printf "%s", script; next }
  { gsub("@MOUSSE_RELEASE_VERSION@", version); print }
' "$dist/install.sh" "$here/cloud-init.yaml" >"$dist/cloud-init.yaml"
if [ -n "$(sed -n '/@MOUSSE_/p' "$dist/cloud-init.yaml")" ]; then
  echo "release/package.sh: cloud-init.yaml still has a placeholder" >&2
  exit 1
fi
echo "Packaged install.sh and cloud-init.yaml for mousse-relay $version"
