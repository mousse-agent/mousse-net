#!/bin/sh
# Install or upgrade a self-hosted mousse-relay on a Linux server with systemd.
#
#   curl -fsSL <release>/install.sh | sudo sh -s -- --public <ip or name>[:port]
#
# It downloads the relay for this machine, refuses it unless the release
# signature (minisign, public key below) and the checksums verify, places the
# binary, creates the `mousse-relay` service user and a systemd unit whose only
# capability is CAP_NET_BIND_SERVICE, runs `mousse-relay init` on a new state
# directory and prints the enrollment link. Run again to upgrade: the state
# directory, and with it the relay identity, is kept.
#
# The release pipeline stamps the version and the public key into this file
# (release/package.sh). An unstamped copy refuses to run.
set -eu

RELEASE_VERSION="@MOUSSE_RELEASE_VERSION@"
# The second line of the release's minisign public key file.
RELEASE_PUBKEY="@MOUSSE_RELEASE_PUBKEY@"
RELEASE_URL="https://github.com/mousse-agent/mousse-net/releases/download/relay-v${RELEASE_VERSION}"

BIN=/usr/local/bin/mousse-relay
STATE=/var/lib/mousse-relay
UNIT=/etc/systemd/system/mousse-relay.service
SERVICE_USER=mousse-relay

die() {
  printf 'mousse-relay install: %s\n' "$*" >&2
  exit 1
}
say() { printf '%s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: install.sh [--public HOST[:PORT]] [--from URL|DIR] [--version X.Y.Z] [--verify-only]

  --public   The address phones and computers dial: this server's public IP or
             DNS name, port 443 unless given. "auto" (the default) takes the
             first public address on this server's interfaces. Used once, by
             `mousse-relay init` on a new state directory.
  --from     Where the release files are: an https:// URL or a local folder
             (default: this release on GitHub).
  --version  The release to install (default: the one this script came with).
  --verify-only  Download and check the release, install nothing (no root needed).
EOF
}

PUBLIC=auto
FROM=${MOUSSE_RELAY_FROM:-}
VERSION=$RELEASE_VERSION
VERIFY_ONLY=
while [ $# -gt 0 ]; do
  case $1 in
    --public) [ $# -ge 2 ] || die "--public needs a value"; PUBLIC=$2; shift 2 ;;
    --public=*) PUBLIC=${1#--public=}; shift ;;
    --from) [ $# -ge 2 ] || die "--from needs a value"; FROM=$2; shift 2 ;;
    --from=*) FROM=${1#--from=}; shift ;;
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
    --version=*) VERSION=${1#--version=}; shift ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

case $RELEASE_PUBKEY in
  @*) die "this copy of install.sh has no release key stamped in; download install.sh from a release" ;;
esac
case $VERSION in
  ''|*[!0-9A-Za-z.+-]*) die "bad version: $VERSION" ;;
esac
if [ -z "$FROM" ]; then
  if [ "$VERSION" = "$RELEASE_VERSION" ]; then
    FROM=$RELEASE_URL
  else
    FROM="https://github.com/mousse-agent/mousse-net/releases/download/relay-v${VERSION}"
  fi
fi

# --- Checks before anything is touched ---------------------------------------

[ "$(uname -s)" = Linux ] || die "the relay installs on Linux only"
[ -n "$VERIFY_ONLY" ] || [ "$(id -u)" = 0 ] || die "run as root (sudo sh)"
case $(uname -m) in
  x86_64|amd64) TARGET=x86_64-unknown-linux-musl ;;
  aarch64|arm64) TARGET=aarch64-unknown-linux-musl ;;
  *) die "no relay build for $(uname -m)" ;;
esac
ARTIFACT="mousse-relay-$TARGET"

for tool in openssl od dd; do
  command -v "$tool" >/dev/null 2>&1 || die "needs $tool"
done
case $(openssl version 2>/dev/null) in
  "OpenSSL 3."*|"OpenSSL 4."*) ;;
  *) die "needs OpenSSL 3 or later to check the release signature" ;;
esac
if [ -z "$VERIFY_ONLY" ]; then
  [ -d /run/systemd/system ] || die "needs systemd (for Docker, use the relay image instead)"
  command -v systemctl >/dev/null 2>&1 || die "needs systemctl"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
umask 077

# --- Download ----------------------------------------------------------------

fetch() { # fetch <name>: copy <FROM>/<name> to $WORK/<name>
  case $FROM in
    https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$1" "$FROM/$1" || die "download failed: $FROM/$1"
      elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$WORK/$1" "$FROM/$1" || die "download failed: $FROM/$1"
      else
        die "needs curl or wget"
      fi ;;
    http://*) die "refusing a plain http download: $FROM" ;;
    file://*) cp "${FROM#file://}/$1" "$WORK/$1" 2>/dev/null || die "missing: $FROM/$1" ;;
    *://*) die "unsupported download address: $FROM" ;;
    *) cp "$FROM/$1" "$WORK/$1" 2>/dev/null || die "missing: $FROM/$1" ;;
  esac
}

# --- minisign signature check (OpenSSL) ---------------------------------------
#
# Formats: https://jedisct1.github.io/minisign/. The public key is "Ed", an
# 8-byte key id and the 32-byte Ed25519 key. A signature file has four lines:
# an untrusted comment, base64("ED" || key id || Ed25519(BLAKE2b-512(file))),
# "trusted comment: <text>", and base64(Ed25519(signature || text)). Only
# prehashed ("ED") signatures are accepted.

hex() { od -An -v -tx1 "$1" | tr -d ' \n'; }
b64d() { printf '%s' "$1" | openssl base64 -d -A >"$2" 2>/dev/null; }
size() { wc -c <"$1" | tr -d ' '; }
cut_bytes() { dd if="$1" of="$4" bs=1 skip="$2" count="$3" 2>/dev/null; }

PK_DONE=
public_key() {
  [ -n "$PK_DONE" ] && return 0
  b64d "$RELEASE_PUBKEY" "$WORK/pk.bin" || die "bad embedded public key"
  [ "$(size "$WORK/pk.bin")" = 42 ] || die "bad embedded public key"
  [ "$(cut_bytes "$WORK/pk.bin" 0 2 /dev/stdout)" = Ed ] || die "bad embedded public key"
  cut_bytes "$WORK/pk.bin" 2 8 "$WORK/pk.id"
  # DER SubjectPublicKeyInfo for Ed25519: a fixed 12-byte prefix, then the key.
  printf '\060\052\060\005\006\003\053\145\160\003\041\000' >"$WORK/pk.der"
  cut_bytes "$WORK/pk.bin" 10 32 "$WORK/pk.raw"
  cat "$WORK/pk.raw" >>"$WORK/pk.der"
  PK_DONE=1
}

ed25519_verify() { # ed25519_verify <message file> <64-byte signature file>
  openssl pkeyutl -verify -pubin -inkey "$WORK/pk.der" -keyform DER -rawin \
    -in "$1" -sigfile "$2" >/dev/null 2>&1
}

# minisig_verify <file> <signature file> <expected trusted comment>
minisig_verify() {
  public_key
  f=$1 sig=$2 want=$3 s="$WORK/sig.parse"
  [ -f "$sig" ] || return 1
  # Exactly four lines, no carriage returns.
  [ "$(wc -l <"$sig" | tr -d ' ')" = 4 ] || return 1
  case $(cat "$sig") in *"$(printf '\015')"*) return 1 ;; esac
  case $(sed -n 1p "$sig") in "untrusted comment: "*) ;; *) return 1 ;; esac
  b64d "$(sed -n 2p "$sig")" "$s.bin" || return 1
  [ "$(size "$s.bin")" = 74 ] || return 1
  [ "$(cut_bytes "$s.bin" 0 2 /dev/stdout)" = ED ] || return 1
  cut_bytes "$s.bin" 2 8 "$s.id"
  [ "$(hex "$s.id")" = "$(hex "$WORK/pk.id")" ] || return 1
  cut_bytes "$s.bin" 10 64 "$s.sig"
  line3=$(sed -n 3p "$sig")
  case $line3 in "trusted comment: "*) ;; *) return 1 ;; esac
  tc=${line3#trusted comment: }
  [ "$tc" = "$want" ] || return 1
  b64d "$(sed -n 4p "$sig")" "$s.global" || return 1
  [ "$(size "$s.global")" = 64 ] || return 1
  openssl dgst -blake2b512 -binary "$f" >"$s.hash" 2>/dev/null || return 1
  [ "$(size "$s.hash")" = 64 ] || return 1
  ed25519_verify "$s.hash" "$s.sig" || return 1
  { cat "$s.sig"; printf '%s' "$tc"; } >"$s.signed"
  ed25519_verify "$s.signed" "$s.global" || return 1
  return 0
}

sha256_of() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }

# verify_release: the checksums file and the artifact are both signed by the
# release key for this version, and the artifact matches its checksum line.
verify_release() {
  minisig_verify "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.minisig" "mousse-relay $VERSION SHA256SUMS" ||
    die "SHA256SUMS is not signed by the release key for $VERSION; nothing installed"
  minisig_verify "$WORK/$ARTIFACT" "$WORK/$ARTIFACT.minisig" "mousse-relay $VERSION $ARTIFACT" ||
    die "$ARTIFACT is not signed by the release key for $VERSION; nothing installed"
  want=$(awk -v n="$ARTIFACT" '$2 == n || $2 == "*" n { print $1 }' "$WORK/SHA256SUMS")
  [ -n "$want" ] && [ "$(printf '%s\n' "$want" | wc -l | tr -d ' ')" = 1 ] ||
    die "SHA256SUMS has no single line for $ARTIFACT; nothing installed"
  [ "$(sha256_of "$WORK/$ARTIFACT")" = "$want" ] ||
    die "$ARTIFACT does not match SHA256SUMS; nothing installed"
}

say "Downloading mousse-relay $VERSION for $TARGET"
fetch SHA256SUMS
fetch "$ARTIFACT"
# A missing signature is not a download error: verify_release refuses it.
for name in SHA256SUMS.minisig "$ARTIFACT.minisig"; do
  (fetch "$name") 2>/dev/null || rm -f "$WORK/$name"
done
verify_release
say "Signature and checksum verified"
if [ -n "$VERIFY_ONLY" ]; then
  say "Verified mousse-relay $VERSION for $TARGET; nothing installed"
  exit 0
fi

# --- Public address ----------------------------------------------------------

private_v4() {
  case $1 in
    10.*|127.*|0.*|169.254.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
  esac
  return 1
}

detect_public() {
  command -v ip >/dev/null 2>&1 || return 1
  for a in $(ip -o -4 addr show scope global 2>/dev/null | awk '{ sub("/.*", "", $4); print $4 }'); do
    private_v4 "$a" || { printf '%s' "$a"; return 0; }
  done
  for a in $(ip -o -6 addr show scope global 2>/dev/null | awk '{ sub("/.*", "", $4); print $4 }'); do
    case $a in fc*|fd*) ;; *) printf '[%s]' "$a"; return 0 ;; esac
  done
  return 1
}

# --- Install -----------------------------------------------------------------

FIRST=
if [ -z "$(ls -A "$STATE" 2>/dev/null)" ]; then
  FIRST=1
fi
if [ -n "$FIRST" ]; then
  if [ "$PUBLIC" = auto ]; then
    PUBLIC=$(detect_public) || die "no public address found on this server; pass --public <ip or name>[:port]"
  fi
  case $PUBLIC in
    *\]:*|[!\[]*:*) ;;
    *) PUBLIC="$PUBLIC:443" ;;
  esac
fi

install -d -m 0755 /usr/local/bin
install -m 0755 "$WORK/$ARTIFACT" "$BIN.new"
mv -f "$BIN.new" "$BIN"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$STATE" --no-create-home \
      --shell /usr/sbin/nologin "$SERVICE_USER"
  else
    adduser -S -D -H -h "$STATE" -s /sbin/nologin "$SERVICE_USER"
  fi
fi
install -d -m 0700 -o "$SERVICE_USER" -g "$(id -gn "$SERVICE_USER")" "$STATE"

as_service_user() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$SERVICE_USER" -- "$@"
  else
    setpriv --reuid="$SERVICE_USER" --regid="$(id -gn "$SERVICE_USER")" --init-groups -- "$@"
  fi
}

LINK=
if [ -n "$FIRST" ]; then
  out=$(as_service_user "$BIN" init --state "$STATE" --public "$PUBLIC") || die "mousse-relay init failed"
  LINK=$(printf '%s\n' "$out" | awk '/^mousse-relay:\/\// { print; exit }')
  [ -n "$LINK" ] || die "mousse-relay init printed no enrollment link"
fi

cat >"$UNIT.new" <<EOF
[Unit]
Description=Mousse relay (self-hosted)
Documentation=https://github.com/mousse-agent/mousse-net
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$(id -gn "$SERVICE_USER")
ExecStart=$BIN serve --state $STATE
Restart=on-failure
RestartSec=2
# Only the right to bind ports below 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
LimitCORE=0
UMask=0077
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$STATE
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT.new"
mv -f "$UNIT.new" "$UNIT"
systemctl daemon-reload
systemctl enable mousse-relay.service >/dev/null 2>&1
systemctl restart mousse-relay.service

say "mousse-relay $VERSION installed and running ($BIN, state in $STATE)"
if [ -n "$LINK" ]; then
  say ""
  say "Enrollment link (single use, paste it in Mousse: Settings, Reach, Your own relay):"
  say "$LINK"
  say ""
  say "Another endpoint: sudo -u $SERVICE_USER $BIN enroll --state $STATE"
else
  say "Upgrade: the relay identity and its authorized list were kept."
fi
