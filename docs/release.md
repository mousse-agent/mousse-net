# Relay releases

How a `mousse-relay` release is built, signed and installed (design
`docs/phase34-design.md` §B.15). Everything is in `release/`.

## What a release holds

| File | What |
|---|---|
| `mousse-relay-x86_64-unknown-linux-musl`, `mousse-relay-aarch64-unknown-linux-musl` | static relay binaries |
| `SHA256SUMS` | their checksums |
| `mousse-relay-image.oci.tar` | the relay image for both platforms, OCI layout |
| `mousse-relay-image.digest` | the image's index digest, to pin it by |
| `install.sh` | the one-command installer, with the release key and version in it |
| `cloud-init.yaml` | the VPS template, with the installer in it |
| `<file>.minisig` | a minisign signature for each file above, except the image tarball (its digest is signed) |
| `BUILD` | commit, version, `SOURCE_DATE_EPOCH`, builder image |

Every signature's trusted comment is `mousse-relay <version> <file name>`.
`install.sh` checks it, so a genuine older release served as a newer one is
refused.

## Building (reproducible)

    release/build.sh            # needs git and Docker with BuildKit

- The source is `git archive` of the commit, never the working tree; a dirty
  tree is refused.
- Crates are vendored from `Cargo.lock`; the build then runs with
  `--locked --offline` and no network.
- The toolchain is the builder image pinned by digest in
  `release/toolchain.env` (Rust 1.96.0 on Alpine, musl host). Each platform
  builds natively in its own image variant (arm64 under emulation on an
  x86_64 machine).
- `build-in-container.sh` fixes every path the compiler sees (`/build/...`),
  remaps them (`--remap-path-prefix`, `-ffile-prefix-map`), sets
  `SOURCE_DATE_EPOCH` to the commit time, `TZ=UTC` and `LC_ALL=C`, links
  statically (`+crt-static`) and refuses a binary with a dynamic loader.
- The image is built from the binaries with `--network none` and
  `rewrite-timestamp=true`, so its digest is reproducible too.

Anyone can rebuild a release and compare `SHA256SUMS`. The
`phase3.reproducible` check does this with two builds in separate containers
with different mount paths, job counts and time zones.

## Signing (offline)

The release key is a minisign key kept offline. Its public key goes in
`release/minisign.pub` (committed when the key is made; until then,
`release/package.sh` has no default key).

    minisign -G -p release/minisign.pub -s <offline>/mousse-relay.key   # once
    release/package.sh --dist dist        # stamps the version and public key
    release/sign.sh --key <offline>/mousse-relay.key --pubkey release/minisign.pub --dist dist

Copy `dist/` to the offline machine for `sign.sh` and back. `sign.sh` checks
`SHA256SUMS` first, then signs and verifies each file.

Publishing: upload the files to the GitHub release `relay-v<version>`, and
push the image with its digest kept, for example
`skopeo copy oci-archive:dist/mousse-relay-image.oci.tar docker://ghcr.io/mousse-agent/mousse-relay:<version>`.

## Installing

### One command

    curl -fsSL https://github.com/mousse-agent/mousse-net/releases/download/relay-v<version>/install.sh | sudo sh -s -- --public <ip or name>

`install.sh`, on Linux with systemd (x86_64 or arm64):

1. Downloads `SHA256SUMS`, the binary for this machine, and their
   signatures, over HTTPS only.
2. Verifies both signatures with the key written into it, and the checksum.
   The check uses OpenSSL 3 (Ed25519 and BLAKE2b-512, minisign's prehashed
   format), so nothing extra is installed. Anything unsigned, signed by
   another key, for another version, or changed is refused, and nothing is
   installed.
3. Places the binary at `/usr/local/bin/mousse-relay`, creates the
   `mousse-relay` system user and `/var/lib/mousse-relay` (mode 0700).
4. On a new state directory, runs `mousse-relay init --public <host:port>`
   as that user. `--public auto` (the default) takes the first public
   address on the server's interfaces; behind a provider's NAT, pass it.
5. Writes `mousse-relay.service`: runs as `mousse-relay`, with
   `CAP_NET_BIND_SERVICE` as its only capability (bounding and ambient),
   `NoNewPrivileges`, `LimitCORE=0`, a read-only system except the state
   directory, and the usual systemd sandboxing. Enables and starts it.
6. Prints the enrollment link.

`install.sh --verify-only` downloads and checks a release without installing
anything (no root needed).

**Upgrade:** run `install.sh` again (or `sudo mousse-relay-install --version
<new>` on a server set up by the template). An existing state directory is
kept, so the relay identity and its authorized list survive; no new link is
made. More enrollment links: `sudo -u mousse-relay mousse-relay enroll --state
/var/lib/mousse-relay`.

### Docker

`release/compose.yaml`: the image pinned by its signed digest, a read-only
root, all capabilities dropped (Docker lets an unprivileged process bind 443
inside the container), `no-new-privileges`, core dumps off and one named
volume at `/state`. The image is `scratch` plus the static binary: no shell,
no package manager, user 65532. The relay sets its own core-dump limit
to 0 at start and makes its process non-dumpable (`PR_SET_DUMPABLE` 0),
so dumps stay off without a shell to run `ulimit -c 0` (design §B.16).

    docker compose run --rm relay init --state /state --public <ip or name>:443
    docker compose up -d

Upgrades change the digest and keep the volume.

### The template

`cloud-init.yaml` is plain user data for any VPS that takes cloud-init
(Ubuntu 22.04+, Debian 12+). It writes the stamped installer to
`/usr/local/sbin/mousse-relay-install` and runs it on first boot; the output,
with the enrollment link, is in `/root/mousse-relay.txt`. It trusts nothing
it downloads that is not signed by the key in it. Platforms that end TLS at
their own proxy cannot carry the relay's pinned key and wait for Phase 5's
browser profile.

## Checks

`node release/tests/check.mjs reproducible|install --out <dir> [--control <name>]`
(`checks/phase3.toml`). They run on any machine with Docker, git, cargo and
node; on the PC only on an `--internal` network. Signing keys are throwaway
ones made under `<dir>`. The Ubuntu 24.04 cloud image root (what a VPS boots)
and minisign 0.12 are fetched once, by pinned SHA-256.

- `phase3.reproducible`: two builds are byte-identical; minisign and
  `install.sh` accept the signed release; `install.sh` refuses an unsigned
  download, a changed binary, a release re-signed by another key and an older
  release served as this one. Control `unsigned-accepted`.
- `phase3.install`: on a fresh cloud image with systemd, `install.sh` gives an
  enrollment link for the public address, the service runs as
  `mousse-relay` with only `CAP_NET_BIND_SERVICE`, `status --json` names the
  linked relay, and an upgrade keeps it; a tampered download leaves no
  binary, unit or user; the cloud-init template does the same on first boot;
  the image has no shell and an unprivileged user, runs read-only, accepts on
  443 and keeps its identity in the volume across restarts; the relay
  sets its own core-dump limit to 0 even where the container allows dumps.
  Control `skip-verify`.
- `phase3.outside-template` is a manual step: an independent tester deploys
  and upgrades the template on their own VPS.
