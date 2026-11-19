# Phase 1b design: user routes, the CLI and "Send link"

Status: **frozen** after the final review (2026-11-18). No more review
rounds; implementation follows §15. Scope: PLAN
"Phase 1b" (`tcp` to a tailnet or port forward, `ssh-stdio`, `ws` through a
user tunnel, the CLI and remaining RPC, "Send link" with CPace).

- **Engine base:** `phase-1a` at `aba51a4`. Line references are against it.
- **App base:** Mousse `net-engine-1a` at `2aea454c6` (M6), plus M5b and M7
  when they land. 1b builds on 1a's §5 pairing, §7 UI and §9 kit. App
  line references are against M5b (`5b3e78f74`).
- **One PR per repo.** The slices in §15 are commit series on `phase-1b`
  (engine) and `net-engine-1b` (app). Each repo's phase lands as one PR.

**Goal:** the 1a app checks pass over each route — `tcp`, `ws` and
`ssh-stdio` — with Plus unreachable. A computer can be added over SSH, or
by a chat link and a typed code. Six desktop builds exist and pass a smoke
check.

CPace passed its Phase 0 review (`checks/reviews/phase0-design-review.md`,
part B), so "Send link" is in scope and its checks are not DEFERRED.

## Decisions

1. **A route is a pipe kind plus an address.** `tcp`, `ws`/`wss` and `ssh`
   each yield a `Pipe` (`pipe.rs:17`). TLS, step 2, the mux and every gate
   above them are unchanged. No route adds an authentication path of its
   own.
2. **Destinations are approved before first use** (§1.3). 1a's automatic
   rule stays: private-range `tcp` IP literals. Every other destination is
   shown to the owner and approved first, and the approval is stored with
   its source. A peer can never make this computer run `ssh`. Loopback is
   dialled in release builds only as an owner-entered plain `ws` address,
   the local hop of a tunnel client.
3. **Dial in bounded tiers:** `tcp`, then `ws` after a head start, then
   `ssh` (§1.4). An SSH login is never raced against a LAN path, unless the
   last working route was SSH.
4. **Adding over SSH is its own bootstrap** (§3.4). It uses no invitation,
   no CPace and no wire change. After the owner consents on A, B grants A
   through its daemon, and A pins B from the reply of the verified SSH
   session. Access is then confirmed over an ordinary engine session.
5. **The remote end of `ssh-stdio` is the running helper,** reached through
   its owner-only local IPC by `mousse-helper pipe` (§3.3). The pipe never
   touches the keystore, which an SSH session often cannot unlock on
   Windows or macOS. SSH never starts the daemon.
6. **SSH add is one way only in 1b.** A gets a grant on B. Both sides'
   rows carry `source: "ssh"`, which 1a's pairback and recovery skip
   (§3.6).
7. **The `ws` listener is loopback only,** for the user's own tunnel
   client. It refuses any request carrying `Origin`; browsers come in
   Phase 5.
8. **Kind-2 joins never take the consented path** (§5.4). Wire rule 10.6.8
   holds as written. Late recovery uses the ticket's genuine pending
   record in the existing durable flow store. The app promotes a row only
   on that ticket's completion record.
9. **Pre-auth admission per listener kind** (§6.2). Capacity is taken at
   accept, before any byte is read. The pipe has its own pool. The
   removal-pause fence is checked inside `Host` at gate registration and
   at enrollment, for every transport.
10. **The CLI is `mousse-cli net-engine`** through the daemon's owner-only
    IPC, for profiles the app runs. Standalone `mousse-helper serve`
    (headless, no app) keeps its own CLI (§8). The two never drive the same
    endpoint.
11. **Start at login reuses the existing startup entry** (§10). The app
    asks once when networking is first turned on. Helpers still start after
    the daemon is ready.
12. **No hard-coded limits.** Every new timeout, cap, gap and size is a
    named default with a `MOUSSE_NET_*` (helper) or `MOUSSE_NET_ENGINE_*`
    (app) override, listed in §13.3. Peer-bound and security-bound ones
    only tighten.
13. **Plus has no role.** No 1b path contacts Plus. App checks point Plus
    at an observing stand-in that denies everything, and fail on any
    attempt (§14).

## 1. Routes

### 1.1 Kinds

| Kind | Hint form | Pipe | Sources |
|---|---|---|---|
| `tcp` | `tcp://<host>:<port>` (wire 10.2.1, unchanged) | `TcpStream` | tickets, pairback routes, owner addresses |
| `wss` | `wss://<host>[:<port>]<path>` | `WsPipe` (§4) | tickets, pairback routes, owner addresses |
| `ws` | `ws://<loopback>:<port><path>` | `WsPipe` | owner addresses only |
| `ssh` | `ssh://[<user>@]<target>[:<port>]` | `SshPipe` (§3) | owner addresses only; never on the wire |

- **`ws`/`wss` grammar:** the 10.2.1 host and port rules. The path is at
  most 200 bytes of ASCII `[A-Za-z0-9._~/-]`, starts with `/` and ends with
  `/mousse-net/1`. There is no user part, query or fragment. The default
  port is 443 for `wss`. A plain `ws` host must be a loopback literal
  (`127.0.0.0/8` or `::1`) and needs a port.
- **`ssh` grammar:** a user of 1 to 64 bytes from `[A-Za-z0-9._-]`, not
  starting with `-`. A target is an IP literal or a name of 1 to 253 bytes
  from `[A-Za-z0-9._-]`, not starting with `-`. `_` is allowed so that
  `~/.ssh/config` aliases work. The target is resolved by `ssh -G` once,
  at setup (§3.1).
- **Spec:** wire.md 10.2.1 moves `wss` from "reserved" to defined, with the
  path rule. `ws`, `ssh` and `relay` stay reserved on the wire, so a
  ticket's `ws` or `ssh` hint is skipped. A 1a reader already skips `wss`
  as reserved, so no version changes. `ticket.json` `route_hints` gains
  `wss` cases, malformed ones included (wrong path suffix, plain `ws`).
- **Core:** `Route` (`pairing/route.rs:35`) gains `Wss { host, port, path
  }`. Plain `Ws` and `Ssh` are net-io types (`pipe::LocalRoute`), because
  core never sees them.

### 1.2 Address classes

`pipe::classify(ip)` replaces `is_private_ip` as the single classifier. It
is an allowlist: an address in none of the first three rows is
`forbidden`.

| Class | Ranges | UI label |
|---|---|---|
| `lan` | `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7` except the tailnet range | LAN |
| `tailnet` | `100.64.0.0/10`, `fd7a:115c:a1e0::/48` | Tailnet |
| `public` | IPv4 outside every range in the next row; IPv6 in `2000::/3` outside every range in the next row | Internet |
| `forbidden` | everything else, including `0/8`, `127/8`, `224/4`, `240/4`, `255.255.255.255`, documentation and benchmarking ranges, `::/128`, `::1`, `fe80::/10`, `ff00::/8`, `64:ff9b::/96` and `64:ff9b:1::/48` (NAT64), `2001:db8::/32`, `2002::/16`, IPv4-compatible `::a.b.c.d` | none |

- **IPv4-mapped** `::ffff:a.b.c.d` takes the class of `a.b.c.d`.
- **Debug builds** may dial `127/8` and `::1` (1a E5a.1). Checks may map a
  loopback port to a class through `MOUSSE_NET_TEST_CLASS_MAP`, read only in
  debug builds (§14).
- **Names.** A DNS name is resolved once per try. Each resolved address is
  classified. `forbidden` ones are dropped, and that exact `SocketAddr` is
  dialled. The name is never resolved again by a lower layer. `wss` keeps
  the name for SNI and `Host` only.

### 1.3 Who may supply what

| Source | Private `tcp` literal | Other `tcp` (tailnet, public, DNS) | `wss` | Plain `ws` | `ssh` |
|---|---|---|---|---|---|
| Ticket hints | automatic (1a) | approved at Connect | approved at Connect | skipped | skipped |
| Pairback routes (1a `pairback.routes`) | automatic (1a) | held as suggestions | held as suggestions | refused | refused |
| Owner addresses (`peer.addresses.set`, CLI, SSH add) | yes | yes | yes | loopback only | yes |
| Browse (mDNS) | as 1a | none | none | none | none |

- **Connect approves the ticket's destinations.** The join dialog lists
  every dialable hint with its class, for example "192.168.1.20 (LAN),
  100.101.7.2 (Tailnet), x.example (Tunnel)". Connect approves them. The
  app passes the approved non-private hints as `join {approved}`. The
  helper dials only private literals plus hints that are in both the
  ticket and `approved`.
- **What pairback discloses.** By default the joiner's `pairback.routes`
  carry only its private LAN literals. The Connect dialog lists this
  computer's tailnet and public routes as unticked boxes ("Also share:
  Tailnet 100.101.7.2, Internet 203.0.113.7:7443"). Only ticked ones are
  sent.
- **Suggestions.** Pairback routes outside the automatic rule are kept on
  the device row as "Addresses <B> offered". They are dialled only after
  the owner taps Use, which calls `peer.addresses.set`. 1a's limit of eight
  routes of 255 bytes each stays.
- **Replacement** of an approved destination counts as a new one.
- **Stored provenance.** The helper keeps `<state>/approvals.json`, one per
  profile, owner-only, written with `write_atomic`. Each entry is `{peer
  identity, destination, source: "ticket" | "owner", at}`. The destination
  is canonical: scheme, lower-case host, explicit port and path (for
  example `wss://x.example:443/mousse-net/1`).
  - `join {approved}` adds `ticket` entries when the join succeeds.
  - `peer.addresses.set` adds `owner` entries and removes the owner
    entries it no longer lists.
  - `peer.forget`, a removal and `ssh.forget` delete that peer's entries.
- **Every dial is filtered.** A destination is dialled only if it passes
  1a's automatic rule or has an entry for that peer. This covers the
  search, `last_route` and renewals (§1.4). `peers.json` keeps every
  ticket hint, as it does today (`peer.rs:334`), but storage is not
  approval.
- **Upgrade.** A 1.0 store has no `approvals.json`. Its routes then count
  only under the automatic rule, so a hint skipped in 1a stays skipped.
- **Cost.** A destination the owner approved learns this computer's IP
  address and receives a TLS ClientHello (or a TLS-wrapped upgrade for
  `wss`). Nothing gets past step 1 without the pin (§12).
- **Controls.** `phase1a.discovery`'s `public-routes` control still holds:
  a ticket's public hint is not dialled without approval. E7 adds the
  `loopback-routes` and `unapproved-public` controls (§14).

### 1.4 Dial order

`Caller::dial_candidates` (`caller.rs:508`) becomes tiered and bounded.

- **Candidates.** The list is built from the current store on every
  search, never from a remembered list (§1.5), and filtered through the
  approvals (§1.3). The order is: last working route, owner addresses,
  approved hints, then browse results. At most `DIAL_MAX_CANDIDATES` are
  kept, in that order.
- **Concurrency.** Each tier keeps 1a's race, `DIAL_PARALLEL` tries at
  once.
- **Tiers:**
  1. **`tcp`**, each try `DIAL_TIMEOUT_MS`. mDNS browse runs beside it, up
     to `BROWSE_WAIT_MS`, and its results join the tier's queue as they
     arrive.
  2. **`ws`/`wss`**, starting `TIER_HEAD_START_MS` after tier 1 (at once if
     tier 1 is empty). Each try gets `WS_DIAL_TIMEOUT_MS`.
  3. **`ssh`**, one route at a time, each try `SSH_DIAL_TIMEOUT_MS`. It
     starts when tiers 1 and 2 are finished, or `DIAL_FAST_TIERS_MS` after
     the search began, whichever comes first. When the last working route
     was `ssh`, it starts after `TIER_HEAD_START_MS` instead.
- **Whole search:** ends with `unreachable` after `DIAL_SEARCH_MS`.
- **Winner:** the first try to pass step 1 wins, as in 1a. A pin mismatch
  moves on, and the host's own refusal stops the search.
- **Joins** dial the same way. `peer::join_routes` (`peer.rs:274`) dials
  `tcp` in sequence today and becomes pipe-generic.
- **Keep connected** (1a E5a.4) is unchanged, except that an SSH failure
  named `auth_denied`, `host_key_changed` or `host_key_unknown` is not
  retried (`retry_ms: null`) until the owner acts. Repeated denied logins
  trip fail2ban and `ufw limit`.
- **No upgrade while connected.** A path that came up over `ws` or `ssh`
  stays until it drops or renews. The renewal or reconnect dials in tier
  order with the current list. A live upgrade is Phase 2 work.

### 1.5 This computer's own routes

The helper reads `<state>/routes.json`, which `routes.config` writes:

    { "lan": true, "tailnet": true, "public": ["tcp://203.0.113.7:7443"],
      "tunnels": ["wss://x.example/mousse-net/1"], "port": 7443 }

- **What is listened on.** Only the selected interfaces, IPv4 only, as in
  1a. One TCP socket per address, all on the kept port:
  - `lan`: `0.0.0.0`, as in 1a. With LAN on, every interface is already
    open, the tailnet one included;
  - `tailnet` without `lan`: each of the interface's `100.64.0.0/10`
    addresses;
  - `public` without `lan`: the LAN address the router forwards to,
    entered with the port forward. Settings says "Port forward also opens
    this computer on your LAN at <address>";
  - none of them: `127.0.0.1` only.

  mDNS runs only with `lan`. The ws listener runs while `tunnels` is not
  empty (§4.1).
- **What is advertised** in tickets and pairback routes: only addresses the
  listener serves.
  - `lan`: the interface's private IPv4 addresses (1a);
  - `tailnet`: the interface's `100.64.0.0/10` addresses;
  - `public` and `tunnels`: as given, after §1.1 and §1.2 checks.

  IPv6 addresses are not advertised, since the listener does not serve
  them. With nothing set, the profile advertises nothing and is reachable
  only over `ssh` (§3.4).
- **Listener lifecycle (the one rule).** Settings changes restart; network
  changes do not.
  - **Settings:** these return `restart_needed: true`, and the app
    restarts that profile's helper, about a second offline: a change to
    `lan`, `tailnet` or `port`; `public` becoming empty or non-empty, or
    its forwarded-to address changing; adding the first tunnel or removing
    the last, which starts or stops the ws listener. Other list changes
    take effect in the next ticket.
  - **Network:** with `lan` off, when the interface watcher (`watch.rs`)
    sees a selected address appear or go (a tailnet flap, a new DHCP
    lease), the helper opens or closes only that socket. Closing a socket
    also closes the connections it accepted. Nothing else drops.
  - **At start:** the helper starts with the sockets that bind and lists
    the rest in `hello` as `unbound`. The watcher retries them.
- **No live updates to peers.** Routes reach peers only in tickets,
  pairback routes or the owner's own entry on the other computer. A peer
  that has the old address needs Add address (§11).
- **Cache.** `remember_routes` (`caller.rs:508-518`) becomes a cache keyed
  by pin with a generation. `peer.addresses.set`, `peer.forget`, a grant
  removal and any change to `approvals.json` bump it, so a renewal never
  dials a removed or unapproved route. `last_route` is dropped when its
  destination loses its approval.
- **`routes.test {route}`** dials this helper's own route, pinned to its
  own identity. It reports `{ok, ms}` once step 1 passes, or `{ok: false,
  reason}`, and closes before step 2. A failure reads "Couldn't confirm
  from this network": many routers do not loop a port forward back to the
  inside. Saving is never blocked.

## 2. `tcp` to a tailnet or port forward

The pipe needs no new code. What 1b adds:

- **Fixed port.** A port forward needs a stable port. The 1a kept port
  already is one (`serve --port`, `endpoint.rs:52`). Settings shows it;
  `routes.config {port}` and `mousse-cli net-engine routes --port` set it.
- **Exposure.** A port forward puts the listener on the internet. §6.2
  applies, and the threat model and privacy doc say what a prober learns
  (§12).
- **Tailnet.** Tailscale's ACLs sit outside Mousse. Mousse relies only on
  the pin and on step 2, as on a LAN. Only IPv4 tailnet addresses are used;
  MagicDNS names are not.
- **No UPnP or NAT-PMP.** The owner sets the forward on the router.

## 3. `ssh-stdio`

### 3.1 The client

`SshPipe` (`mousse-net-io/src/pipe/ssh.rs`) runs the system OpenSSH
client: `ssh` on Unix, `%WINDIR%\System32\OpenSSH\ssh.exe` on Windows, or
`MOUSSE_NET_SSH_BIN` in debug builds. Its stdin and stdout are the pipe.
There is no Rust SSH client, so the user's keys and agent work as they do
in a terminal. The ideas come from v1 (`transports/ssh.ts:157-205`,
`ssh/hostKey.ts`); none of its code is reused.

- **Resolve once.** `ssh.resolve {target}` runs `ssh -G -- <target>` with
  the user's config and the system's `ssh_config`, under
  `SSH_CONNECT_TIMEOUT_SECS`. It refuses a result with `proxyjump` or
  `proxycommand` (`ssh_proxy_unsupported`). It keeps:
  - `user`, `hostname` and `port`;
  - authentication: `identityfile`, `identitiesonly`, `identityagent`,
    `certificatefile` and `pkcs11provider`;
  - algorithms: `hostkeyalgorithms`, `pubkeyacceptedalgorithms`,
    `kexalgorithms`, `ciphers` and `macs`;
  - `addressfamily`.
- **A changed ssh config** is picked up by removing the SSH route and
  adding it again. That runs `ssh -G` again, and a new hostname or port
  asks for the key again (§3.2).
- **One constrained config per route.** It writes
  `<state>/ssh/<route_id>.conf` (owner-only), with `route_id` random:

      Host mousse-<route_id>
        HostName <hostname>
        Port <port>
        User <user>
        HostKeyAlias mousse-<route_id>
        UserKnownHostsFile "<state>/ssh/known_hosts"
        GlobalKnownHostsFile none
        StrictHostKeyChecking yes
        <the kept authentication, algorithm and address-family keys>

  Every later call (key fetch, setup, pipe) is `ssh -F <that file>
  <fixed options> -- mousse-<route_id> <command>`. The user's
  `~/.ssh/config` and the system's `ssh_config` are never read again. Every
  call therefore reaches the same host and port, and checks the same pinned
  key.
- **Fixed options:**
  `-T -o BatchMode=yes -o RemoteCommand=none -o RequestTTY=no`,
  `-o UpdateHostKeys=no -o CheckHostIP=no`,
  `-o ConnectTimeout=<SSH_CONNECT_TIMEOUT_SECS>`,
  `-o ServerAliveInterval=<SSH_ALIVE_INTERVAL_SECS> -o ServerAliveCountMax=<SSH_ALIVE_COUNT>`,
  `-o ControlMaster=no -o ControlPath=none`,
  `-o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no`,
  `-o LogLevel=ERROR`.
- **Environment:** `SSH_ASKPASS*` are stripped and no password is ever
  asked. On Windows the process gets `CREATE_NO_WINDOW`.
- **Stderr** is kept up to `SSH_STDERR_MAX_BYTES` and mapped to a reason:
  `auth_denied`, `host_key_changed`, `host_key_unknown`, `unreachable`,
  `timeout`, `remote_not_installed`, `remote_not_running`,
  `remote_no_endpoint`, `remote_failed`. It is never shown raw in the UI.
- **Lifetime:** the child is killed when the pipe drops.
- **Connection window.** At most `SSH_TARGET_CONNECTS` ssh connections per
  resolved hostname and port per `SSH_TARGET_WINDOW_MS`, so two routes or
  aliases for one server share it. The window counts key fetches, setup
  sessions and pipe dials alike. That keeps setup plus retries under
  `ufw limit` (6 in 30 s). A spawn over the window waits, and the dialog
  says "Waiting a few seconds so <host> doesn't block this computer".

### 3.2 Host keys

- **`ssh.probe {route_id}`** fetches the key through the route's config,
  with every authentication method off and `-N`, into a temporary known
  hosts file. The reply is `{key_type, sha256, in_user_known_hosts}`.
  `in_user_known_hosts` says whether `~/.ssh/known_hosts` lists the same
  key for the hostname. It is shown as a hint and never replaces the
  owner's confirmation. The helper keeps the fetched key bytes in memory
  for that route, for at most `SSH_SETUP_TIMEOUT_MS`.
- **The dialog** shows the SHA256 fingerprint. Trust calls `ssh.trust
  {route_id, sha256}`. The helper checks the kept key against that
  fingerprint and writes its line for `mousse-<route_id>` to
  `<state>/ssh/known_hosts`. It does not connect again. With no kept key
  (expired, or the helper restarted), it answers `probe_again`.
- **Rotation.** A changed key fails with `host_key_changed`, and the row
  offers "Check and trust again". It runs the same probe and confirmation.
  The new file replaces the old one through `write_atomic`, so the old pin
  and the new one never both hold.
- **Why it matters.** Peer TLS is pinned on every connection, so after
  setup SSH carries only ciphertext. During setup (§3.4), though, B's
  identity comes over SSH, so the SSH host key authenticates B at first
  contact.

### 3.3 The remote end: `mousse-helper pipe`

- **Launchers.** After ready, the app writes stable launchers to
  `$MOUSSE_HOME/bin/` (default `~/.mousse/bin/`): `mousse-helper` and
  `mousse-cli` as small `sh` scripts. Each points at the installed app's
  binaries and sets `MOUSSE_HOME`, so an update never changes the SSH
  command. A dev build or a check with its own `MOUSSE_HOME` writes only
  there.
- **Selectors.** Beside them, `$MOUSSE_HOME/net-engine/endpoints.json`
  (owner-only) maps each profile's opaque selector to its state directory.
  A selector is 26 characters of `[a-z2-7]`, random, made once per profile.
  The selector is the only value from B that goes into a remote command, so
  no path is quoted. `O'Brien` and `%` in paths need nothing.
- **Command form (`sh`):** `exec /bin/sh -c '"$HOME"/.mousse/bin/<launcher>
  <args>'`, following v1's `shellQuote.ts:24`. A login shell like fish or
  zsh never parses the inner command. The remote Mousse must use the
  default folder, `~/.mousse`. A custom remote folder is not supported in
  1b. Tests meet this by setting `HOME` to the test home.
- **App-run profiles only.** SSH reaches profiles that Mousse runs, through
  their selector. A standalone `serve` is not reachable over SSH in 1b, and
  `pipe` has no `--state` form.
- **Windows remotes** (`cmd` form, `.cmd` launchers) are in 1b only if S1
  is clean: key logon reaches a GUI-session helper's named pipe, the remote
  process exits when the session is killed, and a space in the path works.
  Otherwise SSH add refuses a Windows remote with "Adding a Windows
  computer over SSH isn't supported yet." PowerShell as the remote default
  shell is not supported in 1b.
- **Marker.** `pipe` and `mousse-cli net-engine ssh` write the line
  `mousse-ssh/1` to stdout before anything else. The client discards
  everything up to and including that line, at most
  `SSH_PREAMBLE_MAX_BYTES`. Without the marker the try fails with
  `remote_failed`, and the tooltip says something on <host> prints text
  when SSH runs a command. Output from `.bashrc` or `.zshenv` no longer
  reaches TLS or the JSON reader.
- **Pipe.** The remote command is `<launcher> pipe --profile <selector>`.
  `pipe` looks up the state directory and reads `control.json`. It
  connects to the running helper's owner-only IPC (`ipc.rs`, unchanged
  security) and sends `{op: "pipe", token}`. After `{ok: true}` it splices
  stdin and stdout to the IPC stream. The helper hands the stream to
  `host.accept`, tagged `route: ssh`. The handover takes at most
  `PIPE_CONNECT_WAIT_MS`.
- **Buffered bytes are kept.** Both sides read the request and reply lines
  through a buffered reader, which may already hold the first TLS bytes.
  The helper hands over the reader's buffer followed by the rest of the
  stream, and `pipe` writes its buffer to stdout before splicing. No byte
  is dropped or read twice.
- **Ending.** When the helper closes the IPC stream (the connection ended,
  or the helper stopped), `pipe` exits at once, even while SSH still holds
  its stdin open. The SSH session then ends, and the caller sees the pipe
  close. When stdin ends first, `pipe` shuts the IPC stream's write side
  and exits once the helper closes.
- **Long socket paths.** A Unix socket path is limited to 104 bytes on
  macOS. When `<state>/control.sock` is longer, the helper and `pipe` both
  use the name relative to the state directory, after changing to it. The
  helper is one process per profile, so that is safe. S1 checks a 150-byte
  path.
- **Pipe errors.** Each is one line on stderr, `mousse-pipe: <reason>`,
  plus an exit code:
  - `not_running` (2): no helper for that profile;
  - `no_endpoint` (3): unknown selector, or the profile's networking is off;
  - `refused` (4): the token, the pipe pool (§6.2) or the pause fence.

  stdout carries only the marker and pipe bytes.
- **App mode IPC.** App mode binds the control listener again (E3.7 retired
  it). It answers only `pipe` and `status`. Every other op answers "This
  profile is run by Mousse; use mousse-cli net-engine". Line reads are
  bounded (§6.2).
- **Why the running helper.** The pipe needs no key, so the keystore is
  never opened from an SSH session. Windows Credential Manager under a
  key-based SSH logon, and a locked macOS keychain, both fail there. The
  remote profile therefore answers only while its helper runs: the user is
  logged in and Mousse is running (§10).
- **Rejected: `ssh -W 127.0.0.1:<port>`.** v1 used it. It needs
  `AllowTcpForwarding`, which hardened servers often turn off. It needs the
  remote's port, and it would bypass the per-profile state directory.

### 3.4 Adding a computer over SSH (A adds B)

Nothing here uses wire §10. The trust is the SSH host key the owner
confirmed, plus the SSH login.

1. **A, "Add over SSH":** the owner enters `user@host` or an alias. The SSH
   user chooses the OS account on B. A runs `ssh.resolve`, then `ssh.probe`
   and the fingerprint confirmation if the route has no pin.
2. **Session 1 (login):** `ssh.run {route_id, request: {op: "profiles"}}`
   runs `mousse-cli net-engine ssh` on B. The request goes on stdin. The
   reply follows the marker and is at most `SSH_REPLY_MAX_BYTES`.
   - `net-engine ssh` connects to the daemon with `disableAutoStart`. With
     no daemon it answers `remote_not_running` and starts nothing.
   - The reply is `{computer, os, starts_at_login, profiles: [{selector,
     label, networking, identity?}]}`. That is every profile of that OS
     account, paired elsewhere or not. It holds no paths.
   - A missing launcher (`127`, or "not found") is `remote_not_installed`.
     For a Windows remote, see §3.3.
3. **A, the owner picks** an existing profile, or "New profile" with a
   label. The list never hides or refuses a profile because it belongs to
   another set of devices, as the PLAN requires.

   Connect is the owner's consent. Before anything is sent, A writes its
   journal row `{state: "ssh_requested", source: "ssh", request_id,
   issued_at, route_id, selector | new_label}`. `request_id` is 16 random
   bytes in hex, so it also parses as a `receipt` (`pairing.rs:375`).
4. **Session 2 (login):** `{op: "prepare", request_id, issued_at, selector
   | new_label, joiner: <A identity>, joiner_name}`. B's daemon runs the
   steps below. Each records its result durably, and a repeat resumes at
   the first unrecorded step. A request takes the same per-device lock as
   1a's removal journal (1a §5.4), so a request and a removal of A never
   interleave.
   1. **Journal the request.** B looks up `request_id` in the daemon-wide
      table `net_engine_ssh_requests`:
      - unknown, with `issued_at` older than `SSH_REQUEST_MAX_AGE_SECS` by
        B's clock: `expired`, and nothing is written;
      - unknown otherwise: B stores the immutable fields `{request_id,
        issued_at, joiner, joiner_name, selector | new_label}` before
        anything else;
      - known with different immutable fields: `bad_request`;
      - `removed`: answers `removed`;
      - `done`: B checks that the stored grant id is still live in the
        helper and that the serving row still holds that same grant id.
        The serving row is the request's own row, or for `existing: true`
        the preserved row recorded in step 4. If so, it returns the stored
        reply, `existing` included, with `already: true`. Otherwise it
        marks the request `removed` and answers `removed`;
      - open: resumes.
   2. **Profile.** For `new_label`, B creates the profile tagged with
      `request_id` and stores its selector. After a crash, the tag finds
      the profile, so a retry never makes a second one.
   3. **Networking.** B turns it on if it was off, with nothing advertised
      (§1.5: loopback only, no LAN, no tailnet). It waits for the helper,
      within `SSH_SETUP_TIMEOUT_MS`.
   4. **Row.** B looks up the profile's row for A:
      - none: B writes `{state: "ssh_granting", source: "ssh",
        request_id}` and records `row: own` on the request;
      - a row with this `request_id` (B stopped after writing it): B
        resumes at step 5, or at step 6 when the row already holds the
        request's grant id;
      - any other live row (1a pairing or an earlier request): never
        overwritten. B records `row: existing`, that row's key and its
        grant id on the request, and goes to step 6 with `existing: true`;
      - a `removing` row: `busy`, and A tries again later.
   5. **Grant.** `grant.add {identity: A, name: joiner_name, receipt:
      request_id}` makes role `owner` and is idempotent by identity
      (`host.rs:765`), so a repeat returns the same grant. B stores the
      grant id on the request, then on the row's `grant` field. A resume
      that finds the id on the request but not on the row copies it.
   6. **Done.** An own row moves to `ssh_granted`. B stores the reply,
      marks the request `done`, and replies `{identity, name, selector,
      grant_id, existing, already, starts_at_login}`.

   A removal of A on B marks every open or `done` request for A on that
   profile `removed`, under the same lock.
5. **A:** pins B. It calls `peer.add {identity: B, name}` with no routes,
   then `peer.addresses.set` with the SSH route `{route_id, selector,
   shell}`. The row moves to `ssh_granted`.
6. **Confirm:** A dials B (§1.4). When the connection is live, A's row
   moves to `connected`. B's row moves to `connected` on A's first live
   inbound connection whose grant is the row's grant. B shows one line,
   "Added over SSH from <A>".

**Retry safety.** A repeats `prepare` with the same `request_id` on its
own only while its row has never been `connected`, and only within
`SSH_REQUEST_MAX_AGE_SECS` of `issued_at`. B keeps request records for
`SSH_REQUEST_KEEP_SECS`, which is at least twice the maximum age, so a
request id is never seen as new a second time. After that, a new grant
needs Connect on A again, with a new `request_id`.

| Lost or crashed | What happens |
|---|---|
| B's reply lost (session dropped) | A's row is still `ssh_requested`. A repeats `prepare`. B resumes, or returns the stored reply. |
| B crashed after step 1, 2, 3, 4 or 5 | The repeat resumes at the next step. The profile tag, the stored grant id and the idempotent `grant.add` keep each step single. |
| B crashed between writing its row and storing the grant id | The repeat finds the row with this `request_id` and no grant id, resumes at step 5, and gets the same grant. |
| B crashed after the helper saved the grant, before its id was stored; B's owner then removed A, and A never retried | The removal finds no grant id, so it removes A's live grant by identity and `request_id` first (§3.6). After B restarts, B has no grant, no row and no `awaiting_pairback` row for A, and A's dial gets `NOT_AUTHORIZED`. |
| B's `existing: true` reply lost | A repeats. The request is `done` with `row: existing`, and the preserved row still holds the stored grant id, so B returns the stored reply with `already: true`. |
| A crashed after the reply | A's recovery repeats `prepare` (the row was never `connected`), gets `already: true`, and continues at step 5. |
| B's owner removed A before A connected | The request is `removed`. A's row reads "<B> removed access", with Add again (a new request) and Remove. A stops repeating. |
| B's owner removed A after A connected | A's dial gets `NOT_AUTHORIZED`. A never repeats `prepare` then; the row reads "<B> removed access". |
| Confirmation dial unreachable | Keep connected retries the dial. `prepare` is not repeated for a network failure. |

**Not covered in 1b:** a headless Linux server with no logged-in Mousse,
and any remote where the daemon is not running. Both answer
`remote_not_running`. The headless daemon is PLAN §8.

**SSH connections per add:** a key fetch when the route has no pin, then
sessions 1 and 2, then the pipe dial. That is four, under the window's
five. Adding the SSH route to a computer A already pairs with skips step 4
on A: A holds B's pin and is granted, so it only stores the route.

### 3.5 Errors shown (one line each; details in the tooltip)

| Reason | Text |
|---|---|
| `auth_denied` | "SSH sign-in was refused. Mousse uses your SSH keys or agent, never a password." |
| `host_key_changed` | "<host>'s SSH key changed." Check and trust again |
| `remote_not_installed` | "Mousse isn't installed for <user> on <host>." |
| `remote_not_running` | "Mousse isn't running for <user> on <host>. Sign in there and open it once." |
| `remote_no_endpoint` | "That profile is gone on <host>." |
| `remote_failed` | "Mousse on <host> didn't answer as expected." |
| `removed` | "<host> removed this computer's access." Add again |
| `ssh_proxy_unsupported` | "Jump hosts aren't supported yet." |
| `windows_remote_unsupported` | "Adding a Windows computer over SSH isn't supported yet." (only if S1 fails) |

### 3.6 Direction and journals

- **One way only.** A's row reads "Uses <B>". B's row reads "<A> uses this
  computer". A later Send link between the two adds the other direction.
- **Existing access is not authority to grant back.** After A adds B
  over SSH, A holds B's pin and B grants A. A link naming B, damaged or
  not, then meets a live grant. The host answers an invalid proof on a
  live connection with `AUTHORIZED {state: live}` (`spec/wire.md:520`),
  and the caller reports that as "already paired" (`caller.rs:913`). For
  kind 2 that outcome means only "existing access". It writes no
  completion record, moves no row to `joined`, and never runs `grantBack`
  (`pairing.ts:218`). The dialog reads "This link didn't work. Ask for a
  new one." Only a `PAIRED` for this ticket gives authority to grant
  back: one after the code exchange, or one answered from a grant whose
  receipt names this ticket's invitation, which only this ticket's
  enrollment writes.
- **A Send link between SSH-added computers.** 1a's `join` reuses the row
  for the host (`pairing.ts:131`, `peers.byEndpoint`). Connect on a
  `source: "ssh"` row keeps the row as it is (state, `source`, SSH
  address) and stores the kind-2 fields (ticket hash, `approved`,
  `share`) beside them as a pending link. The row converts (`source`
  cleared, the SSH address kept, state `joined`) only when the helper
  reports a `PAIRED` for that ticket as above. Any other ending drops the
  pending link and leaves the SSH row unchanged. The host converts its row
  for the joiner only at enrollment, never when the request arrives.
  From then on 1a's pairing runs as usual.
- **SSH rows have their own states:** `ssh_requested`, `ssh_granting` and
  `ssh_granted`, then `connected`. 1a's code does not know the `ssh_*`
  states, and every 1a path also skips rows with `source: "ssh"`:
  - `advance()` (`pairing.ts:222-241`), which sends `pairback` for
    `granted` rows;
  - `clientReady()` and `recover()` (`pairing.ts:400-417`);
  - `grantBack` (`pairing.ts:243`);
  - host recovery (`pairing.ts:309-335, 380`), which turns a live owner
    grant with no row into `awaiting_pairback`. B writes its row before
    the grant exists, so that case never arises.
- **Removal and expiry reconcile the grant first.** B can stop after the
  helper saved the grant (step 5) but before the request or the row holds
  its id. 1a's removal skips `grant.remove` when the row's `grant` is
  empty (`pairing.ts:511`), and `reconcileGrants` (`pairing.ts:345`) would
  then turn the leftover live grant into an `awaiting_pairback` row. So,
  under the removal lock, before a removal or the expiry rule below
  discards an SSH row or request with no grant id, B lists the helper's
  grants and removes every live grant for A's identity whose receipt is
  the request's `request_id`. Only then is the row or request discarded.
  `reconcileGrants` also skips a grant whose receipt names a request in
  `net_engine_ssh_requests`: an open request attaches it to its row, and a
  `removed` or expired one removes it.
- **Recovery of SSH rows** is its own: A repeats `prepare` under the rule
  above. On B, a `ssh_granting` row whose request holds a live grant id
  gets that id on the row and moves to `ssh_granted`. One with no grant id
  waits for A's repeat, and is deleted once its request is older than
  `SSH_REQUEST_MAX_AGE_SECS`.
- **Display.** `ssh_requested` and `ssh_granted` read "Connecting…", not
  1a's "Finishing pairing…".

### 3.7 Tests (no real sign-ins)

- **Test server:** `crates/mousse-helper/tests/common/sshd.rs`, an SSH
  server built on `russh`, pinned as a dev-dependency only.
  - It listens on `127.0.0.1` on the PC.
  - It accepts one generated client key and has one generated host key.
  - It runs only `mousse-helper pipe …`, `mousse-cli net-engine ssh` (the
    app checks) and a configurable login-shell preamble, as the current
    user, with a test `MOUSSE_HOME`.
- **Real client:** each test runs the system `ssh` through §3.1's
  constrained config, made from a test config with `IdentitiesOnly=yes`
  and the test key. It never reads the user's agent, keys or config.
- **Cross-machine:** only the Mac listens on the LAN, running the same test
  server.

## 4. `ws` through a user tunnel

### 4.1 Listener (host)

- **Bind:** `127.0.0.1:<ws_port>`. The port is kept in the endpoint file
  like the TCP port (`--ws-port`). `hello` reports `ws_port`. The listener
  exists only while a tunnel is set. Adding the first tunnel or removing
  the last restarts the helper (§1.5).
- **Admission first:** a ws slot (§6.2) is taken at accept, before a byte
  is read. Over the cap, the socket is closed.
- **Upgrade checks,** in order, before any byte goes to TLS. The whole
  upgrade request must arrive within `WS_UPGRADE_WAIT_MS` and fit in
  `WS_HEADER_MAX_BYTES`, else the socket is closed.
  1. method `GET`;
  2. path ending in `/mousse-net/1`, else `404`;
  3. no `Origin` header, else `403`;
  4. `Sec-WebSocket-Protocol` offering `mousse.1`, which is selected, else
     `400`;
  5. the removal-pause fence, else `503`.

  `Host` is not checked: tunnels rewrite it, and rebinding attacks come
  from browsers, which always send `Origin`.
- **After the upgrade:**
  - binary messages only; a text message closes with 1003;
  - at most `WS_MESSAGE_MAX_BYTES` per message (65 536, tighten-only);
  - no permessage-deflate;
  - library pings are answered.

  `WsPipe` turns messages into the byte stream for `host.accept`, tagged
  `route: ws`, carrying its slot.
- **Library:** `tokio-tungstenite`, pinned, `default-features = false`,
  with `handshake` on. The server reads the request itself under the caps
  above, then uses `accept_hdr_async` on the buffered stream.

### 4.2 Client (caller)

- **`wss`:** the outer TLS is a separate rustls client with the platform
  verifier (`rustls-platform-verifier`, pinned), SNI equal to the URL's
  host, and ALPN `http/1.1`. TCP goes to the classified address (§1.2).
- **Test root.** Debug builds add one extra root from
  `MOUSSE_NET_TEST_EXTRA_ROOT`. Release builds never read it, and nothing
  is ever installed in an OS store.
- **Plain `ws`** is dialled only to a loopback owner address: the local hop
  of a tunnel client on this computer.
- **No proxies or redirects.** A redirect fails with `ws_redirect`.
- **Outer TLS is not a trust step.** It only gets through the tunnel. The
  pinned peer TLS runs inside, so a tunnel that terminates TLS sees
  metadata, never content.
- **Timing:** `WS_DIAL_TIMEOUT_MS` covers connect, outer TLS, upgrade and
  step 1. Messages written are at most 16 KiB.

### 4.3 Tunnel setup (no process management)

- **Settings → "Reach through a tunnel"** shows `http://127.0.0.1:<ws_port>`
  and two copyable examples:
  - `cloudflared tunnel --url http://127.0.0.1:<port>`;
  - `tailscale funnel <port>`.

  It has a field for the public URL. `https://x` is stored as
  `wss://x/mousse-net/1`. Test runs `routes.test`.
- **Mousse never starts, stops or configures a tunnel.** v1 did, through
  `ProcessSupervisor`, Serve records and undo. That is out.
- **A changed URL** (cloudflared quick tunnels change on every run) reaches
  peers only through a new link or the owner's Add address (§11). The UI
  recommends a named tunnel or Funnel for lasting use.

## 5. "Send link"

### 5.1 Host

- **Create:** `invite.create {kind: "link"}` returns `{invitation, uri,
  code, attempts_left: 3, routes, expires_at}`. Each `HostEvent::ShowCode`
  (`host.rs:124`) becomes `invite.code {invitation, code, attempts_left}`.
- **Dialog, "Send link" tab:**
  - the link with a Copy button;
  - the code as `123 456`;
  - "3 tries left";
  - one line: "Send the link in a chat. Read the code to them another way."
- **The code** is not in the copied text.
- **After a wrong code,** the dialog shows the new code and "2 tries left".
- **After the third,** `invite.ended {reason: "attempts_exhausted"}`, and
  the dialog shows "Three wrong codes. This link no longer works." with
  "New link".
- **Enrollment** follows wire 10.6.5 and needs no tap. The 1a dialog's
  approval step is skipped for links.
- **Name:** the grant is named `<computer>` (wire 10.3). After pairing,
  the joiner's `mousse.hello` `name` carries `<computer> (<profile>)`, and
  the host app renames the grant's display row.

### 5.2 Link form

- **Format:** `mousse://pair#<fragment>`.
- **Scheme registration:** only packaged builds (`app.isPackaged`) call
  `setAsDefaultProtocolClient`. Dev builds and any app started by the kit
  (`MOUSSE_CHECK` set) never do. Handling is in `src/main/index.ts:185`
  (`open-url`, `second-instance` and the launch argv).
- **Profile:** when more than one profile has networking on, activation asks
  which profile joins.
- **Paste:** pasting the link, or the bare fragment, into "Enter link"
  works the same. No web page sits in 1b's path.

### 5.3 Joiner

1. A link opens "Enter link" with the ticket filled in. The app decodes it
   locally. A decode error shows "This link is damaged. Ask for a new
   one."
2. **Consent** (1a §5.1 step 2): "Connect to the computer in this link? It
   will also be able to use this computer." The dialog lists:
   - the destinations it will contact (§1.3);
   - "Also share", unticked: this computer's tailnet and public routes,
     which pairback sends only if ticked.

   Connect writes the 1a `consented` row with `kind: 2`, the ticket hash,
   the `approved` list and the `share` list. A row added over SSH keeps its
   state and holds these as a pending link until the ticket's `PAIRED`
   (§3.6). A repeated join after a restart reuses both lists from the row.
3. **Join:** `join {ticket, arrival: "link", approved}`. The helper dials
   (§1.4), sends `JOIN_PROOF` and gets `join_only`. Then:
   - **Code needed:** `join.code_needed {invitation, attempts_left}`. The
     dialog shows six boxes, "Type the code shown on the other computer."
   - **Submit:** `join.code {invitation, code}` feeds the helper's
     `CodeEntry` (`caller.rs:91`) through a channel. A format error is
     `bad_code`, which is not an attempt.
   - **A wrong code:** `join.attempt_failed {invitation, attempts_left}`.
     The dialog shows wire 10.6.6's text, shortened:

     > That code didn't work. If you typed it exactly, the link may have
     > been swapped; get a new one another way.
   - **No tries left:** the reply is `attempts_exhausted`, shown as "No
     tries left. Ask for a new link." Opening the same link again ends the
     same way, on this side from the flow record and on the host because
     the invitation is gone.
4. **Success:** as 1a, `joined` → `granted` → pairback, which sends the
   private LAN literals plus the `share` list.

### 5.4 Pins, flow records and wire rule 10.6.8

- **The store is already durable.** App mode installs the file-backed
  store: `caller.use_flow_records(Arc::new(endpoint.flow_records()))` in
  `serve.rs`'s app branch. The debit, the pending mark and the
  one-join-per-ticket hold survive a crash today.
- **The consented path.** `peer.rs:285` sets `pinned = consented || <pin in
  peers.json>`. A consented join goes to `join_pinned_with_redial`, which
  calls `mark_outcome_pending_if_expired` (`caller.rs:~793`) and makes up a
  pending outcome once the ticket expires.
- **Kind 2 never takes that path.** For kind 2, `consented` and the app's
  `pinned` are ignored. `pinned` is true only if `peers.json` held the
  ticket's host pin before this flow began. The join runs `join_flow` with
  no made-up pending outcome.
- **Late recovery** (wire 10.6.7) runs only when the flow store holds a
  genuine pending record for that ticket's hash, written when the
  confirmation was sent. With none, an expired ticket ends with `expired`.
- **Completion record (new).** When a kind-2 flow ends with a `PAIRED`
  for this ticket (§3.6: after the code exchange, or from a grant whose
  receipt names this invitation), the helper writes
  `<state>/joins/<ticket hash>.done` before it saves the pin. The record
  is `{ticket_hash, host_identity, outcome, peer, approvals, at}`, written
  with `write_atomic`. `peer` is the full `PeerRecord` the join writes
  (name, role, `routes`, `last_route`; `peer.rs:322-346`), and `approvals`
  are the `approvals.json` entries for the approved destinations.
  - The join then writes `peers.json`, `approvals.json` and the flow
    store's pin mark, in that order.
  - **The pin mark is settled on disk.** Today `pin_stored`
    (`caller.rs:279`) returns `Ok` when the flow is not in memory, so
    after a restart the durable pending mark would stay. Both the join and
    the replay call a new `settle_stored(ticket_hash)`, which takes the
    ticket's lock in the file-backed flow store and clears the durable
    mark whether or not the flow is in memory.
  - If the helper stops anywhere after the record, the next `join.status`
    replays all three writes, each idempotent and merged as the join
    merges them, before it answers `done`. A replayed peer never lacks
    its routes or approvals.
  - **Replay only for the current pairing.** A removal of the host's
    identity (`peer.forget`, or a grant removal for it) deletes every
    completion record naming that identity, under the peers lock. Replay
    takes the same lock and checks the record still exists before it
    writes. A removal after completion is therefore never undone, and
    `join.status` then answers `done: null, pending: false`.
  - The record is deleted when the app sends `join.ack {ticket_hash}`
    after its row reaches `joined` and the mark is settled, or
    `JOIN_DONE_KEEP_SECS` after the ticket expires.
  - It lives beside the flow records and does not change the
    `JoinerRecord` format of wire 10.7.
- **`join.status {ticket_hash}`** → `{done: {identity, name, role} | null,
  pending: bool, attempts_left}`.
- **App recovery for a `consented` kind-2 row** uses only that ticket's
  hash:
  - `done` is set: go to `joined` with that identity;
  - `pending` is true: repeat `join` with the stored `approved` list. The
    helper resumes the proof and learns the outcome, even after expiry;
  - otherwise: "Pairing didn't finish", with Retry while the ticket is
    valid, and Remove.

  A pin the helper already holds promotes nothing, and neither does
  "already paired" (§3.6). A one-way SSH add, for example, leaves B's pin
  on A, and a crash after Connect on a swapped or unfinished link to B
  must not run `grantBack`.
- **Tests** (`app_link`, `phase1b.link-app`):
  - a fresh swapped link (another key, valid expiry) gets the swapped-link
    text and never ends "already paired";
  - an expired swapped link with a `consented` row ends `expired`, with no
    pending outcome and never "already paired";
  - a crash after the confirmation is sent, with `PAIRED` lost, is
    recovered from the pending record;
  - a crash after the completion record but before `peers.json` is
    saved, with WSS as the only route, is replayed by `join.status`: the
    row reaches `joined`, then reconnects and sends pairback over that WSS
    route;
  - a crash after Connect, with B's pin already held from an SSH add and
    the ticket unfinished, ends "Pairing didn't finish" and grants nothing;
  - a damaged link after a real one-way SSH add ends "This link didn't
    work". The check reads the grant tables on both sides: B still grants
    A once, under the SSH grant id; A grants nothing to B; both rows keep
    `source: "ssh"`;
  - completion replay after a restart clears the durable pending mark, so
    opening the ticket again does not ask the host again;
  - completion replay after the host was removed restores no peer and no
    approval, and `join.status` answers `done: null`.

### 5.5 Tampered links (what each change does)

| Change | Result |
|---|---|
| bad base64 or CBOR | refused before dialling (`encoding`, `cbor`, `field`) |
| kind 2 → 1 | refused before dialling: kind 1 needs an in-app scan (`PAIRING_FAILED`) |
| secret or invitation id | host closes with `INVITATION_INVALID`; no attempt spent. If the host already grants the joiner (an SSH add), it answers `AUTHORIZED {state: live}` instead: "This link didn't work", and no grant changes on either side (§3.6) |
| host key | no address answers as that key, or a fake host does. The fake host's code exchange fails with the swapped-link text, and the real invitation is untouched |
| a route hint | the ticket hash differs, so CPace fails: `PAIRING_FAILED`, one attempt spent on each side |
| `expires_at` | the same as a route hint; a past value is refused before dialling (`expired`) |

## 6. Traffic that must never reach RPC

### 6.1 Layers (unchanged, now on every route)

| Layer | Stops |
|---|---|
| Admission (§6.2) | floods past the per-kind pools; anything while removal is paused |
| `ws` upgrade checks (§4.1) | non-WebSocket requests, browsers, wrong path or protocol, slow or large headers |
| `pipe` IPC (§3.3) | other OS users (the OS); the same user without the token; long or slow lines |
| TLS step 1 (wire 5.4) | no certificate, wrong version or ALPN, bad certificate |
| Step 2 and the host gate (wire 8, 8.1) | any stream before a live grant; a join-only connection opening streams |
| Helper `inbound` (`app/mod.rs:288`) | announces a connection to the app only once it is live |
| Helper labels (1a §2.3) | streams outside the §3.2 labels plus `mousse.tunnel` (§9) |
| `authorizeEngine` (1a §4.3) and the editor refusal (§9.2) | methods outside the allowlist; removed, blocked or `removing` rows; editor off |

### 6.2 Admission

- **Pools per listener kind:** `PREAUTH_TCP`, `PREAUTH_WS` and
  `PREAUTH_PIPE`, each per endpoint. The pools do not share, so a flood
  through a tunnel cannot take the owner's SSH pipe or LAN joins.
- **Per source:** `PREAUTH_PER_SOURCE` per IPv4 address, or per IPv6 /64,
  on TCP only. `ws` and pipe connections all come from loopback.
- **When a slot is taken:** at accept, before any read — the ws upgrade,
  the IPC line or the TLS ClientHello.
- **How long it lasts:** until the connection is live or closed. It passes
  from the ws or pipe layer to TLS and step 2.
  - Before `JOIN_PROOF`: `HANDSHAKE_TIMEOUT_MS`, then `JOIN_PROOF_WAIT_MS`.
  - Join-only: the proof wait no longer applies. The slot lasts until
    enrollment, a close, or the end of the invitation, whichever comes
    first. The host closes join-only connections when their invitation
    expires, is cancelled or runs out of attempts, so the invitation's
    expiry (`TICKET_LIFETIME_SECS`) bounds the slot. Only a holder of the
    ticket's secret reaches join-only.
- **Re-pairing on a live connection.** A slot is released at `live`, but a
  granted device's valid proof moves a live connection back to join-only
  (wire §10 step 3; `AdmittedJoinOnly`, `host.rs:428`). That transition
  takes a new slot from the connection's kind pool and checks the
  admission fence, both under the host lock. With the pool full or the
  fence set, the proof opens nothing: the connection stays live under its
  grant, and the host answers `AUTHORIZED {state: live}`, as for any proof
  that opens nothing. The slot then lasts as for any join-only connection.
- **Reads before TLS:**
  - ws upgrade: `WS_UPGRADE_WAIT_MS` and `WS_HEADER_MAX_BYTES` (§4.1);
  - IPC: every line at most `IPC_LINE_MAX_BYTES`. The first line must
    arrive within `IPC_FIRST_LINE_WAIT_MS`. `Channel::recv` (`ipc.rs`)
    reads lines with no bound today, and gets a bounded reader.
- **Over the limit:** TCP is closed at accept, ws is closed before reading,
  and `pipe` gets `refused`.
- **The removal-pause fence** (`shared.removal`, 1a §5.4) moves into
  `Host` as an admission fence that the helper sets and clears. It is
  checked under the host's lock at two points, for every transport alike:
  - **gate registration:** after TLS, when a connection enters the gate
    table, before step 2 is decided;
  - **enrollment:** before a grant is committed for a `JOIN_PROOF` or a
    finished code exchange.

  Setting the fence takes the same lock, then closes every registered
  connection that is not live, join-only ones included. A handshake that
  finishes during the pause therefore meets the fence at registration.
  Listeners also refuse at accept while paused, and `inbound`'s check
  (`app/mod.rs:294`) stays as a second line.
- **Limits only tighten.** Overrides may lower these caps and waits but
  never raise them (§13.3).
- **`stats`** gains `preauth_open` and `preauth_refused` per kind.
- **Not a promise against denial of service.** The threat model says a
  flood on one kind can delay that kind's legitimate connections.

### 6.3 The route probe

`mousse-check probe --route <hint> --pin <host identity> --invite <ticket>
[--grant-key <file>]` links `mousse-net-io`. It sends each case and
expects the named close on the wire:

1. Bytes that are not TLS → TLS failure.
2. For `ws` only:
   - plain `GET` → `404`;
   - wrong path → `404`;
   - with `Origin` → `403`;
   - no subprotocol → `400`;
   - headers past `WS_HEADER_MAX_BYTES`, and headers trickled past
     `WS_UPGRADE_WAIT_MS` → closed;
   - a text message after the upgrade → close 1003.
3. TLS:
   - without a client certificate → handshake failure;
   - TLS 1.2 only → handshake failure;
   - wrong ALPN → handshake failure.
4. A fresh identity:
   - immediate `OPEN mousse.rpc` → `NOT_AUTHORIZED`;
   - immediate `OPEN mousse.tunnel` → `NOT_AUTHORIZED`;
   - silence → `NOT_AUTHORIZED` after `JOIN_PROOF_WAIT_MS`;
   - a bad `JOIN_PROOF` → `INVITATION_INVALID`.
5. A valid `JOIN_PROOF` → `join_only`, then:
   - `OPEN mousse.rpc`, `mousse.hello` or `mousse.tunnel` →
     `NOT_AUTHORIZED`;
   - a garbage `CODE_EXCHANGE` → `CODE_ABORT PAIRING_FAILED`, with one host
     attempt spent.
6. Identities:
   - a removed identity, `OPEN mousse.rpc` → `NOT_AUTHORIZED`;
   - a granted identity whose device has editor off, `OPEN mousse.tunnel`
     with kind `ssh` → `tunnel.close editor_off`, and no endpoint session.
7. Admission: `PREAUTH_<kind> + 1` silent connections → the last one is
   refused. With the ws pool full, a pipe still connects.
8. For `ssh` only, `pipe`:
   - a wrong token → `refused`;
   - a line past `IPC_LINE_MAX_BYTES` → closed;
   - a stopped helper → `not_running`.

**Each case has its own two assertions:**

- **Wire:** the probe records the close it got. A missing or different
  close fails with `wire_accepted`.
- **App:** the case's expected app-side record, read from the host's
  `stats` and the daemon's dispatcher, tunnel and ledger counters for
  that probe connection only. Any other record fails with
  `probe_reached_app`, even when the wire looked right.

| Cases | Expected app-side record |
|---|---|
| 1–5, 6 (removed identity), 7, 8 | nothing: no `conn.up`, no stream, no authorized call, no endpoint session, no ledger row |
| 6 (editor off) | one `conn.up` and one `mousse.tunnel` stream delivered to the app, then one refusal `editor_off`. No endpoint session, no authorized call, and no ledger row beyond the refusal row v1 already writes. |

## 7. App ↔ helper protocol 1.1

These are additions only. A 1.1 helper serves a 1.0 app (1a messages
only). The app needs 1.1 for anything in 1b.

- **Session:** the `hello` reply adds `ws_port` and `routes_config`.
- **Routes:**
  - `routes.config {lan?, tailnet?, public?, tunnels?, port?}` → `{routes,
    restart_needed}`;
  - `routes.test {route}` → `{ok, ms?, reason?}`;
  - `peer.addresses.set` takes every §1.3 owner kind. `ssh` entries carry
    `{route_id, selector, shell}`;
  - `peer.add` routes keep 1a's rule (private literals only); the app holds
    the rest as suggestions (§1.3);
  - `approvals.list {identity?}` → `[{identity, destination, source,
    at}]`, for the device row and the checks.
- **Connections:** `conn.up` adds `route {kind: tcp|ws|ssh, class:
  lan|tailnet|public|tunnel|ssh}`.
- **Send link:**
  - `invite.create {kind: "in_person"|"link"}`;
  - event `invite.code {invitation, code, attempts_left}`;
  - `invite.ended` reasons gain `attempts_exhausted`.
  - `join {ticket, arrival: "scan"|"link", approved?, pinned?}`.
    `arrival` replaces 1a's fixed in-app scan, and kind 1 needs `scan`.
    `approved` lists the ticket's non-private hints the owner approved.
    `pinned` is ignored for kind 2 (§5.4).
  - `join.code {invitation, code}`;
  - `join.status {ticket_hash}` and `join.ack {ticket_hash}` (§5.4);
  - events `join.code_needed {invitation, attempts_left}` and
    `join.attempt_failed {invitation, attempts_left}`;
  - join errors gain `attempts_exhausted`, `pairing_failed`,
    `invitation_invalid`, `bad_code`, `expired` and `forbidden_address`.
- **SSH:**
  - `ssh.resolve {target}` → `{route_id, user, hostname, port, pinned}`;
  - `ssh.probe {route_id}` → `{key_type, sha256, in_user_known_hosts}`;
  - `ssh.trust {route_id, sha256}`, or `probe_again` when no probed key
    is kept;
  - `ssh.run {route_id, request}` → `{reply}` or `{error, reason}`;
  - `ssh.forget {route_id}`.
- **Debug only:** `stats` adds the §6.2 counters and per-connection
  `app_streams`.

## 8. The CLI

| Where | Command | Through |
|---|---|---|
| A profile Mousse runs | `mousse-cli net-engine status`, `devices`, `invite [--link]`, `join <link>`, `remove <device>`, `addresses <device> <route>…`, `routes [--lan on\|off] [--tailnet on\|off] [--public h:p] [--tunnel url] [--port N] [--test]`, `ssh add <target> [--profile <selector>\|--new <label>]` | the daemon's owner-only IPC (`src/cli/daemonClient.ts:66`), the same service methods as the UI, journals included |
| The same, run over SSH | `mousse-cli net-engine ssh` (§3.4) | the same, with `disableAutoStart` |
| A standalone `serve` (headless, no app) | `mousse-helper invite [--link]`, `join`, `peers`, `grants`, `remove`, `term`, plus new `serve --ws-port N --public h:p --tunnel url --no-lan` and `routes test` | `ipc.rs` |
| A profile Mousse runs, over SSH | `mousse-helper pipe --profile <selector>` | `ipc.rs` |

- **Typing the code.** `join` reads the code from the terminal, never from
  argv or a pipe. That is the "installed app" of wire 10.6.2. Without a
  terminal it refuses with `no_tty`.
- **Approval.** `join` prints the destinations and asks for `y` before
  dialling, as the dialog does. `--yes` is refused without a terminal for
  the same reason as the code.
- **No autostart for `ssh`.** Every other `net-engine` command keeps the
  usual autostart.
- **`term`** stays standalone-only. App-mode terminals use the app's
  existing remote terminal.
- **Local only.** `mousse-cli net-engine` adds no network surface. Its
  methods join `NET_ENGINE_LOCAL_METHODS` (`shared/netEngine/local.ts`).

## 9. Remaining RPC

### 9.1 Methods

1a's `ENGINE_OWNER_METHODS` (`shared/netEngine/allowlist.ts:9`) leaves out
the groups below. 1b adds the first four. Spaces, chats and bots wait for
Teams membership (1a §4.6).

| Group | Methods | What it needs over the engine |
|---|---|---|
| Editor | `routed.editor.folder`, `routed.editor.ask` (`accessClasses.ts:201-203`) | allowlist, plus the §9.2 refusal in `authorizeEngine` |
| Editor tunnel | local `net.editor.tunnel.open/read/write/end/close`, kinds `ssh` and `ssh.check` (`shared/net/tunnel.ts`), driven by `mousse-cli net ssh-proxy` | §9.2 |
| Access | `bridge.access.mine` (`view`) | allowlist only |
| Chat dispatch | `bridge.dispatch` (`work`), sent through `BridgeHub.prepare` (`ChatTaskDispatchService.ts:58`) | allowlist, plus `prepare` on the Hub's engine branch |
| Hub local methods | the 21 `bridge.hub.*` (`bridge/hub/local.ts:71-97`), `not_supported` for engine ids today (`hub/service.ts:272`) | the 1a M4 engine branch behind each, with no v1 fallthrough |
| Not in 1b | `bridge.thread.open`, `bridge.lists.open` (v1 Bridge views; M13 checks whether anything still calls them); `spaces.*`, `chats.send/cancel`, `bots.*` (Teams); the phone API names (Phase 2); `net.direct.*`, `authority.transfer.*` (v1 only) | |

### 9.2 The editor tunnel over the engine

The existing editor security is reused unchanged. No new splice is
written.

- **Own instances.** Today `EditorTunnels` and `EditorEndpoint` are built
  inside v1's `NetService` (`NetService.ts:827`). The engine service builds
  its own pair at start, with the same options and its own refusal, so the
  editor works over the engine with v1 off. The two pairs share no state.
  `net/editor/` is marked in its header and in PLAN as kept through
  Phase 2's v1 removal.

- **Transport.** A new helper label, `mousse.tunnel` (interactive,
  caller-opened), carries one tunnel. The first frames are v1's
  `TunnelMessage`s (`tunnel.open`, then `tunnel.ready` or `tunnel.close`).
  After `tunnel.ready` the stream carries raw bytes. The app wraps the
  stream as a `TunnelLink` (`net/editor/tunnel.ts`), so `EditorTunnels`
  runs as it does for v1.
- **Far end.** The same as v1: `EditorEndpoint` (`net/editor/endpoint/`),
  the in-daemon SSH server fed by `endpoint.serve`, or the system SSH
  server where v1 already falls back to it (`no_ssh_server`,
  `host_untrusted`, `no_host_key`).
- **Host keys.** `tunnel.ready` carries the host keys. The caller pins them
  with `editor.pinHostKeys` before the stream reaches `ssh-proxy`, as
  `openEditorTunnel` does (`NetService.ts:2985-3000`).
- **Refusal.** `EditorTunnelOptions.refusal` for an engine link is
  `engineEditorRefusal(identity)`, the engine twin of
  `NetService.deviceRefusal` (`NetService.ts:2884`). Its answers, in order:
  - `net_off`: the profile's networking is off;
  - `blocked`: the row is missing, `removing`, removed or blocked, or not
    connected;
  - `capability`: the grant is not live with role `owner`;
  - `setting_off`: `workOnThreads` is off;
  - `editor_off`: the device's editor switch is off.

  `checkNodePolicy` is not used for this, since it has no editor check.
  `authorizeEngine` runs the same function for `routed.editor.*`.
- **Teardown.** `EditorTunnels.reconcile()` runs on every change that can
  take the right away: an editor or work switch, a block, a grant closed
  (`grant.closed`), a row leaving `connected`, and networking off. It ends
  live tunnels and sweeps what the endpoint started for that device. A
  closed session ends its tunnels through `link.onClosed`.
- **Tests** (`phase1b.editor-app`):
  - a live owner grant with editor off: `tunnel.open` → `editor_off`, and
    no endpoint session;
  - editor turned off with a tunnel open: the tunnel closes with
    `editor_off`, and the endpoint's processes for that device are swept;
  - the same for a block and for a removal.

## 10. Start at login

- **Reuse.** The existing startup entry (`mms/startup/*`, the same one
  `mousse-cli service install` writes) is the only registration. 1b adds
  no registration code and never removes the entry on its own.
- **Ask once.** When a profile's networking is first turned on and
  `startupStatus().installed` is false, the app asks once: "Start Mousse at
  login so your other computers can reach this one?" with "Start at login"
  and "Not now". The answer is remembered.
- **Over SSH.** `prepare` cannot ask. Its reply carries `starts_at_login`,
  and A's dialog shows "Mousse on <host> won't start after a restart" when
  it is false.
- **Startup speed:** the daemon reports ready first. `startNetworkedProfiles`
  then runs in the background, as in 1a §1. No 1b work runs before ready:
  launchers, `endpoints.json` and route detection run after ready, and the
  keystore unlock waits for the helper.
- **Without a login:** a profile still is not reachable with nobody logged
  in. That waits for the headless daemon (PLAN §8).

## 11. Situations

| Situation | Behaviour |
|---|---|
| Tailnet goes down | Its addresses leave the next ticket. Callers that dial a dead tailnet route fall to the next tier. |
| Quick tunnel URL changes | Peers keep the old route and fail on it. The owner adds the new address on each, or uses a new link, SSH or LAN. |
| Port forward behind CGNAT, or no hairpin | `routes.test` says "Couldn't confirm from this network". Saving still works. |
| SSH key needs a passphrase and the daemon has no agent | `auth_denied`. The tooltip suggests the agent or a key file. The daemon inherits `SSH_AUTH_SOCK` from the app when the app starts it (risk 3). |
| Remote Mousse updated | The launcher path is stable, so nothing changes. |
| Remote profile removed, or networking off | `remote_no_endpoint`. The row reads "That profile is gone on <host>", with Remove. |
| Remote user logged out | `remote_not_running`, retried with backoff inside the connection window. |
| SSH host key rotated | `host_key_changed`, not retried until "Check and trust again". |
| Path came up over SSH, LAN returns | The path stays on SSH until it renews or drops. |
| Two profiles on B, A adds one over SSH | Only that profile's selector is used. The other is untouched, and either may be paired elsewhere. |
| SSH add retried after a lost reply | The same `request_id` resumes or returns the stored result, with no second grant or profile. |
| B's owner removes A while A is still retrying | The request is `removed`. A stops and shows "<B> removed access". |
| App upgraded from 1a with ticket hints in `peers.json` | Only 1a's automatic rule applies to them until the owner approves more (§1.3). |
| Send link opened twice, or in two windows | The flow-record hold refuses the second (`busy`). Attempts are shared through the record. |
| App killed mid-code | The debit is already stored. Reopening the link resumes with the attempts left, or learns the outcome from the pending record. |
| Removal saving while a link join is in flight | The pause fence refuses the proof and closes join-only connections. |
| A granted peer re-pairs while the pool is full or removal is paused | The proof opens nothing; the connection stays live under its grant (§6.2). |
| Wrong clock | 1a's neutral message, on every route. |

## 12. Threat model and privacy updates

- **threat-model.md**, new "Routes beyond the LAN" section:
  - internet-exposed listeners (port forward, tunnel) and the per-kind
    admission pools, which are not denial-of-service protection;
  - every route ends at the same pin check and step 2;
  - a destination outside private literals is dialled only after the
    owner's approval, which is stored with its source. The dialled address
    is the classified one;
  - the listener binds only the interfaces the owner selected;
  - a peer can never make a device run SSH, and plain `ws` is never dialled
    off loopback;
  - SSH add trusts the confirmed SSH host key plus the login, and nothing
    else;
  - the `ws` listener refuses browsers;
  - the editor tunnel over the engine keeps v1's rules: the editor switch,
    teardown on every rights change, and loopback-only forwards.
- **privacy.md:**
  - a port forward or tunnel lets any internet prober learn the host's
    identity key (already true on a LAN, now global);
  - an approved destination learns the joiner's IP address before any pin
    check;
  - the tunnel provider sees both IPs, timing, sizes and the WebSocket
    path, never content;
  - the tailnet coordinator sees that two nodes talk;
  - over SSH, B's profile list (labels, no paths) is shown to whoever logs
    in as that OS account.
- **wire.md 10.2.1:** the `wss` grammar (§1.1).
- **limits.md:** the §13.3 rows.

## 13. Files

### 13.1 Engine

- `mousse-net-core/src/pairing/route.rs`: the `Wss` route, grammar and
  vectors.
- `mousse-net-io/src/pipe.rs` becomes `pipe/{mod,tcp,ws,ssh}.rs`, with
  `classify`, `LocalRoute`, resolve-then-dial and tiered candidates.
- `caller.rs`: the bounded tiered race; the route cache with a generation;
  kind 2 off the consented path.
- `host.rs`: admission pools; the admission fence checked at gate
  registration and enrollment; join-only connections closed when their
  invitation ends.
- `store.rs`: SSH route details in `PeerRecord`; `approvals.json`; the
  kind-2 completion records in `joins/`.
- `mousse-helper`:
  - `serve.rs`: the `ws` listener, `--ws-port`, `--public`, `--tunnel`,
    `--no-lan`, per-address binding, the app-mode IPC listener (pipe and
    status), and `routes.json` read at start;
  - `ipc.rs`: the bounded line reader and the buffer-keeping handoff;
  - new `pipe.rs` (the remote `pipe` command, the marker, `--profile`,
    ending when the helper closes);
  - new `ssh.rs` (resolve, constrained config, probe with kept key bytes,
    trust, run, the connection window);
  - `app/pairing.rs`: link invitations, `join` arrival, `approved` and
    code, `join.status` and `join.ack`;
  - `app/paths.rs`: routes config and the §1.3 source policy;
  - `peer.rs`: pipe-generic joins, and kind 2 ignoring `consented` and
    `pinned`.
- `mousse-check`: `probe`, the Plus stand-in, `--route` and the
  route-selection assertion in `tools/app-check/run.mjs`,
  `tools/build-smoke.mjs`, and `checks/phase1b.toml`.
- `spec/wire.md`, `spec/threat-model.md`, `spec/privacy.md`,
  `docs/limits.md`.

### 13.2 Mousse

- `src/mms/netEngine/`:
  - `pairing.ts`: link host and joiner, kind-2 recovery through
    `join.status`, the `ssh_*` states and the `source: "ssh"` skips, SSH
    add on A, the `share` list in pairback;
  - `NetEngineService.ts`: routes settings and helper restart, launchers
    and `endpoints.json`, the startup question, the engine's own
    `EditorTunnels` and `EditorEndpoint`;
  - `helper/appChannel.ts`: protocol 1.1;
  - new `ssh.ts`: the remote `net-engine ssh` handler (`profiles`,
    `prepare`, the `net_engine_ssh_requests` journal and its steps);
  - new `editorRefusal.ts`: `engineEditorRefusal`.
- `src/shared/netEngine/allowlist.ts` and `local.ts`.
- `src/cli/commands/netEngine.ts`.
- `src/main/index.ts`: the `mousse://` scheme, packaged builds only.
- Hub:
  - `bridge/hub/service.ts`: the local methods' engine branch and
    `prepare`;
  - `net/editor/tunnel.ts`: an engine `TunnelLink`, and `reconcile()` wired
    to engine changes.
- Renderer: `components/netEngine/`:
  - `AddDeviceDialog`: Send link, Enter link (with destinations) and Over
    SSH tabs;
  - `ReachSection`: LAN, Tailnet, Port forward and Tunnel, each with Test;
  - row route labels and "Addresses <B> offered".

### 13.3 New limits

"Tighten" means overrides may only lower the value.

| Variable | Default | Allowed | What it limits |
|---|---|---|---|
| `MOUSSE_NET_PREAUTH_TCP` | 48 | 1 to 48 (tighten) | TCP connections not yet live, per endpoint |
| `MOUSSE_NET_PREAUTH_WS` | 16 | 1 to 16 (tighten) | ws connections not yet live, per endpoint |
| `MOUSSE_NET_PREAUTH_PIPE` | 4 | 1 to 4 (tighten) | pipe connections not yet live, per endpoint |
| `MOUSSE_NET_PREAUTH_PER_SOURCE` | 8 | 1 to 8 (tighten) | TCP, per IPv4 address or IPv6 /64 |
| `MOUSSE_NET_WS_UPGRADE_WAIT_MS` | 5000 | 100 to 5000 (tighten) | Time for the whole upgrade request |
| `MOUSSE_NET_WS_HEADER_MAX_BYTES` | 8192 | 1024 to 8192 (tighten) | Upgrade request size |
| `MOUSSE_NET_WS_MESSAGE_MAX_BYTES` | 65536 | tighten only; the floor is set while building (§15) | One received ws message |
| `MOUSSE_NET_IPC_LINE_MAX_BYTES` | 65536 | 1024 to 65536 (tighten) | One IPC line |
| `MOUSSE_NET_IPC_FIRST_LINE_WAIT_MS` | 2000 | 100 to 2000 (tighten) | Time for the first IPC line |
| `MOUSSE_NET_TIER_HEAD_START_MS` | 500 | 0 to 10000 | Wait before `ws` candidates start |
| `MOUSSE_NET_DIAL_MAX_CANDIDATES` | 16 | 1 to 64 | Candidates per search |
| `MOUSSE_NET_DIAL_FAST_TIERS_MS` | 12000 | 1000 to 60000 | Latest start of the `ssh` tier |
| `MOUSSE_NET_DIAL_SEARCH_MS` | 45000 | 5000 to 300000 | One whole search |
| `MOUSSE_NET_WS_DIAL_TIMEOUT_MS` | 10000 | 500 to 60000 | One `ws` try: connect, outer TLS, upgrade, step 1 |
| `MOUSSE_NET_SSH_DIAL_TIMEOUT_MS` | 20000 | 1000 to 120000 | One `ssh` try: login, marker, remote `pipe`, step 1 |
| `MOUSSE_NET_SSH_CONNECT_TIMEOUT_SECS` | 10 | 1 to 120 | `ConnectTimeout`, and `ssh -G` |
| `MOUSSE_NET_SSH_ALIVE_INTERVAL_SECS` | 15 | 1 to 300 | `ServerAliveInterval` |
| `MOUSSE_NET_SSH_ALIVE_COUNT` | 3 | 1 to 20 | `ServerAliveCountMax` |
| `MOUSSE_NET_SSH_TARGET_CONNECTS` | 5 | 1 to 5 (tighten) | ssh connections per resolved host and port per window |
| `MOUSSE_NET_SSH_TARGET_WINDOW_MS` | 30000 | 30000 to 600000 (tighten: longer only) | The window |
| `MOUSSE_NET_SSH_SETUP_TIMEOUT_MS` | 60000 | 1000 to 600000 | One `ssh.run` or `ssh.probe` |
| `MOUSSE_NET_SSH_STDERR_MAX_BYTES` | 16384 | 1024 to 1048576 | `ssh` stderr kept for the reason |
| `MOUSSE_NET_SSH_PREAMBLE_MAX_BYTES` | 65536 | 0 to 65536 (tighten) | Output skipped before the marker |
| `MOUSSE_NET_SSH_REPLY_MAX_BYTES` | 1048576 | 1024 to 1048576 (tighten) | One `ssh.run` reply |
| `MOUSSE_NET_PIPE_CONNECT_WAIT_MS` | 2000 | 100 to 60000 | Remote `pipe`: reach the helper's IPC and get `ok` |
| `MOUSSE_NET_JOIN_DONE_KEEP_SECS` | 86400 | 0 to 2592000 | How long an unacknowledged kind-2 completion record is kept after the ticket expires |
| `MOUSSE_NET_ENGINE_SSH_REQUEST_DEADLINE_MS` (app) | 120000 | 1000 to 600000 | App deadline for `ssh.*` and one SSH add try |
| `MOUSSE_NET_ENGINE_SSH_REQUEST_MAX_AGE_SECS` (app) | 86400 | 60 to 86400 (tighten) | How long A may repeat one `request_id`; B refuses older unknown ones |
| `MOUSSE_NET_ENGINE_SSH_REQUEST_KEEP_SECS` (app) | 604800 | at least twice the maximum age | How long B keeps request records |

Fixed on purpose: the 65 536-byte `ws` message maximum, the
`/mousse-net/1` path suffix, the `mousse.1` subprotocol, the
`mousse-ssh/1` marker, the selector grammar and the pipe exit codes.

## 14. Owner checks: `checks/phase1b.toml`

- **Build binding.** As in 1a §9. `app/MOUSSE_REVISION` moves to the
  `net-engine-1b` tip once S1, S2 and E12 have landed.
- **Routes in app checks.** `run.mjs --route tcp|ws|ssh`. The app is given
  only that route, and the check asserts from `conn.up.route` that every
  connection used it. Otherwise it fails with `route_mismatch`.
  - `tcp`: debug loopback, mapped to `tailnet` and then `public` through
    `MOUSSE_NET_TEST_CLASS_MAP`. The pipe code is the same for every class.
    The class decides policy, which `phase1b.routes` proves with real
    address literals. The check also proves the approval path: the public
    hint is dialled only after Connect.
  - `ws`: a local TLS-terminating tunnel stand-in. Its certificate comes
    from the debug-only extra root (§4.2).
  - `ssh`: §3.7's server.
  - No real tailnet, Funnel or cloudflared account is used in any check.
- **Route cases (kit change).** A check may list `cases = ["tcp", "ws",
  "ssh"]`. Each case is its own signed result, and the check passes only
  when every case passes. Each control runs once per case and must print
  FAIL in each. Today `cases()` (`manifest.rs:234`) reports one unnamed
  case when there is no matrix, so E12 adds the list.
- **Same cases on every route.** `routes-app` runs 1a's app cases on each
  route, with their controls: `picker-v1-off`, `private-streams`,
  `pair-both-ways`, `removal`, `once-or-unknown`, `reconnect`,
  `path-switch` and `shared-computer`.
- **Reverse direction, with no PC listener off loopback:**
  - single-machine checks: both endpoints run on the PC, and every
    listener (TCP, ws stand-in, SSH test server) is on loopback. The
    reverse direction uses the same route kind: `tcp` loopback, or the
    joiner's own ws stand-in on loopback, shared through the `share` list.
    For `ssh`, the kit configures two separate loopback SSH routes, one
    per direction, each to its own test server, and sets each as the other
    side's owner address. `pair-both-ways` then asserts both directions.
    The real SSH add (`ssh-add-app`) asserts one direction.
  - cross-machine checks: only PC → Mac traffic is tested. The pairing is a
    kit fixture: the Mac grants the PC, and the PC pins the Mac, as
    `phase1a.pair-offline` injects its ticket. The Mac never dials the PC.
    For `ssh`, the pairing is a real SSH add from the PC to the Mac's test
    server, and the cell asserts one direction.
  - the attested chat-link check needs the Mac → PC direction too. The kit
    runs a relay on the Mac. The PC's kit opens one outbound connection to
    it and carries the Mac's dials back to the PC's loopback listener. The
    PC shares the relay's address (a private LAN literal) in pairback.
- **Plus and egress.** Every app check points the app's Plus endpoints at
  a recorder on loopback that accepts, records the request and answers
  `403`. Any attempt fails the run with `plus_contacted`, and the
  recorder's self-test proves it records. Egress is also denied at run
  time, so an endpoint the redirect missed cannot get out unseen:
  - the daemon runs with an in-process guard, loaded before any other code
    in check mode. It refuses and records any socket or DNS lookup to
    anything but loopback and the cell's allowed peer address;
  - the helper, in debug builds, refuses any connection outside
    `MOUSSE_NET_TEST_EGRESS` (loopback, plus the Mac's address in cross
    cells);
  - where the OS allows it without admin rights, the run is also fenced:
    a network namespace with loopback only on Linux, and a `sandbox-exec`
    profile on macOS. Windows relies on the two guards.

  Any refused attempt fails with `egress_attempted`.
- **Topology.** The PC listens only on loopback. Cross-machine cells have
  the Mac listen (TCP, the test SSH server, the tunnel stand-in, the
  relay), and the PC dials.
- **Deep link.** `link-app` starts the packaged-mode handler with the URL
  in argv, which is how Windows and Linux deliver a scheme. The test app
  runs with its own user-data folder (`--user-data-dir` in the test home),
  so its single-instance lock is its own and `second-instance` never hands
  the link to the Mousse already running on the PC. The check confirms
  that the selected profile joins. macOS `open-url` and a real click are
  the attested check.
- **Chat fixture.** The attested check needs no chat account. The kit
  serves a static chat page on loopback that shows a message with the
  link. The tester opens it in the default browser and clicks the link.

```toml
phase = "phase1b"
title = "User routes, CLI and Send link"
plan = "docs/PLAN.md#phase-1b-user-routes-cli-and-send-link"

[[check]]
id = "phase1b.routes"
title = "Route grammar (wss path, loopback-only ws); allowlist classify; approval policy and stored provenance; resolve once and dial the classified address; bounded tiered dial; renewals and last_route filtered by approvals; only selected interfaces bound and served addresses advertised; routes.test"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 30
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
]
control = [
  { name = "peer-ssh-routes", breaks = "a peer's routes may name ssh targets", env = { RUSTFLAGS = '--cfg mousse_control="peer-ssh-routes"' } },
  { name = "loopback-routes", breaks = "a release-policy build dials a ticket's loopback hint", env = { RUSTFLAGS = '--cfg mousse_control="loopback-routes"' } },
  { name = "plain-ws-from-ticket", breaks = "a ticket's plain ws hint is dialled", env = { RUSTFLAGS = '--cfg mousse_control="plain-ws-from-ticket"' } },
  { name = "unapproved-public", breaks = "a ticket's public hint is dialled without approval", env = { RUSTFLAGS = '--cfg mousse_control="unapproved-public"' } },
  { name = "unapproved-last-route", breaks = "last_route and renewals skip the approval filter", env = { RUSTFLAGS = '--cfg mousse_control="unapproved-last-route"' } },
  { name = "upgrade-trusts-routes", breaks = "a 1.0 store's routes count as approved", env = { RUSTFLAGS = '--cfg mousse_control="upgrade-trusts-routes"' } },
  { name = "resolve-again", breaks = "the pipe resolves the name again instead of dialling the classified address", env = { RUSTFLAGS = '--cfg mousse_control="resolve-again"' } },
  { name = "unlisted-allowed", breaks = "classify treats unlisted ranges as public", env = { RUSTFLAGS = '--cfg mousse_control="unlisted-allowed"' } },
  { name = "stale-renewal-routes", breaks = "renewals dial the remembered list after an edit", env = { RUSTFLAGS = '--cfg mousse_control="stale-renewal-routes"' } },
  { name = "unbounded-candidates", breaks = "the search ignores DIAL_MAX_CANDIDATES and DIAL_SEARCH_MS", env = { RUSTFLAGS = '--cfg mousse_control="unbounded-candidates"' } },
  { name = "ssh-races-lan", breaks = "ssh candidates start with tcp ones", env = { RUSTFLAGS = '--cfg mousse_control="ssh-races-lan"' } },
  { name = "bind-all-lan-off", breaks = "the listener binds 0.0.0.0 with LAN off", env = { RUSTFLAGS = '--cfg mousse_control="bind-all-lan-off"' } },
]

[[check]]
id = "phase1b.admission"
title = "Per-kind pre-auth pools taken at accept; ws upgrade and IPC line caps; slot held through join-only until the invitation ends; a re-pair from live takes a slot and meets the fence; the fence at gate registration and enrollment on every transport, raced against TLS completion; buffer-keeping IPC handoff; IPv6 per /64; tighten-only overrides"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 18
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_admission", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_admission", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_admission", "--no-fail-fast"] },
]
control = [
  { name = "no-preauth-budget", breaks = "no pre-auth cap on any listener", env = { RUSTFLAGS = '--cfg mousse_control="no-preauth-budget"' } },
  { name = "shared-preauth-pool", breaks = "one pool for all listener kinds, so a ws flood blocks the pipe", env = { RUSTFLAGS = '--cfg mousse_control="shared-preauth-pool"' } },
  { name = "ws-slot-after-headers", breaks = "the ws slot is taken after the upgrade is read", env = { RUSTFLAGS = '--cfg mousse_control="ws-slot-after-headers"' } },
  { name = "ipc-unbounded-line", breaks = "IPC lines are read with no size or time cap", env = { RUSTFLAGS = '--cfg mousse_control="ipc-unbounded-line"' } },
  { name = "ipc-handoff-drops-buffer", breaks = "the pipe handoff drops bytes the line reader had buffered", env = { RUSTFLAGS = '--cfg mousse_control="ipc-handoff-drops-buffer"' } },
  { name = "join-only-frees-slot", breaks = "a join-only connection releases its slot before enrollment", env = { RUSTFLAGS = '--cfg mousse_control="join-only-frees-slot"' } },
  { name = "join-only-outlives-invitation", breaks = "a join-only connection stays after its invitation ends", env = { RUSTFLAGS = '--cfg mousse_control="join-only-outlives-invitation"' } },
  { name = "fence-at-accept-only", breaks = "the fence is checked at accept but not at gate registration, so a handshake finishing during the pause gets in", env = { RUSTFLAGS = '--cfg mousse_control="fence-at-accept-only"' } },
  { name = "fence-tcp-only", breaks = "the fence covers TCP but not ws and pipe", env = { RUSTFLAGS = '--cfg mousse_control="fence-tcp-only"' } },
  { name = "enroll-while-paused", breaks = "enrollment commits a grant while paused", env = { RUSTFLAGS = '--cfg mousse_control="enroll-while-paused"' } },
  { name = "repair-skips-slot", breaks = "an already-granted peer's re-pair proof goes join-only with that kind's pool full", env = { RUSTFLAGS = '--cfg mousse_control="repair-skips-slot"' } },
  { name = "repair-skips-fence", breaks = "an already-granted peer's re-pair proof goes join-only while removal is paused", env = { RUSTFLAGS = '--cfg mousse_control="repair-skips-fence"' } },
  { name = "limits-raise", breaks = "an override may raise a tighten-only limit", env = { RUSTFLAGS = '--cfg mousse_control="limits-raise"' } },
]

[[check]]
id = "phase1b.ssh"
title = "ssh-stdio through the system client and a local test server: one constrained config per route with the kept ssh -G options, strict pinned host keys written from the probed bytes, atomic rotation, marker and preamble, pipe --profile to the running helper ending when the helper closes, the window per resolved host and port"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 16
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
]
control = [
  { name = "accept-new-host-key", breaks = "ssh runs with StrictHostKeyChecking=accept-new", env = { RUSTFLAGS = '--cfg mousse_control="accept-new-host-key"' } },
  { name = "user-config-in-pipe", breaks = "the pipe dial reads the user's ssh config instead of the route's", env = { RUSTFLAGS = '--cfg mousse_control="user-config-in-pipe"' } },
  { name = "trust-unprobed-key", breaks = "ssh.trust writes a key other than the probed bytes", env = { RUSTFLAGS = '--cfg mousse_control="trust-unprobed-key"' } },
  { name = "pipe-no-token", breaks = "the IPC hands over a pipe without the token", env = { RUSTFLAGS = '--cfg mousse_control="pipe-no-token"' } },
  { name = "no-preamble-skip", breaks = "the client feeds output before the marker to TLS", env = { RUSTFLAGS = '--cfg mousse_control="no-preamble-skip"' } },
  { name = "pipe-outlives-helper", breaks = "the remote pipe waits for stdin to end after the helper closed", env = { RUSTFLAGS = '--cfg mousse_control="pipe-outlives-helper"' } },
  { name = "window-per-route", breaks = "the connection window is kept per route, not per resolved host and port", env = { RUSTFLAGS = '--cfg mousse_control="window-per-route"' } },
]

[[check]]
id = "phase1b.ws"
title = "Loopback ws listener refuses non-upgrade, wrong path, Origin, missing subprotocol, slow or large headers and text frames; wss client with the platform verifier plus a debug-only root through a TLS-terminating stand-in"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 12
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
]
control = [
  { name = "ws-allow-origin", breaks = "the ws listener accepts requests with Origin", env = { RUSTFLAGS = '--cfg mousse_control="ws-allow-origin"' } },
  { name = "plain-ws-off-loopback", breaks = "the client dials plain ws to a non-loopback address", env = { RUSTFLAGS = '--cfg mousse_control="plain-ws-off-loopback"' } },
  { name = "release-test-root", breaks = "a release build reads the extra test root", env = { RUSTFLAGS = '--cfg mousse_control="release-test-root"' } },
]

[[check]]
id = "phase1b.send-link"
title = "Pair by link and code; every tampered field fails as §5.5; three wrong codes end the invitation and the flow, and reopening fails on both sides; fresh and expired swapped links never end already-paired; completion records; crashes after confirmation, after the completion record and with a pre-existing pin recover correctly"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 22
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
]
control = [
  { name = "journal-pins-link", breaks = "a consented send-link join counts the ticket's host as pinned", env = { RUSTFLAGS = '--cfg mousse_control="journal-pins-link"' } },
  { name = "fabricate-pending-kind2", breaks = "an expired kind-2 join makes up a pending outcome", env = { RUSTFLAGS = '--cfg mousse_control="fabricate-pending-kind2"' } },
  { name = "skip-code-confirm", breaks = "the joiner accepts PAIRED without CPace key confirmation", env = { RUSTFLAGS = '--cfg mousse_control="skip-code-confirm"' } },
  { name = "host-attempts-reset-on-reconnect", breaks = "a new connection resets the host's attempt count", env = { RUSTFLAGS = '--cfg mousse_control="host-attempts-reset-on-reconnect"' } },
  { name = "joiner-records-in-memory", breaks = "app mode keeps joiner flow records in memory, so a restart restores three tries", env = { RUSTFLAGS = '--cfg mousse_control="joiner-records-in-memory"' } },
  { name = "invitation-survives-exhaustion", breaks = "the host keeps the invitation after the third failure", env = { RUSTFLAGS = '--cfg mousse_control="invitation-survives-exhaustion"' } },
  { name = "link-accepts-kind1", breaks = "a kind-1 ticket is accepted with arrival link", env = { RUSTFLAGS = '--cfg mousse_control="link-accepts-kind1"' } },
  { name = "no-completion-record", breaks = "the pin is saved without a completion record first", env = { RUSTFLAGS = '--cfg mousse_control="no-completion-record"' } },
  { name = "same-code-after-failure", breaks = "the host keeps showing the failed attempt's code", env = { RUSTFLAGS = '--cfg mousse_control="same-code-after-failure"' } },
]

[[check]]
id = "phase1b.no-rpc-without-grant"
title = "The §6.3 probe on every route (tcp, ws, ssh): each case gets its own wire close and its own app-side record; the editor-off case is delivered, then refused"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
app = true
cases = ["tcp", "ws", "ssh"]
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.no-rpc-without-grant", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.no-rpc-without-grant", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.no-rpc-without-grant", "--out", "{out}"] },
]
control = [
  { name = "admit-ungranted", expect_reason = "wire_accepted", breaks = "the host gate treats an identity awaiting a proof as live", env = { RUSTFLAGS = '--cfg mousse_control="admit-ungranted"' } },
  { name = "join-only-streams", expect_reason = "wire_accepted", breaks = "a join-only connection may open streams", env = { RUSTFLAGS = '--cfg mousse_control="join-only-streams"' } },
  { name = "inbound-before-live", expect_reason = "probe_reached_app", breaks = "the helper announces a connection before it is live", env = { RUSTFLAGS = '--cfg mousse_control="inbound-before-live"' } },
  { name = "tunnel-ignores-editor", expect_reason = "probe_reached_app", breaks = "the engine editor refusal skips the editor switch, so the editor-off case starts an endpoint session", env = { MOUSSE_NET_ENGINE_CONTROL = "tunnel-ignores-editor" } },
  { name = "no-preauth-budget", expect_reason = "wire_accepted", breaks = "no pre-auth cap on any listener", env = { RUSTFLAGS = '--cfg mousse_control="no-preauth-budget"' } },
]

[[check]]
id = "phase1b.routes-app"
title = "1a's app cases (picker-v1-off, private-streams, pair-both-ways, removal, once-or-unknown, reconnect, path-switch, shared-computer) over tcp (tailnet and public classes), ws and ssh (two loopback SSH routes, one per direction), route asserted, Plus recorded and egress denied"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
app = true
cases = ["tcp", "ws", "ssh"]
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.routes-app", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.routes-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.routes-app", "--out", "{out}"] },
]
control = [
  { name = "plus-probe", expect_reason = "plus_contacted", breaks = "route setup asks Plus for anything", env = { MOUSSE_NET_ENGINE_CONTROL = "plus-probe" } },
  { name = "egress-probe", expect_reason = "egress_attempted", breaks = "the app contacts an address outside the cell, not through the Plus redirect", env = { MOUSSE_NET_ENGINE_CONTROL = "egress-probe" } },
  { name = "lan-only-candidates", expect_reason = "unreachable", breaks = "the app passes only LAN addresses to the helper", env = { MOUSSE_NET_ENGINE_CONTROL = "lan-only-candidates" } },
  { name = "route-leak", expect_reason = "route_mismatch", breaks = "the app adds routes other than the one under test", env = { MOUSSE_NET_ENGINE_CONTROL = "route-leak" } },
]
# Each 1a case keeps its own 1a control and runs it in every route case.

[[check]]
id = "phase1b.link-app"
title = "Link pairing through the daemon's methods: argv activation in an isolated user-data folder into the selected profile, destinations approved and stored, code typed, Connected both ways; three wrong codes end both dialogs and reopening fails on both sides; restart mid-code keeps the count; every §5.5 tamper refused; a pre-existing pin promotes nothing; a crash before peers.json is saved, with WSS the only route, is replayed with routes and approvals; replay settles the on-disk mark after a restart and restores nothing after a removal; a damaged link after a one-way SSH add changes no grant on either side"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.link-app", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.link-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.link-app", "--out", "{out}"] },
]
control = [
  { name = "link-pinned-journal", expect_reason = "swapped_link_trusted", breaks = "the app passes pinned for send-link joins and the helper honours it", env = { MOUSSE_NET_ENGINE_CONTROL = "link-pinned-journal", RUSTFLAGS = '--cfg mousse_control="journal-pins-link"' } },
  { name = "done-pin-only", expect_reason = "no_route_after_recovery", breaks = "completion recovery saves the pin but not the peer's routes and approvals", env = { RUSTFLAGS = '--cfg mousse_control="done-pin-only"' } },
  { name = "pin-stored-memory-only", expect_reason = "pending_after_done", breaks = "replay after a restart settles only the in-memory flow, so the durable pending mark stays", env = { RUSTFLAGS = '--cfg mousse_control="pin-stored-memory-only"' } },
  { name = "replay-after-removal", expect_reason = "removed_peer_restored", breaks = "removal leaves completion records, so a later join.status restores the removed host", env = { RUSTFLAGS = '--cfg mousse_control="replay-after-removal"' } },
  { name = "already-grants-back", expect_reason = "grant_without_code", breaks = "a kind-2 already-paired outcome counts as done and runs grantBack", env = { MOUSSE_NET_ENGINE_CONTROL = "already-grants-back" } },
  { name = "pin-promotes-kind2", expect_reason = "promoted_without_completion", breaks = "app recovery moves a consented kind-2 row to joined on any held pin", env = { MOUSSE_NET_ENGINE_CONTROL = "pin-promotes-kind2" } },
  { name = "link-host-reset", expect_reason = "attempts_reset", breaks = "a reconnect gives the host three tries again", env = { RUSTFLAGS = '--cfg mousse_control="host-attempts-reset-on-reconnect"' } },
  { name = "link-joiner-reset", expect_reason = "attempts_reset", breaks = "an app restart mid-code gives the joiner three tries again", env = { RUSTFLAGS = '--cfg mousse_control="joiner-records-in-memory"' } },
  { name = "link-reopen-exhausted", expect_reason = "exhausted_link_reopened", breaks = "the host keeps the invitation after the third failure", env = { RUSTFLAGS = '--cfg mousse_control="invitation-survives-exhaustion"' } },
  { name = "link-code-bypass", expect_reason = "paired_without_code", breaks = "the joiner pairs without the code's key confirmation", env = { RUSTFLAGS = '--cfg mousse_control="skip-code-confirm"' } },
  { name = "link-tamper-kind", expect_reason = "tamper_accepted", breaks = "the helper accepts a kind-1 ticket from a link", env = { RUSTFLAGS = '--cfg mousse_control="link-accepts-kind1"' } },
  { name = "link-approvals-lost", expect_reason = "approval_lost", breaks = "a repeated join after restart ignores the consented row's approved list", env = { MOUSSE_NET_ENGINE_CONTROL = "link-approvals-lost" } },
  { name = "link-scheme-registered", expect_reason = "scheme_registered", breaks = "a kit-started app registers the mousse scheme", env = { MOUSSE_NET_ENGINE_CONTROL = "link-scheme-registered" } },
]

[[check]]
id = "phase1b.ssh-add-app"
title = "Add over SSH (test server, second Mousse home): existing profile, a profile paired elsewhere, a new one; never refused; one way only; B's row connected on A's first inbound; a crash at each prepare step resumes with one profile and one grant; a removal on B survives A's retries; an existing 1a row is kept and a lost existing reply is returned again; a crash between the row and its grant id resumes; a crash after the grant is saved, then a removal, then a restart with no retry leaves no grant and no row; a later Send link converts the rows and ends connected both ways; no daemon autostart"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.ssh-add-app", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.ssh-add-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.ssh-add-app", "--out", "{out}"] },
]
control = [
  { name = "refuse-if-paired", expect_reason = "refused_paired_profile", breaks = "SSH setup hides or refuses a profile paired elsewhere", env = { MOUSSE_NET_ENGINE_CONTROL = "refuse-if-paired" } },
  { name = "ssh-row-pairback", expect_reason = "ssh_row_pairback", breaks = "1a's advance, recovery or grantBack acts on a source ssh row", env = { MOUSSE_NET_ENGINE_CONTROL = "ssh-row-pairback" } },
  { name = "profile-before-journal", expect_reason = "duplicate_after_crash", breaks = "B creates the profile before journaling the request", env = { MOUSSE_NET_ENGINE_CONTROL = "profile-before-journal" } },
  { name = "grant-id-not-checked", expect_reason = "removed_grant_reported_live", breaks = "B answers a done request from its stored reply without checking the stored grant id", env = { MOUSSE_NET_ENGINE_CONTROL = "grant-id-not-checked" } },
  { name = "retry-after-connected", expect_reason = "removal_undone", breaks = "A repeats prepare after NOT_AUTHORIZED on a row that was connected", env = { MOUSSE_NET_ENGINE_CONTROL = "retry-after-connected" } },
  { name = "overwrite-1a-row", expect_reason = "1a_row_lost", breaks = "prepare overwrites an existing row for A", env = { MOUSSE_NET_ENGINE_CONTROL = "overwrite-1a-row" } },
  { name = "own-row-not-resumed", expect_reason = "stuck_granting", breaks = "a repeat after a crash treats the request's own ssh_granting row as another pairing's", env = { MOUSSE_NET_ENGINE_CONTROL = "own-row-not-resumed" } },
  { name = "existing-reply-not-kept", expect_reason = "existing_reply_lost", breaks = "a repeat after a lost existing reply answers removed", env = { MOUSSE_NET_ENGINE_CONTROL = "existing-reply-not-kept" } },
  { name = "removal-skips-unsaved-grant", expect_reason = "grant_survived_removal", breaks = "removal of a row with no grant id leaves the helper's grant, which reconciliation turns into a pairing", env = { MOUSSE_NET_ENGINE_CONTROL = "removal-skips-unsaved-grant" } },
  { name = "ssh-row-not-converted", expect_reason = "stuck_finishing", breaks = "a code-confirmed ticket join keeps source ssh on the row, so pairing never finishes", env = { MOUSSE_NET_ENGINE_CONTROL = "ssh-row-not-converted" } },
  { name = "remote-autostart", expect_reason = "daemon_started", breaks = "net-engine ssh starts the daemon", env = { MOUSSE_NET_ENGINE_CONTROL = "remote-autostart" } },
]

[[check]]
id = "phase1b.editor-app"
title = "Editor tunnel over the engine with v1 off: the engine's own EditorEndpoint with pinned host keys; refused with editor off; editor off, block or removal closes an open tunnel and sweeps"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.editor-app", "--out", "{out}"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.editor-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.editor-app", "--out", "{out}"] },
]
control = [
  { name = "tunnel-ignores-editor", expect_reason = "tunnel_without_editor", breaks = "the engine editor refusal skips the editor switch", env = { MOUSSE_NET_ENGINE_CONTROL = "tunnel-ignores-editor" } },
  { name = "no-reconcile", expect_reason = "tunnel_outlived_right", breaks = "engine rights changes do not run reconcile", env = { MOUSSE_NET_ENGINE_CONTROL = "no-reconcile" } },
]

[[check]]
id = "phase1b.routes-cross"
title = "PC dials the Mac over tcp (Mac LAN listener, tailnet class by stand-in map), ws (tunnel stand-in on the Mac) and ssh (test server on the Mac), one signed result per route, route asserted, Plus recorded and egress denied; terminal and remote thread on the Mac from the PC"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
cases = ["tcp", "ws", "ssh"]
device_steps = "As phase1a.pair-offline, once per case, with phase1b.routes-cross --route <case> on both run.mjs commands; the Mac runs --role host and is the only side listening off loopback. tcp and ws pair by kit fixture; ssh by a real SSH add from the PC. Controls run per case."
control = [
  { name = "plus-probe", expect_reason = "plus_contacted", breaks = "route setup asks Plus for anything", env = { MOUSSE_NET_ENGINE_CONTROL = "plus-probe" } },
  { name = "egress-probe", expect_reason = "egress_attempted", breaks = "the app contacts an address outside the cell", env = { MOUSSE_NET_ENGINE_CONTROL = "egress-probe" } },
  { name = "route-leak", expect_reason = "route_mismatch", breaks = "the app adds routes other than the one under test", env = { MOUSSE_NET_ENGINE_CONTROL = "route-leak" } },
]

[[check]]
id = "phase1b.desktop-builds"
title = "Release helper and packaged app for six targets: --version names the build; the packaged app starts; release serve answers mousse-check probe over tcp and ws on loopback"
targets = ["windows-x64", "windows-arm64", "macos-arm64", "macos-x64", "linux-x64", "linux-arm64"]
# One local entry per target running tools/build-smoke.mjs; macos-x64 under Rosetta, linux-arm64 in a container on the Mac.
# windows-arm64 runs natively on a GitHub-hosted windows-11-arm runner. The kit counts it, shown as hosted, only after checking
# the smoke and its must-fail control against both pinned commits and the artifact digest.
control = [
  { name = "stale-helper", breaks = "the packaged helper is not the build under test", env = { MOUSSE_BUILD_ID = "0000000+release" } },
]

[[check]]
id = "phase1b.pair-by-chat-link"
title = "Mac: Send link; post it in the kit's loopback chat page; PC opens the page in the default browser, clicks the link, types the code, connected both ways (Mac to PC through the kit relay). A second link with one character changed fails. Afterwards the installed Mousse is the mousse handler again."
targets = ["pc-to-mac-lan"]
manual = true
steps = "Attest with both app and helper builds."

[[check]]
id = "phase1b.login-start"
title = "With the existing startup entry installed, reboot the Mac and log in without opening Mousse: the PC's row reads Connected within 30 s"
targets = ["pc-to-mac-lan"]
manual = true
steps = "Attest with both app and helper builds."
```

## 15. Work breakdown

E = engine repo (`phase-1b`), M = Mousse (`net-engine-1b`).

| # | Repo | What | Proved by |
|---|---|---|---|
| S1 | E | **Pipe spike.** System `ssh` through the constrained config against the `russh` server on all three OSes. Spaces in the state path and in `UserKnownHostsFile` on Windows OpenSSH. A 150-byte macOS socket path. A login-shell preamble. A key logon in a non-interactive Windows context (a batch logon through Task Scheduler) reaching a GUI-session helper's named pipe, and the remote process exiting when the session is killed. The `cmd` form on Windows. | go or no-go for §3.3 and for Windows remotes; results recorded in §16 |
| S2 | E | **Route-policy spike.** Resolve-then-dial through a `TcpStream` handed to rustls and `tokio-tungstenite` (SNI by name, TCP by classified address). A bounded search with 16 dead candidates, timed. A cloudflared quick tunnel to a loopback ws listener on the Mac, observed once and never in a check. | numbers for §13.3 defaults; recorded in §16 |
| E7 | E | Route kinds and the `wss` grammar (spec and vectors); allowlist `classify`; the §1.3 source and approval policy (`join {approved}`, `approvals.json`, the upgrade rule, `approvals.list`); resolve-then-dial; the bounded tiered dial filtered by approvals, `last_route` included; the route cache generation; pipe-generic joins; `routes.json` read at start, per-address binding and `restart_needed`; `routes.test` | `phase1b.routes`; `ticket.json` vectors; `phase1a.discovery` still passing with its `public-routes` control |
| E8 | E | `WsPipe` client and server, the loopback listener, `--ws-port`, `--tunnel`; the debug-only extra root; the tunnel stand-in | `phase1b.ws` |
| E9 | E | `SshPipe`; `ssh.resolve`, `ssh.probe` with kept key bytes, `ssh.trust`, `ssh.run`, `ssh.forget`; the constrained config with the kept `ssh -G` options, and atomic rotation; marker and preamble; the window per resolved host and port; the remote `pipe --profile`, the buffer-keeping handoff and ending when the helper closes; the app-mode IPC listener (pipe and status); the `russh` test server | `phase1b.ssh` |
| E10 | E | Admission: per-kind pools at accept, the slot and fence on a re-pair from live, the bounded IPC reader, ws upgrade caps, slots through join-only until the invitation ends, the admission fence in `Host` at gate registration and enrollment, tighten-only limits | `phase1b.admission` |
| E11 | E | Send link in app mode: `invite.create {kind: link}`, `invite.code`, `join` arrival, `approved` and code, the code channel, kind 2 off the consented path and late recovery only from a genuine pending record; completion records only for a `PAIRED` of the ticket, with the full peer and approval writes, replayed by `join.status` under the peers lock and dropped on removal; `settle_stored` on disk; `join.ack`; protocol 1.1 | `phase1b.send-link`; Phase 0 `pairing_e2e` unchanged |
| E12 | E | Kit: `mousse-check probe` (with `mousse.tunnel`, admission cases and per-case app assertions), the Plus recorder and the egress guards, `cases` in the manifest, `run.mjs --route` and the route assertion, cross-machine pairing fixtures, two loopback SSH routes for the `ssh` case, the Mac relay, the loopback chat page, `tools/build-smoke.mjs` (version, start, probe), the hosted `windows-11-arm` job and its verification, `checks/phase1b.toml`; spec, threat model, privacy and limits docs | kit self-tests; every control prints FAIL |
| M8 | M | Protocol 1.1 client; `ReachSection` and helper restart on `restart_needed` (§1.5's one rule); owner addresses for every kind; destinations and "Also share" in the join dialog; "Addresses <B> offered"; route labels on rows | unit tests; `phase1b.routes-app` over `tcp` |
| M9 | M | Send link: host tab, Enter link, the `mousse://` scheme (packaged only), profile choice on activation, code entry, the `consented` row's `approved` and `share` lists, the pending link on a `source: "ssh"` row, converted only on the ticket's `PAIRED`; no `grantBack` on "already paired"; kind-2 recovery through `join.status` only | `phase1b.link-app`; component tests; real-app captures |
| M10 | M | SSH add (one way): dialog, fingerprint confirmation, profile choice; `mousse-cli net-engine ssh` (`profiles`, `prepare`, no autostart); the `net_engine_ssh_requests` journal with resumable steps (own-row and `existing` branches), the removal lock, the grant id on the request and the row, checked on retry, grant reconciliation by identity and `request_id` before removal or expiry, and retention; the `ssh_*` states and `source: "ssh"` skips; B's row connected on A's first inbound; launchers and `endpoints.json` under `MOUSSE_HOME` | `phase1b.ssh-add-app`; `phase1b.routes-app` over `ssh` |
| M11 | M | Tunnel UI and `routes.test` wording | `phase1b.routes-app` over `ws` |
| M12 | M | `mousse-cli net-engine` | CLI tests through the daemon's local methods |
| M13 | M | Remaining RPC (§9): the engine's own `EditorTunnels` and `EditorEndpoint` with an engine `TunnelLink`; `net/editor/` marked as kept; `engineEditorRefusal`, `reconcile()` on engine changes; editor rows; `bridge.access.mine`; `bridge.dispatch` with Hub `prepare`; the Hub local methods' engine branch | `phase1b.editor-app`; allowlist test; Hub tests with v1 unchanged; `phase1b.no-rpc-without-grant` |
| M14 | M | The startup question (existing entry); six-target packaging | startup tests; `phase1b.desktop-builds`; `phase1b.login-start` (attested) |

**Settle while building** (on the slices named):

- **E12, M8 — reverse WSS fixture.** It asserts three steps: nothing is
  disclosed before the joiner ticks "Also share", nothing is dialled
  before the receiving owner taps Use, then the reverse connection works.
- **E12 — `route-leak`.** The control makes the wrong route win (offered
  first, and answering), so the route assertion has something to catch.
  Adding a candidate alone can leave every connection correct.
- **M10, E12 — `retry-after-connected`.** Judged by an unexpected
  `prepare` arriving at B, not by B's answer, since B's removal journal
  would refuse it anyway and hide the faulty retry.
- **E8 — ws message cap.** The 65 536-byte cap becomes
  `WS_MESSAGE_MAX_BYTES`, a named tighten-only override (§13.3).
- **Order.** S1 and S2 first. E10 lands before E8's and E9's listeners are
  switched on. The CLI, remaining RPC and the six-build smoke keep their
  scope.

**Order:**

1. S1 and S2.
2. E7.
3. E8, E9, E10 and E11 in parallel; E8's and E9's listeners stay off until
   E10 lands.
4. E12.
5. M8 to M14, with M8 first and M13 independent of the route slices.
6. Pin `app/MOUSSE_REVISION`.
7. `phase1b.routes-cross` and the attested checks last.

## 16. Risks and settled questions

**Risks**

1. **Windows as an SSH remote.** The shell, launcher and named-pipe access
   differ. v1 never supported it. S1 decides, and on failure Windows
   remotes are refused with `windows_remote_unsupported`.
2. **Internet exposure.** Port forwards and tunnels put the listener on
   the internet. Security still rests on the pin and step 2, which every
   route shares and Phase 0 vectors cover. Denial of service is not
   defended, and §12 says so.
3. **No agent in the daemon.** A daemon started at login, by launchd or
   systemd, may lack `SSH_AUTH_SOCK`. v1 hit this. A passphrase-protected
   key then fails with `auth_denied` and a tooltip.
4. **Quick tunnels change URLs.** Peers keep the old route until the owner
   adds the new one. The UI recommends a named tunnel or Funnel.
5. **Non-LAN `tcp` in checks is a stand-in.** The class map relabels
   loopback, so checks prove the policy and the route used, not a real
   internet path. S2's cloudflared observation and the attested chat-link
   check are the only real internet paths.
6. **`windows-arm64` on a hosted runner.** Its result is a CI artifact, not
   a signed device result. It counts only after the kit checks the native
   packaged-app smoke and its must-fail control against both pinned
   commits and the artifact digest, and it is shown as `hosted`.
7. **1a slices still open in the app** (M5b, M7). 1b's M slices build on
   them, so 1b's app branch starts after they land.
8. **SSH add needs a running Mousse on B and the default `~/.mousse`
   folder.** Headless servers and custom remote folders wait for later
   phases.

**Settle while building**

- **Probe results.** The kit judges the wire observation and the
  app observation separately, so `tunnel-ignores-editor` fails with its
  own reason, not whichever comes first.
- **Port-forward bind address.** `routes.config` and the CLI take
  the local address the router forwards to, checked against this
  computer's interfaces.
- **Egress on Windows.** The test app also starts with a
  resolver rule or a dead loopback proxy, so Electron's own network stack
  is covered. The guard is a kit preload, never daemon code.
- **Scheme handler.** The attested chat-link check ends by
  restoring the installed Mousse as the `mousse://` handler.
- **Clock skew.** An `expired` answer to a request A just made
  shows 1a's wrong-clock message.

**Settled**

1. **SSH add direction:** one way only in 1b. A Send link can add the other
   direction once its code exchange succeeds (§3.6).
2. **ProxyJump and ProxyCommand:** refused in 1b (§3.1).
3. **Destinations:** 1a's automatic private-literal rule; explicit
   approval for everything else (§1.3).
4. **Identity binding:** host-local. Moot with the SSH bootstrap; the
   ticket schema is unchanged.
5. **Link form:** `mousse://` plus paste; no https page (§5.2).
6. **Mousse not running on the remote:** typed `remote_not_running`; a
   running daemon is required; nothing is started or installed (§3.4).
7. **Live path upgrade:** deferred to Phase 2. Renewals and reconnects use
   the current list (§1.4).
8. **`windows-arm64`:** a GitHub-hosted Arm runner, verified as in risk 6
   (§14).
9. **Tunnels:** owner-run (§4.3).
10. **SSH-enabled profiles:** loopback only, with nothing advertised
    (§3.4 step 4).
11. **Tailnet:** IPv4 addresses only, no MagicDNS (§2).
12. **`term` against an app-run profile:** out of 1b (§8).
13. **Start at login:** the existing entry, asked once (§10).
14. **Outer `wss`:** the platform verifier, a debug-only extra root for
    tests, and plain `ws` only on a tunnel's loopback hop (§4.2).

15. **Hosted result:** accepted as `hosted`, under the verification in
    risk 6.
16. **Pairback disclosure:** only private LAN literals by default. The
    joiner ticks any tailnet or public route to disclose, and the
    receiving owner still approves before dialling it (§1.3, §5.3).

Also settled: remote `pipe` over owner IPC, not `ssh -W` (§3.3); spaces,
chats and bots stay out of 1b (§9).

**Open questions**

None.

**Spike results (S1, S2)**

Run 2026-11-19; method and full numbers in `spikes/ssh-pipe/README.md`
and `spikes/route-policy/README.md`. The test server for E9 is
`spikes/ssh-pipe/src/sshd.rs` (`russh =0.65.2`).

S1, the pipe:

1. Constrained config: works with the system client on Windows
   (OpenSSH_for_Windows 9.5p2), macOS (10.3p1) and Linux (9.6p1), and PC to
   Mac over the LAN. Settles §3.1 as written.
2. Paths in the config: double quotes; a space and an apostrophe need
   nothing more; on Windows backslashes or forward slashes both work. `%`
   must be written `%%` (unescaped it fails, and `%d` silently reads the
   wrong file). The same applies to a `-o` value on the command line.
   Single quotes and bare paths fail.
3. Probe: `-N` with every auth method off writes one `mousse-<id>` line to
   the temporary file and exits 255 with `Permission denied (publickey).`
   The line's base64 is the key; its SHA256 matches the server on all
   three clients. The strict connect with that line passes; another key
   fails with `Host key for mousse-<id> has changed ...`.
4. Preamble: skipped, then 1 MiB of random bytes echoes back identical on
   every OS pair. A `.zshenv` that prints without a final newline puts the
   marker mid-line, so the client skips to the first `mousse-ssh/1\n`
   anywhere within `SSH_PREAMBLE_MAX_BYTES`, not only at a line start
   (§3.3, E9).
5. 150-byte socket path on macOS: absolute bind fails; bind and connect by
   the relative name after `chdir` work. Settles §3.3 "Long socket paths".
6. Killing the client: the remote child was gone within 15 ms (macOS),
   62 ms (Linux), 0.5 s (PC to Mac) and about 1 s (Windows).
7. Stderr for the reason mapping: `Permission denied (publickey).`
   (`auth_denied`); `REMOTE HOST IDENTIFICATION HAS CHANGED` / `Host key for
   <alias> has changed` (`host_key_changed`); `No <TYPE> host key is known
   for <alias>` (`host_key_unknown`); `connect to host <h> port <p>:
   Connection refused` (`unreachable`); `Connection timed out` and
   `Connection timed out during banner exchange` (`timeout`); exit 127 with
   `not found` (`remote_not_installed`). Windows `ssh.exe` with
   `ConnectTimeout` prints nothing for a refused port at `LogLevel=ERROR`,
   so exit 255 with empty stderr maps to `unreachable`.
8. Windows remotes: **no-go.** A key logon reaching a GUI-session pipe was
   not tested (an S4U task needs admin rights here; no `sshd` installed),
   nor `sshd`'s session teardown. The `cmd /c` form works only as
   `""<launcher>" <args>"` (a path with `&` or parentheses breaks the plain
   form). SSH add refuses Windows remotes with
   `windows_remote_unsupported` in 1b.

S2, route policy:

1. Resolve once: a `.invalid` name that the system cannot resolve dialled
   fine through rustls (SNI by name) and `client_async` on the TLS stream,
   with one lookup for two dials. The platform verifier refuses the test
   certificate without the extra root. Settles §1.2 and §4.2 as written.
2. Bounded search, `DIAL_PARALLEL` 4, `DIAL_TIMEOUT_MS` 2000: 16 dead
   candidates take 8.0 s on Windows (a refused loopback connect itself
   takes about 2 s there, so every try times out) and 4.0 s on Linux; a
   live 16th candidate wins at 6.1 s (Windows) and 2.0 s (Linux).
3. cloudflared quick tunnel, once: upgrade, `mousse.1`, binary frames and a
   65 536-byte message pass; upgrade at 735 ms cold and 97 ms warm; 1 KiB
   round trip 11 ms median. The tunnel adds no `Origin`.

Decisions: the §13.3 defaults hold (`TIER_HEAD_START_MS` 500,
`WS_DIAL_TIMEOUT_MS` 10000, `SSH_DIAL_TIMEOUT_MS` 20000,
`DIAL_FAST_TIERS_MS` 12000, `DIAL_SEARCH_MS` 45000); none changes. The
`WS_MESSAGE_MAX_BYTES` floor is 16 384, the largest message a writer sends
(§4.2), so the override range is 16 384 to 65 536, tighten only.
