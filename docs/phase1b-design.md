# Phase 1b design: user routes, the CLI and "Send link"

Status: design, for review (2026-11-18). Scope: PLAN "Phase 1b" (`tcp` to a
tailnet or port forward, `ssh-stdio`, `ws` through a user tunnel, the CLI
and remaining RPC, "Send link" with CPace).

- **Engine base:** `phase-1a` at `aba51a4`. Line references are against it.
- **App base:** Mousse `net-engine-1a` at `2aea454c6` (M6), plus M5b and M7
  when they land. 1b builds on 1a's §5 pairing, §7 UI and §9 kit.
- **One PR per repo.** The slices in §15 are commit series on `phase-1b`
  (engine) and `net-engine-1b` (app). Each repo's phase lands as one PR.

**Goal:** the 1a app checks pass over each route — `tcp` to a non-LAN
address, `ssh-stdio` and `ws` — with Plus unreachable. A computer can be
added over SSH or by a chat link and a typed code. Six desktop builds
exist and pass a smoke check.

CPace passed its Phase 0 review (`checks/reviews/phase0-design-review.md`,
part B), so "Send link" is in scope and its checks are not DEFERRED.

## Decisions

1. **A route is a pipe kind plus an address.** `tcp`, `ws`/`wss` and `ssh`
   each yield a `Pipe` (`pipe.rs:17`). TLS, step 2, the mux and every gate
   above them are unchanged. No route adds an authentication path of its
   own.
2. **Who may supply which route is fixed per source** (§1.3). A peer can
   never make this computer run `ssh`, so a peer can never spend the
   owner's SSH keys. Loopback is never dialled in release builds, whatever
   the source.
3. **Dial in tiers:** `tcp` first, then `ws` after a head start, then `ssh`
   only when both found nothing (§1.4). An SSH login is never raced against
   a LAN path.
4. **Adding over SSH is a send-link pairing carried over SSH** (§3.4). The
   remote Mousse makes a "Send link" invitation restricted to this
   computer's identity, and returns the ticket and code over the verified
   SSH session. The joiner submits the code itself. There is no new
   arrival kind and no wire change, and nobody needs to be at the remote
   computer.
5. **The remote end of `ssh-stdio` is the running helper,** reached through
   its owner-only local IPC by `mousse-helper pipe` (§3.3). The pipe never
   touches the keystore, which an SSH session often cannot unlock on
   Windows or macOS.
6. **SSH add pairs one way by default.** This computer gets a grant on the
   remote one. "Also let <B> use this computer" adds the 1a pairback (§3.6).
7. **The `ws` listener is loopback only,** for the user's own tunnel
   client. It refuses any request carrying `Origin`; browsers come in
   Phase 5.
8. **Send-link `join` never treats the host as pinned because of the app's
   journal** (§5.4). Wire rule 10.6.8 holds as written. Recovery after a
   lost `PAIRED` uses the file-backed joiner flow record.
9. **Pre-auth budget on every listener** (§6.2). Port forwards and tunnels
   expose the listener to the internet. Connections not yet live are
   capped per endpoint and per source address, under named limits.
10. **The CLI is `mousse-cli net-engine`** through the daemon's owner-only
    IPC, for profiles the app runs. Standalone `mousse-helper serve`
    (headless, no app) keeps its own CLI (§8). The two never drive the same
    endpoint.
11. **Mousse starts at login while any profile has networking on** (§10).
    This was deferred from 1a. Helpers still start after the daemon is
    ready.
12. **No hard-coded limits.** Every new timeout, cap, gap and size is a
    named default with a `MOUSSE_NET_*` (helper) or `MOUSSE_NET_ENGINE_*`
    (app) override, listed in §13.3. Peer-bound and security-bound ones
    only tighten.
13. **Plus has no role.** No 1b path contacts Plus. The route checks run
    with every Plus endpoint unreachable, and fail if anything tries (§14).

## 1. Routes

### 1.1 Kinds

| Kind | Hint form | Pipe | Where it lives |
|---|---|---|---|
| `tcp` | `tcp://<host>:<port>` (wire 10.2.1, unchanged) | `TcpStream` | tickets, peer routes, owner addresses |
| `ws`, `wss` | `wss://<host>[:<port>]<path>`, `ws://…` | `WsPipe` (§4) | tickets, peer routes, owner addresses |
| `ssh` | `ssh://[<user>@]<host>[:<port>]` | `SshPipe` (§3) | owner addresses only; never on the wire |

- **`ws` grammar:** the 10.2.1 host and port rules. The path is required,
  at most 200 bytes, ASCII `[A-Za-z0-9._~/-]`, and starts with `/`. There
  is no user part, query or fragment. The default port is 443 for `wss`
  and 80 for `ws`.
- **`ssh` grammar:** the 10.2.1 host rules, plus an optional user of 1 to
  64 bytes from `[A-Za-z0-9._-]`. `<host>` may be an `~/.ssh/config`
  alias, which counts as a DNS name. The per-route remote details (§3.3)
  are stored beside it in `peers.json`, not in the hint.
- **Spec:** wire.md 10.2.1 moves `ws` and `wss` from "reserved" to defined.
  `ssh` and `relay` stay reserved on the wire: a ticket's `ssh` hint is
  skipped. A 1a reader already skips `ws` and `wss` as reserved, so no
  version changes. `ticket.json` `route_hints` gains `ws` and `wss` cases,
  malformed ones included.
- **Core:** `Route` (`pairing/route.rs:35`) gains `Ws { tls, host, port,
  path }`. `Ssh` is a net-io type (`pipe::LocalRoute`), because core never
  sees it.

### 1.2 Address classes

`pipe::classify(ip)` replaces `is_private_ip` as the single classifier:

| Class | Ranges | UI label |
|---|---|---|
| `lan` | RFC 1918, IPv4 link-local, `fc00::/7` except the tailnet range | LAN |
| `tailnet` | `100.64.0.0/10`, `fd7a:115c:a1e0::/48` | Tailnet |
| `public` | other global unicast | Internet |
| `forbidden` | loopback, unspecified, multicast, broadcast, documentation ranges, IPv4-mapped forms of these | none |

A DNS name is classified when it is dialled. Each resolved address must not
be `forbidden`, otherwise the try fails with `forbidden_address`. A name
cannot smuggle in loopback. Debug builds allow loopback, as 1a E5a.1 does,
so tests stay on one computer.

### 1.3 Who may supply what

| Source | `tcp` lan/tailnet/public | `ws`/`wss` | `ssh` |
|---|---|---|---|
| Ticket hints | yes | yes | skipped (`reserved`) |
| Peer routes (pairback, §1.5 `routes`) | yes | yes | refused `bad_route` |
| Owner addresses (`peer.addresses.set`, CLI, SSH add) | yes | yes | yes |
| Browse (mDNS) | as 1a | none | none |

1a refused public and tailnet addresses from peers (1a §5.3). That rule
existed for scope, not for safety: the pin check runs on every route
(wire 5.4). The cost of accepting them is stated in §12. `phase1a.discovery`'s
`public-routes` control asserts the old rule, so E7 replaces it with
`loopback-routes` (a release build that dials loopback hints) and retitles
the check.

### 1.4 Dial order

`Caller::dial_candidates` (`caller.rs:508`) becomes tiered. Within a tier
the 1a order and parallel race are kept: last working route, owner
addresses, hints, then browse.

1. **`tcp`:** each try gets `DIAL_TIMEOUT_MS`.
2. **`ws`:** starts `TIER_HEAD_START_MS` after tier 1, or at once if tier 1
   has no candidates. Each try gets `WS_DIAL_TIMEOUT_MS`.
3. **`ssh`:** starts only when tiers 1 and 2 ended with no host. It tries
   one route at a time, with `SSH_DIAL_TIMEOUT_MS` each.

The first try to pass step 1 wins, as in 1a. A pin mismatch moves on, and
the host's own refusal stops the search.

Joins dial the same way. `peer::join_routes` (`peer.rs:274`) currently
dials `tcp` in sequence and becomes pipe-generic.

**Keep connected** (1a E5a.4) is unchanged, except that an SSH failure
named `auth_denied`, `host_key_changed` or `host_key_unknown` is not
retried (`retry_ms: null`) until the owner acts. Repeated denied logins
trip fail2ban and `ufw limit`.

**No upgrade while connected.** A path that came up over `ws` or `ssh`
stays until it drops or renews. Renewals and reconnects dial in tier order,
so the path improves at the next one (open question 7).

### 1.5 This computer's own routes

The helper builds its route list from `<state>/routes.json`, which
`routes.config` sets:

    { "lan": true, "public": ["tcp://203.0.113.7:7443"], "tunnels": ["wss://x.example/mousse-net/1"] }

- **LAN:** `lan: true` keeps 1a's `--listen-ip 0.0.0.0` and the interface
  hints (`serve.rs:64`). With `lan: false` the TCP listener binds
  `127.0.0.1` and mDNS is off. The listener rebinds on the same kept port
  without a restart.
- **Tailnet:** any interface address in the tailnet class becomes a `tcp`
  hint automatically. The 1a watcher (`watch.rs`) already polls
  interfaces, so tailnet up or down changes the list.
- **Public and tunnels:** taken as given, validated by §1.1 and §1.2.
- **On change,** the helper emits `routes.changed {routes}`. The app sends
  `routes {routes}` on every open `mousse.hello` stream where this side is
  the host. The receiving app calls `peer.routes.set {identity, routes}`,
  which replaces that peer's hints (refused per §1.3) and keeps its owner
  addresses. `{proto, name}` on `mousse.hello` gains `routes` too.
- **`routes.test {route}`:** the helper dials its own route, pinned to its
  own identity, and reports `{ok, ms}` once step 1 passes, or `{ok: false,
  reason}`. It closes before step 2, so it proves a port forward or tunnel
  reaches this endpoint.

## 2. `tcp` to a tailnet or port forward

The pipe needs no new code. What 1b adds:

- **Fixed port.** A port forward needs a stable port. The 1a kept port
  already is one (`serve --port`, `endpoint.rs:52`). Settings shows it, and
  "Use port N" sets it.
- **Exposure.** A port forward puts the listener on the internet. §6.2's
  budget applies, and the threat model and privacy doc say what a prober
  learns (§12).
- **Tailnet.** Tailscale's own ACLs sit outside Mousse. Mousse relies only
  on the pin and on step 2, as on a LAN. MagicDNS names are not used
  (open question 11).
- **No UPnP or NAT-PMP.** The owner sets the forward on the router.

## 3. `ssh-stdio`

### 3.1 The client

`SshPipe` (`mousse-net-io/src/pipe/ssh.rs`) runs the system OpenSSH
client: `ssh` on Unix, `%WINDIR%\System32\OpenSSH\ssh.exe` on Windows, or
`MOUSSE_NET_SSH_BIN` in debug builds. Its stdin and stdout are the pipe.
There is no Rust SSH client: the user's keys, agent, config and known hosts
work as they do in a terminal.

These ideas come from v1 (`transports/ssh.ts:157-205`, `ssh/hostKey.ts`);
none of its code is reused.

- **Fixed options:**
  `-T -o BatchMode=yes -o StrictHostKeyChecking=yes`,
  `-o UserKnownHostsFile="<state>/ssh_known_hosts ~/.ssh/known_hosts"`,
  `-o UpdateHostKeys=no -o CheckHostIP=no`,
  `-o ConnectTimeout=<SSH_CONNECT_TIMEOUT_SECS>`,
  `-o ServerAliveInterval=<SSH_ALIVE_INTERVAL_SECS> -o ServerAliveCountMax=<SSH_ALIVE_COUNT>`,
  `-o ControlMaster=no -o ControlPath=none`,
  `-o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no`,
  `-o LogLevel=ERROR`.
- **Environment:** `SSH_ASKPASS*` are stripped and no password is ever
  asked. On Windows the process gets `CREATE_NO_WINDOW`.
- **Resolution:** `ssh -G <target>` runs first, with
  `SSH_CONNECT_TIMEOUT_SECS`, to read the user, hostname, port and
  `proxyjump`/`proxycommand`. A target that needs either is refused with
  `ssh_proxy_unsupported` (open question 2).
- **Stderr** is kept up to `SSH_STDERR_MAX_BYTES` and mapped to a reason:
  `auth_denied`, `host_key_changed`, `host_key_unknown`, `unreachable`,
  `timeout`, `remote_not_running`, `remote_no_endpoint`, `remote_failed`.
  It is never forwarded raw to the UI.
- **Lifetime:** the child is killed when the pipe drops.
- **Spacing:** at most one spawn per target per `SSH_DIAL_GAP_MS`. That
  keeps renewals plus reconnects under `ufw limit`.

### 3.2 Host keys

- `ssh.probe {target}` runs `ssh -G`, then fetches the key with every
  authentication method off and `-N`. The key goes to a temporary known
  hosts file, never to the user's. The reply is `{user, hostname, port,
  key_type, sha256, known}`, where `known` means the key matches the user's
  or Mousse's file.
- If the key is not known, the dialog shows the SHA256 fingerprint. Trust
  calls `ssh.trust {target, key}`, which appends to
  `<state>/ssh_known_hosts`.
- From then on `StrictHostKeyChecking=yes` holds. A changed key fails with
  `host_key_changed`, and the row offers "Check and trust again".
- **Why it matters here:** peer TLS is pinned on every connection, so after
  pairing SSH only carries ciphertext. During setup (§3.4), though, the
  ticket and code travel over SSH, so the SSH host key is what authenticates
  the remote endpoint at first contact.

### 3.3 The remote end: `mousse-helper pipe`

- **Launchers.** On every start, after ready, the app writes stable
  launchers to `~/.mousse/bin/`. On Unix these are `mousse-helper` and
  `mousse-cli` as small `sh` scripts. On Windows they are `.cmd` files.
  Each points at the installed app's binaries, so an update never changes
  the SSH command.
- **Shell.** A first probe command prints a marker whose output differs
  under POSIX `sh`, `cmd.exe` and PowerShell. The route stores `shell: sh |
  cmd | powershell`. The command wrappers are:
  - `sh`: `exec /bin/sh -c '<cmd>'`, following v1's `shellQuote.ts:24`. A
    login shell like fish or zsh never parses it.
  - `cmd`: a quoted path.
  - `powershell`: `& '<path>'`.

  Paths and values never contain the shell's metacharacters (`'`, `"`,
  `%`, `$`, `` ` ``, `\` on `sh`). One that does is refused, not escaped.
  Secrets travel on stdin, never in argv.
- **Pipe.** The remote command is `<launcher> pipe --state <state dir>`.
  `pipe` reads `control.json` in that state directory, connects to the
  running helper's owner-only IPC (`ipc.rs`, unchanged security), and sends
  `{op: "pipe", token}`. After `{ok: true}` it splices stdin and stdout to
  the IPC stream. The helper hands the IPC stream to `host.accept`, tagged
  `route: ssh`. The handover takes at most `PIPE_CONNECT_WAIT_MS`.
- **Pipe errors.** Each is one line on stderr, `mousse-pipe: <reason>`, plus
  an exit code:
  - `not_running` (2): no helper for that state directory;
  - `no_endpoint` (3): the profile is gone or its networking is off;
  - `refused` (4).

  stdout carries only pipe bytes.
- **App mode IPC.** App mode binds the control listener again (E3.7 retired
  it), and it answers only `pipe` and `status`. Every other op answers "This
  profile is run by Mousse; use mousse-cli net-engine".
- **Why the running helper.** The pipe needs no key, so the keystore is
  never opened from an SSH session. Windows Credential Manager under a
  key-based SSH logon, and a locked macOS keychain, both fail there. The
  remote profile therefore answers only while its helper runs: the user is
  logged in and Mousse started (§10), or a standalone `serve` is running.
- **Rejected: `ssh -W 127.0.0.1:<port>`.** v1 used it. It needs
  `AllowTcpForwarding`, which hardened servers often turn off. It needs
  the remote's port. It would also bypass the per-profile state directory.

### 3.4 Adding a computer over SSH (A adds B)

1. **A, dialog "Add over SSH":** the owner enters `user@host` or an alias.
   The SSH user chooses the OS account on B. Then:
   - `ssh.probe`, and the host key is confirmed if it is not known;
   - the shell probe.
2. **A → B, `mousse-cli net-engine ssh`** (one JSON request on stdin, one
   reply on stdout; `SSH_SETUP_TIMEOUT_MS`), run through `ssh.run {target,
   request}`:
   - `{op: "profiles"}` → `{computer, profiles: [{id, label, networking,
     identity?}]}`. That is every profile of that OS account, whether or
     not it is paired elsewhere.
3. **A, the owner picks:**
   - an existing profile. One whose `identity` A already pairs with skips
     to step 6 and only adds the SSH route;
   - or "New profile" with a label.

   The list never filters out or refuses a profile because it belongs to
   another set of devices, as the PLAN requires.
4. **A → B:** `{op: "prepare", profile | new_label, joiner: <A identity>,
   joiner_name}`. B's daemon then:
   - creates the profile if asked;
   - turns networking on if it was off, with `lan: false` (reachable over
     SSH and tunnels only; open question 10);
   - waits for the helper;
   - calls `invite.create {kind: "link", expect: <A identity>}`.

   The reply is `{identity, name, ticket, code, state_dir, helper,
   expires_at}`, where `helper` is the launcher's absolute path.
5. **A:** writes the 1a consent journal row, then calls `join {ticket,
   arrival: "link", via: <ssh route with shell, helper, state_dir>, code}`.
   The helper dials through `SshPipe` and runs the send-link flow with the
   given code (§5). On success it stores the SSH route as an owner address.
6. **B:** the invitation's `expect` is host-local and not on the wire. A
   `JOIN_PROOF` from any other identity is answered as a wrong proof
   (`INVITATION_INVALID`, wire 10.3). A leaked ticket and code are
   therefore useless to anyone else.
7. **B's app** shows the new device in its list with a one-line notice,
   "Added over SSH from <A>".

**Ticket and code together.** The rule "the code reaches the joiner
independently of the link" (wire 10.6.2) protects links that travel over
untrusted channels. Here both come over one SSH session whose host key the
owner verified and whose login proves control of the account. That session
is the independent channel, and nothing passes through a link page.

### 3.5 Errors shown (one line each; details in the tooltip)

| Reason | Text |
|---|---|
| `auth_denied` | "SSH sign-in was refused. Mousse uses your SSH keys or agent, never a password." |
| `host_key_changed` | "<host>'s SSH key changed." Check and trust again |
| `remote_not_installed` (launcher missing) | "Mousse isn't installed for <user> on <host>." |
| `remote_not_running` | "Mousse isn't running for <user> on <host>. Sign in there once, or turn on Start at login." |
| `remote_no_endpoint` | "That profile is gone on <host>." |
| `ssh_proxy_unsupported` | "Jump hosts aren't supported yet." |

### 3.6 Direction

- **Default:** SSH add creates A's grant on B only. A's peer row gets
  `ways: "to_host"`. B's grant row reads "<A> uses this computer".
- **Both ways:** with "Also let <B> use this computer" checked, A runs 1a's
  `grant.add` and pairback after `PAIRED`, with A's routes as §1.3 allows.
- 1a §5.2's `connected` becomes "every direction this pairing has works".

### 3.7 Tests (no real sign-ins)

- **Test server:** `crates/mousse-helper/tests/common/sshd.rs`, an SSH
  server built on `russh`, pinned as a dev-dependency only.
  - It listens on `127.0.0.1` on the PC.
  - It accepts one generated client key and has one generated host key.
  - It runs only `mousse-helper pipe …`, `mousse-cli net-engine ssh` (the
    app checks) and the shell probe, as the current user, with a test
    home.
- **Real client:** each test runs the system `ssh` with
  `-F <test config>`, `IdentitiesOnly=yes` and the test key, so it never
  reads the user's agent, keys or config.
- **Shells:** Windows covers `cmd` and PowerShell through the test server's
  `shell` setting. Unix covers `sh`.
- **Cross-machine:** only the Mac listens on the LAN, running the same test
  server.

## 4. `ws` through a user tunnel

### 4.1 Listener (host)

- **Bind:** `127.0.0.1:<ws_port>`. The port is kept in the endpoint file
  like the TCP port (`--ws-port`). The listener is on while `routes.json`
  has a tunnel or `ws: true`. `hello` reports `ws_port`.
- **Upgrade checks,** in order, before any byte goes to TLS:
  1. method `GET`; headers at most `WS_HEADER_MAX_BYTES`;
  2. path ending in `/mousse-net/1`, else `404`;
  3. no `Origin` header, else `403`;
  4. `Sec-WebSocket-Protocol` offering `mousse.1`, which is selected, else
     `400`;
  5. the pre-auth budget (§6.2), else `503`.

  `Host` is not checked: tunnels rewrite it, and rebinding attacks come
  from browsers, which always send `Origin`.
- **After the upgrade:**
  - binary messages only; a text message closes with 1003;
  - at most 65 536 bytes per message, a fixed constant;
  - no permessage-deflate;
  - library pings are answered.

  `WsPipe` turns messages into the byte stream for `host.accept`, tagged
  `route: ws`.
- **Library:** `tokio-tungstenite`, pinned, `default-features = false`,
  with `handshake` on. The server uses `accept_hdr_async` with the checks
  above.

### 4.2 Client (caller)

- **Outer TLS (`wss`):** a separate rustls client with the platform
  verifier (`rustls-platform-verifier`, pinned), SNI equal to the URL's
  host, and ALPN `http/1.1`.
- **No proxies or redirects.** A redirect fails with `ws_redirect`.
- **Outer TLS is not a trust step.** It only gets through the tunnel. The
  pinned peer TLS runs inside, so a tunnel that terminates TLS sees
  metadata, never content.
- **`ws://`** (plain outer) is allowed for self-run proxies on a LAN or
  tailnet (open question 14).
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
  `ProcessSupervisor`, Serve records and undo. That is out (open question
  9).
- **A changed URL** (cloudflared quick tunnels change on every run) reaches
  connected peers through §1.5. A peer that was offline through the change
  needs the address again (§11).

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
  the host app renames the grant's display row. Privacy.md's "until a later
  minor" note is then met at the app level, after the confirmation.

### 5.2 Link form

- **Format:** `mousse://pair#<fragment>`. The app registers the `mousse`
  scheme: `setAsDefaultProtocolClient`, plus `open-url` and
  `second-instance` handling in `src/main/index.ts:185`.
- **Paste:** pasting the link, or the bare fragment, into "Enter link"
  works the same.
- **No page:** no web page sits in 1b's path (open question 5).

### 5.3 Joiner

1. A link opens "Enter link" with the ticket filled in. The app decodes it
   locally. A decode error shows "This link is damaged. Ask for a new
   one."
2. **Consent** (1a §5.1 step 2): "Connect to the computer in this link? It
   will also be able to use this computer." Connect writes the 1a
   `consented` journal row.
3. **Join:** `join {ticket, arrival: "link"}` with no `code`. The helper
   dials (§1.4), sends `JOIN_PROOF` and gets `join_only`. Then:
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
     tries left. Ask for a new link."
4. **Success:** as 1a `joined` → `granted` → pairback.

### 5.4 Journals, pins and wire rule 10.6.8

- **The rule.** `peer::join_routes` treats the host as pinned when
  `consented` is set (`peer.rs:285`). For a send link that would let a
  swapped link end "already paired", which wire 10.6.8 forbids.
- **Kind 2.** E10 ignores `pinned` for kind 2. The host counts as pinned
  only if `peers.json` held its pin before this flow.
- **Flow records.** App mode uses `FlowRecordStore` (`store.rs:749`) in
  `<state>/joins/`, instead of the in-memory one. The debit, the pending
  mark and the one-join-per-ticket hold then survive a crash, as wire 10.7
  requires.
- **App recovery for a `consented` send-link row:**
  - the helper holds the host's pin: go to `joined`;
  - the flow record is pending: repeat `join`. The helper reconnects to
    learn the outcome (10.6.7), even after expiry;
  - otherwise: "Pairing didn't finish", with Retry while the ticket is
    valid and Remove.

### 5.5 Tampered links (what each change does)

| Change | Result |
|---|---|
| bad base64 or CBOR | refused before dialling (`encoding`, `cbor`, `field`) |
| kind 2 → 1 | refused before dialling: kind 1 needs an in-app scan (`PAIRING_FAILED`) |
| secret or invitation id | host closes with `INVITATION_INVALID`; no attempt spent |
| host key | no address answers as that key, or a fake host does. The fake host's code exchange fails with the swapped-link text, and the real invitation is untouched |
| a route hint | the ticket hash differs, so CPace fails: `PAIRING_FAILED`, one attempt spent on each side |

## 6. Traffic that must never reach RPC

### 6.1 Layers (unchanged, now on every route)

| Layer | Stops |
|---|---|
| `ws` upgrade checks (§4.1) | non-WebSocket requests, browsers, wrong path or protocol |
| `pipe` IPC (§3.3) | other OS users (the OS); the same user without the token |
| TLS step 1 (wire 5.4) | no certificate, wrong version or ALPN, bad certificate |
| Step 2 and the host gate (wire 8, 8.1) | any stream before a live grant; a join-only connection opening streams |
| Helper labels (1a §2.3) | streams outside the §3.2 labels plus `mousse.tunnel` (§9) |
| `authorizeEngine` (1a §4.3) | methods outside the allowlist; removed, blocked or `removing` rows |

### 6.2 Pre-auth budget

- **What counts:** from accept until the connection is live or closed, on
  each listener:
  - `PREAUTH_CONNECTIONS` per endpoint, for all listeners and the pipe
    together;
  - `PREAUTH_PER_SOURCE` per remote IP, for TCP only. `ws` and pipe
    connections all arrive from loopback.
- **Over the limit:** TCP is closed at accept, `ws` gets `503`, and `pipe`
  gets `refused`.
- **Join-only connections count** until enrollment. The 10 s
  `JOIN_PROOF_WAIT_MS` and the handshake timeout bound each slot.
- **`stats`** gains `preauth_open` and `preauth_refused`.
- **Not a promise against denial of service.** The threat model says a
  flood can delay the owner's own reconnects.

### 6.3 The route probe

`mousse-check probe --route <hint> --pin <host identity> --invite
<ticket>` links `mousse-net-io` and sends each of the following, expecting
the named close:

1. Bytes that are not TLS → TLS failure.
2. For `ws` only:
   - plain `GET` → `404`;
   - wrong path → `404`;
   - with `Origin` → `403`;
   - no subprotocol → `400`;
   - a text message after the upgrade → close 1003.
3. TLS:
   - without a client certificate → handshake failure;
   - TLS 1.2 only → handshake failure;
   - wrong ALPN → handshake failure.
4. A fresh identity:
   - immediate `OPEN mousse.rpc` → `NOT_AUTHORIZED`;
   - silence → `NOT_AUTHORIZED` after `JOIN_PROOF_WAIT_MS`;
   - a bad `JOIN_PROOF` → `INVITATION_INVALID`.
5. A valid `JOIN_PROOF` → `join_only`, then:
   - `OPEN mousse.rpc` → `NOT_AUTHORIZED`;
   - `OPEN mousse.hello` → `NOT_AUTHORIZED`;
   - a garbage `CODE_EXCHANGE` → `CODE_ABORT PAIRING_FAILED`, with one
     host attempt spent.
6. Identities:
   - a removed identity, `OPEN mousse.rpc` → `NOT_AUTHORIZED`;
   - a denied identity → `NOT_AUTHORIZED`.
7. For `ssh` only, `pipe`:
   - a wrong token → `refused`;
   - a stopped helper → `not_running`.

The app check then asserts, from the host's `stats` and the daemon's
dispatcher counter:

- no stream from a probe connection reached the app;
- no engine call was authorized;
- no ledger row was written.

## 7. App ↔ helper protocol 1.1

These are additions only. A 1.1 helper serves a 1.0 app (1a messages
only). The app needs 1.1 for anything in 1b.

- **Session:** the `hello` reply adds `ws_port` and `routes_config`.
- **Routes:**
  - `routes.config {lan?, public?, tunnels?, ws?}` → `{routes}`;
  - `routes.test {route}` → `{ok, ms?, reason?}`;
  - event `routes.changed {routes}`;
  - `peer.routes.set {identity, routes}`.
  - `peer.addresses.set` takes every §1.3 owner kind. `ssh` entries carry
    `{shell, helper, state_dir}`.
- **Connections:** `conn.up` adds `route {kind: tcp|ws|ssh, class:
  lan|tailnet|public|tunnel|ssh}`.
- **Send link:**
  - `invite.create {kind: "in_person"|"link", expect?}`;
  - event `invite.code {invitation, code, attempts_left}`;
  - `invite.ended` reasons gain `attempts_exhausted`.
  - `join {ticket, arrival: "scan"|"link", via?, code?, pinned?}`.
    `arrival` replaces 1a's fixed in-app scan; kind 1 needs `scan`, and
    `pinned` is ignored for kind 2 (§5.4). `via` is an SSH route; `code`
    is used once, for the SSH add.
  - `join.code {invitation, code}`;
  - events `join.code_needed {invitation, attempts_left}` and
    `join.attempt_failed {invitation, attempts_left}`;
  - join errors gain `attempts_exhausted`, `pairing_failed`,
    `invitation_invalid`, `bad_code` and `forbidden_address`.
- **SSH:**
  - `ssh.probe {target}` → `{user, hostname, port, key_type, sha256,
    known}`;
  - `ssh.trust {target, key}`;
  - `ssh.run {target, request}` → `{reply}` or `{error, reason}`.
- **Denials** (1a listed deny lists as not in 1.0):
  - `grant.remove {grant, deny?}`, journaled as 1a §5.4;
  - `denials.list`;
  - `deny.remove {identity}`.
- **Debug only:** `stats` adds the §6.2 counters and per-connection
  `app_streams`.

## 8. The CLI

| Where | Command | Through |
|---|---|---|
| A profile Mousse runs | `mousse-cli net-engine status`, `devices`, `invite [--link]`, `join <link>`, `remove <device> [--deny]`, `addresses <device> <route>…`, `routes [--lan on\|off] [--public h:p] [--tunnel url] [--test]`, `ssh add <target> [--profile id\|--new label] [--both-ways]` | the daemon's owner-only IPC (`src/cli/daemonClient.ts:66`), the same service methods as the UI, journals included |
| The same, run over SSH | `mousse-cli net-engine ssh` (§3.4) | the same |
| A standalone `serve` (headless, no app) | `mousse-helper invite [--link]`, `join`, `peers`, `grants`, `remove`, `term`, plus new `serve --ws-port N --public h:p --tunnel url --no-lan` and `routes test` | `ipc.rs` |
| Either | `mousse-helper pipe --state <dir>` | `ipc.rs` |

- **Typing the code.** `join` reads the code from the terminal, never from
  argv or a pipe. That is the "installed app" of wire 10.6.2. Without a
  terminal it refuses with `no_tty`.
- **`term`** stays standalone-only. App-mode terminals are daemon PTYs
  reached through the picker (open question 12).
- **Local only.** `mousse-cli net-engine` adds no network surface; it is a
  local method client. Its methods join `NET_ENGINE_LOCAL_METHODS`
  (`shared/netEngine/local.ts`).

## 9. Remaining RPC

1a's `ENGINE_OWNER_METHODS` (`shared/netEngine/allowlist.ts:9`) leaves out
the groups below. 1b adds the first four. Spaces, chats and bots wait for
Teams membership (1a §4.6).

| Group | Methods | What it needs over the engine |
|---|---|---|
| Editor | `routed.editor.folder`, `routed.editor.ask` (`accessClasses.ts:201-203`) | the editor tunnel below |
| Editor tunnel | local `net.editor.tunnel.open/read/write/end/close`, kinds `ssh`, `ssh.check` (`shared/net/tunnel.ts`), driven by `mousse-cli net ssh-proxy` | new label `mousse.tunnel` (interactive, caller-opened). The header is `{kind}`. The host checks `editor` access with `checkNodePolicy` and splices to `127.0.0.1:22`. The local side picks the engine branch for engine ids. |
| Access | `bridge.access.mine` (`view`) | allowlist only |
| Chat dispatch | `bridge.dispatch` (`work`), sent through `BridgeHub.prepare` (`ChatTaskDispatchService.ts:58`) | allowlist, plus `prepare` on the Hub's engine branch |
| Hub local methods | the 21 `bridge.hub.*` (`bridge/hub/local.ts:71-97`), `not_supported` for engine ids (`hub/service.ts:272`) | the engine branch from 1a M4 behind each one, with no v1 fallthrough |
| Not in 1b | `bridge.thread.open`, `bridge.lists.open` (v1 Bridge views; M13 checks whether anything still calls them); `spaces.*`, `chats.send/cancel`, `bots.*` (Teams); the phone API names (Phase 2); `net.direct.*`, `authority.transfer.*` (v1 only) | |

The helper's inbound label list (`app/mod.rs` `LABELS`) gains
`mousse.tunnel`.

## 10. Start at login

- **When:** while any profile has networking on, the app registers the
  daemon to start at login, headless, through the existing `mms/startup/`.
  - Windows: Task Scheduler `ONLOGON`, with the `Run` key as fallback.
  - macOS: a LaunchAgent.
  - Linux: a systemd user unit.
- **Setting:** "Start at login", default on while networking is on. It
  lives beside the networking switch. When the last switch turns off, the
  registration is removed, unless the user set `mms.autostart` on their
  own.
- **Startup speed:** the daemon reports ready first. `startNetworkedProfiles`
  then runs in the background, as in 1a §1. No 1b work runs before ready:
  - launchers (§3.3) and route detection run after ready;
  - the keystore unlock waits for the helper.
- **Without a login:** a profile still is not reachable with nobody logged
  in. That waits for the headless daemon (PLAN §8).

## 11. Situations

| Situation | Behaviour |
|---|---|
| Tailnet goes down | Its `tcp` hints drop from this computer's routes (`routes.changed`). Callers fall to the next tier. |
| Quick tunnel URL changes | Connected peers get the new route on `mousse.hello`. A peer that was offline needs Add address, or an SSH or LAN path. |
| Port forward behind CGNAT | `routes.test` fails, and the row says "Not reachable from the internet". |
| SSH key needs a passphrase and the daemon has no agent | `auth_denied`. The tooltip suggests the agent or a key file. The daemon inherits `SSH_AUTH_SOCK` from the app when the app starts it (risk 3). |
| Remote Mousse updated | The launcher path is stable, so nothing changes. |
| Remote profile removed, or networking off | `remote_no_endpoint`. The row reads "That profile is gone on <host>", with Remove. |
| Remote user logged out | `remote_not_running`, retried with backoff. Login start on B covers reboots. |
| SSH host key rotated | `host_key_changed`, not retried until "Check and trust again". |
| Path came up over SSH, LAN returns | The path stays on SSH until it renews or drops (open question 7). |
| Two profiles on B, A adds one over SSH | Only that endpoint's state directory is used. The other profile is untouched, and either may be paired elsewhere. |
| Send link opened twice, or in two windows | The flow-record hold refuses the second (`busy`). Attempts are shared through the record. |
| App killed mid-code | The debit is already stored. Reopening the link resumes with the attempts left, or learns the outcome. |
| Wrong clock | 1a's neutral message, on every route. |

## 12. Threat model and privacy updates

- **threat-model.md**, new "Routes beyond the LAN" section:
  - internet-exposed listeners (port forward, tunnel) and the pre-auth
    budget, which is not denial-of-service protection;
  - every route ends at the same pin check and step 2;
  - a peer can never make a device run SSH;
  - SSH setup's trust is the verified SSH host key plus the login;
  - the `ws` listener refuses browsers;
  - a loopback route is never dialled in release.
  - It also records the cost of §1.3: a tampered ticket or peer route can
    make a joiner dial a public address it names, which reveals the
    joiner's IP. It cannot pass step 1.
- **privacy.md:**
  - a port forward or tunnel lets any internet prober learn the host's
    identity key (already true on a LAN, now global);
  - the tunnel provider sees both IPs, timing, sizes and the WebSocket
    path, never content;
  - the tailnet coordinator sees that two nodes talk;
  - `routes` sent on `mousse.hello` reveal this computer's addresses to its
    paired peers only.
- **wire.md 10.2.1:** the `ws`/`wss` grammar (§1.1).
- **limits.md:** the §13.3 rows.

## 13. Files

### 13.1 Engine

- `mousse-net-core/src/pairing/route.rs`: the `Ws` route, grammar and
  vectors.
- `mousse-net-io/src/pipe.rs` becomes `pipe/{mod,tcp,ws,ssh}.rs`, with
  `classify`, `LocalRoute` and tiered candidates.
- `caller.rs`: the tiered race.
- `host.rs`: the pre-auth budget.
- `store.rs`: SSH route details in `PeerRecord`.
- `mousse-helper`:
  - `serve.rs`: the `ws` listener, `--ws-port`, `--public`, `--tunnel` and
    `--no-lan`, listener rebind, and the app-mode IPC listener (pipe and
    status);
  - new `pipe.rs` (the remote `pipe` command);
  - new `ssh.rs` (probe, trust, run);
  - `app/pairing.rs`: link invitations, `expect`, `join` arrival and code;
  - `app/paths.rs`: routes config, `peer.routes.set`, the §1.3 source
    policy;
  - `peer.rs`: pipe-generic joins, and kind 2 ignoring `pinned`.
- `mousse-check`: `probe`, the Plus stand-in, `--route` in
  `tools/app-check/run.mjs`, and `checks/phase1b.toml`.
- `spec/wire.md`, `spec/threat-model.md`, `spec/privacy.md`,
  `docs/limits.md`.

### 13.2 Mousse

- `src/mms/netEngine/`:
  - `pairing.ts`: link host and joiner, SSH add, journal recovery for kind
    2;
  - `NetEngineService.ts`: routes settings, `routes` on hello, launchers,
    login start;
  - `helper/appChannel.ts`: protocol 1.1;
  - new `ssh.ts`: the remote `net-engine ssh` handler.
- `src/shared/netEngine/allowlist.ts` and `local.ts`.
- `src/cli/commands/netEngine.ts`.
- `src/main/index.ts`: the `mousse://` scheme.
- `src/mms/startup/*`: registration while networking is on.
- Hub:
  - `bridge/hub/service.ts`: the local methods' engine branch and
    `prepare`;
  - `net/editor/*`: the engine branch of the editor tunnel.
- Renderer: `components/netEngine/`:
  - `AddDeviceDialog`: Send link, Enter link and Over SSH tabs;
  - `ReachSection`: LAN, Tailnet, Port forward and Tunnel, each with
    Test;
  - row route labels.

### 13.3 New limits

| Variable | Default | Allowed | What it limits |
|---|---|---|---|
| `MOUSSE_NET_PREAUTH_CONNECTIONS` | 64 | 1 to 4096 | Connections not yet live, per endpoint, all listeners and pipes |
| `MOUSSE_NET_PREAUTH_PER_SOURCE` | 8 | 1 to 1024 | The same per remote IP (TCP) |
| `MOUSSE_NET_TIER_HEAD_START_MS` | 500 | 0 to 10000 | Wait before `ws` candidates start |
| `MOUSSE_NET_WS_DIAL_TIMEOUT_MS` | 10000 | 500 to 60000 | One `ws` try: connect, outer TLS, upgrade, step 1 |
| `MOUSSE_NET_WS_HEADER_MAX_BYTES` | 8192 | 1024 to 65536 | Upgrade request headers |
| `MOUSSE_NET_SSH_DIAL_TIMEOUT_MS` | 20000 | 1000 to 120000 | One `ssh` try: login, remote `pipe`, step 1 |
| `MOUSSE_NET_SSH_CONNECT_TIMEOUT_SECS` | 10 | 1 to 120 | `ConnectTimeout` |
| `MOUSSE_NET_SSH_ALIVE_INTERVAL_SECS` | 15 | 1 to 300 | `ServerAliveInterval` |
| `MOUSSE_NET_SSH_ALIVE_COUNT` | 3 | 1 to 20 | `ServerAliveCountMax` |
| `MOUSSE_NET_SSH_DIAL_GAP_MS` | 6000 | 0 to 600000 | Least time between `ssh` spawns to one target |
| `MOUSSE_NET_SSH_SETUP_TIMEOUT_MS` | 60000 | 1000 to 600000 | One `ssh.run` or `ssh.probe` |
| `MOUSSE_NET_SSH_STDERR_MAX_BYTES` | 16384 | 1024 to 1048576 | `ssh` stderr kept for the reason |
| `MOUSSE_NET_PIPE_CONNECT_WAIT_MS` | 2000 | 100 to 60000 | Remote `pipe`: reach the helper's IPC and get `ok` |
| `MOUSSE_NET_ENGINE_SSH_REQUEST_DEADLINE_MS` (app) | 120000 | 1000 to 600000 | App deadline for `ssh.*` and an SSH join |

Fixed on purpose: the 65 536-byte `ws` message maximum, the `/mousse-net/1`
path suffix, the `mousse.1` subprotocol, and the pipe error codes.

## 14. Owner checks: `checks/phase1b.toml`

- **Build binding.** As in 1a §9. `app/MOUSSE_REVISION` moves to the
  `net-engine-1b` tip when E11 lands.
- **Routes in app checks.** `run.mjs --route tcp|ws|ssh`:
  - `tcp` uses a non-LAN address class: debug loopback, labelled
    `public`, on the PC;
  - `ws` uses a local TLS-terminating tunnel stand-in with a test root;
  - `ssh` uses §3.7's server.
- **Plus unreachable.** Every app check points the app's Plus endpoints at
  a stand-in on a closed loopback port that records attempts. Any attempt
  fails the run with `plus_contacted`.
- **Topology.** The PC listens only on loopback. Cross-machine cells have
  the Mac listen (TCP, the test SSH server, the tunnel stand-in), and the
  PC dials.

```toml
phase = "phase1b"
title = "User routes, CLI and Send link"
plan = "docs/PLAN.md#phase-1b-user-routes-cli-and-send-link"

[[check]]
id = "phase1b.routes"
title = "Route grammar and classes; source policy (no peer ssh, no release loopback); tiered dial; own routes and routes.test"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 16
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_routes", "--no-fail-fast"] },
]
control = [
  { name = "peer-ssh-routes", breaks = "a peer's routes may name ssh targets", env = { RUSTFLAGS = '--cfg mousse_control="peer-ssh-routes"' } },
  { name = "loopback-routes", breaks = "a release-policy build dials loopback hints", env = { RUSTFLAGS = '--cfg mousse_control="loopback-routes"' } },
  { name = "ssh-races-lan", breaks = "ssh candidates start with tcp ones", env = { RUSTFLAGS = '--cfg mousse_control="ssh-races-lan"' } },
]

[[check]]
id = "phase1b.ssh"
title = "ssh-stdio through the system client and a local test server: strict host keys, pipe to the running helper, sh/cmd/PowerShell, expect-restricted invitations"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 12
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ssh", "--no-fail-fast"] },
]
control = [
  { name = "accept-new-host-key", breaks = "ssh runs with StrictHostKeyChecking=accept-new", env = { RUSTFLAGS = '--cfg mousse_control="accept-new-host-key"' } },
  { name = "expect-ignored", breaks = "an expect-restricted invitation enrolls any identity", env = { RUSTFLAGS = '--cfg mousse_control="expect-ignored"' } },
  { name = "pipe-no-token", breaks = "the IPC hands over a pipe without the token", env = { RUSTFLAGS = '--cfg mousse_control="pipe-no-token"' } },
]

[[check]]
id = "phase1b.ws"
title = "Loopback ws listener refuses non-upgrade, wrong path, Origin, missing subprotocol and text frames; wss client through a TLS-terminating stand-in"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 10
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_ws", "--no-fail-fast"] },
]
control = [
  { name = "ws-allow-origin", breaks = "the ws listener accepts requests with Origin", env = { RUSTFLAGS = '--cfg mousse_control="ws-allow-origin"' } },
]

[[check]]
id = "phase1b.send-link"
title = "Pair by link and code; every tampered field fails as §5.5; three wrong codes end the invitation on the host and the flow on the joiner, across a joiner restart; a swapped link never ends already-paired"
targets = ["windows-x64", "macos-arm64", "linux-x64"]
min_tests = 14
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
  { target = "macos-arm64", host = "macos-aarch64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["cargo", "test", "-p", "mousse-helper", "--test", "app_link", "--no-fail-fast"] },
]
control = [
  { name = "journal-pins-link", breaks = "a consented send-link join counts the ticket's host as pinned", env = { RUSTFLAGS = '--cfg mousse_control="journal-pins-link"' } },
  { name = "joiner-records-in-memory", breaks = "app mode keeps joiner flow records in memory, so a restart resets attempts", env = { RUSTFLAGS = '--cfg mousse_control="joiner-records-in-memory"' } },
  { name = "same-code-after-failure", breaks = "the host keeps showing the failed attempt's code", env = { RUSTFLAGS = '--cfg mousse_control="same-code-after-failure"' } },
]

[[check]]
id = "phase1b.no-rpc-without-grant"
title = "The §6.3 probe on every route (tcp, ws, ssh): each probe gets its close, no probe stream reaches the app, no engine call is authorized"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.no-rpc-without-grant", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.no-rpc-without-grant", "--out", "{out}"] },
]
control = [
  { name = "admit-ungranted", expect_reason = "probe_reached_app", breaks = "the host gate treats an identity awaiting a proof as live", env = { RUSTFLAGS = '--cfg mousse_control="admit-ungranted"' } },
  { name = "join-only-streams", expect_reason = "probe_reached_app", breaks = "a join-only connection may open streams", env = { RUSTFLAGS = '--cfg mousse_control="join-only-streams"' } },
]

[[check]]
id = "phase1b.routes-app"
title = "picker-v1-off, once-or-unknown, removal, reconnect and path-switch over tcp (non-LAN), ws and ssh, with Plus unreachable"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.routes-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.routes-app", "--out", "{out}"] },
]
control = [
  { name = "plus-probe", expect_reason = "plus_contacted", breaks = "route setup asks Plus for anything", env = { MOUSSE_NET_ENGINE_CONTROL = "plus-probe" } },
  { name = "lan-only-candidates", expect_reason = "unreachable", breaks = "the app passes only LAN addresses to the helper", env = { MOUSSE_NET_ENGINE_CONTROL = "lan-only-candidates" } },
]

[[check]]
id = "phase1b.link-app"
title = "Link pairing through the daemon's methods: consent, code, Connected both ways; three wrong codes end both dialogs; an app restart mid-code keeps the count; a tampered link is refused"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.link-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.link-app", "--out", "{out}"] },
]
control = [
  { name = "link-pinned-journal", expect_reason = "swapped_link_trusted", breaks = "the app passes pinned for send-link joins and the helper honours it", env = { MOUSSE_NET_ENGINE_CONTROL = "link-pinned-journal", RUSTFLAGS = '--cfg mousse_control="journal-pins-link"' } },
]

[[check]]
id = "phase1b.ssh-add-app"
title = "Add over SSH (test server, second Mousse home): pick an existing profile, a profile paired elsewhere, and a new one; never refused; one-way by default, both ways when asked"
targets = ["windows-x64", "linux-x64"]
judge = "marker"
app = true
local = [
  { target = "windows-x64", host = "windows-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.ssh-add-app", "--out", "{out}"] },
  { target = "linux-x64", host = "linux-x86_64", command = ["node", "{root}/tools/app-check/run.mjs", "phase1b.ssh-add-app", "--out", "{out}"] },
]
control = [
  { name = "refuse-if-paired", expect_reason = "refused_paired_profile", breaks = "SSH setup hides or refuses a profile paired elsewhere", env = { MOUSSE_NET_ENGINE_CONTROL = "refuse-if-paired" } },
]

[[check]]
id = "phase1b.routes-cross"
title = "PC dials the Mac over tcp (tailnet if both have one, else a LAN port forward stand-in), ws (tunnel stand-in on the Mac) and ssh (test server on the Mac), Plus unreachable; terminal and remote thread work on each"
targets = ["pc-to-mac-lan"]
judge = "marker"
cross_machine = true
app = true
device_steps = "As phase1a.pair-offline, with phase1b.routes-cross and --route tcp|ws|ssh on both run.mjs commands; the Mac runs --role host."
control = [
  { name = "plus-probe", expect_reason = "plus_contacted", breaks = "route setup asks Plus for anything", env = { MOUSSE_NET_ENGINE_CONTROL = "plus-probe" } },
]

[[check]]
id = "phase1b.desktop-builds"
title = "Release helper and packaged app for six targets: --version names the build; standalone serve pairs by link over tcp and ws on loopback"
targets = ["windows-x64", "windows-arm64", "macos-arm64", "macos-x64", "linux-x64", "linux-arm64"]
# One local entry per target running tools/build-smoke.mjs; macos-x64 under Rosetta, linux-arm64 in a container on the Mac. windows-arm64: open question 8.
control = [
  { name = "stale-helper", breaks = "the packaged helper is not the build under test", env = { MOUSSE_BUILD_ID = "0000000+release" } },
]

[[check]]
id = "phase1b.pair-by-chat-link"
title = "Mac: Send link; paste into a chat; PC opens it, types the code, connected both ways. A second link with one character changed fails."
targets = ["pc-to-mac-lan"]
manual = true
steps = "Attest with both app and helper builds."

[[check]]
id = "phase1b.login-start"
title = "Reboot the Mac, log in without opening Mousse: the PC's row reads Connected within 30 s"
targets = ["pc-to-mac-lan"]
manual = true
steps = "Attest with both app and helper builds."
```

## 15. Work breakdown

E = engine repo (`phase-1b`), M = Mousse (`net-engine-1b`).

| # | Repo | What | Proved by |
|---|---|---|---|
| S1 | E | **Spike.** Before E9: the system `ssh` against the `russh` test server on all three OSes, with `cmd` and PowerShell shells on Windows. A Windows OpenSSH key logon reaching a GUI-session helper's named pipe (the IPC ACL holds across logon sessions). A real `cloudflared` quick tunnel to a loopback `ws` listener on the Mac (Plus blocked). | go or no-go for §3.3 and §4; results recorded in §16 |
| E7 | E | Route kinds and the `ws` grammar (spec and vectors); `classify`; the §1.3 policy, including the `phase1a.discovery` control swap; tiered dial; pipe-generic joins; `routes.json`, tailnet detection, `routes.changed`, `peer.routes.set`, `routes.test`; the pre-auth budget | `phase1b.routes`; `ticket.json` vectors; `phase1a.discovery` with `loopback-routes` |
| E8 | E | `WsPipe` client and server, the loopback listener, `--ws-port`, `--tunnel`; the tunnel stand-in for tests | `phase1b.ws` |
| E9 | E | `SshPipe`; `ssh.probe`, `ssh.trust`, `ssh.run`; the remote `pipe` command; the app-mode IPC listener (pipe and status); `expect` invitations; the `russh` test server | `phase1b.ssh` |
| E10 | E | Send link in app mode: `invite.create {kind: link}`, `invite.code`, `join` arrival and code, the code channel, `FlowRecordStore` in app mode, kind 2 ignoring `pinned`; `grant.remove {deny}`, `denials.list`, `deny.remove`; protocol 1.1 | `phase1b.send-link`; Phase 0 `pairing_e2e` unchanged |
| E11 | E | Kit: `mousse-check probe`, the Plus stand-in, `run.mjs --route`, `tools/build-smoke.mjs`, `checks/phase1b.toml`; spec, threat model, privacy and limits docs | kit self-tests; every control prints FAIL |
| M8 | M | Protocol 1.1 client; routes settings (`ReachSection`), `routes` on hello, owner addresses for every kind, route labels on rows | unit tests; `phase1b.routes-app` over `tcp` |
| M9 | M | Send link: host tab, Enter link, `mousse://` scheme, code entry, the journal for kind 2 | `phase1b.link-app`; component tests; real-app captures |
| M10 | M | SSH add: dialog, host key confirmation, profile choice; `mousse-cli net-engine ssh`; launchers; `lan: false` for profiles turned on over SSH; one-way rows | `phase1b.ssh-add-app`; `phase1b.routes-app` over `ssh` |
| M11 | M | Tunnel UI and `routes.test` | `phase1b.routes-app` over `ws` |
| M12 | M | `mousse-cli net-engine` | CLI tests through the daemon's local methods |
| M13 | M | Remaining RPC (§9): editor rows and `mousse.tunnel`, `bridge.access.mine`, `bridge.dispatch` with Hub `prepare`, the Hub local methods' engine branch | allowlist test; editor tunnel over an engine session; Hub tests with v1 unchanged; `phase1b.no-rpc-without-grant` |
| M14 | M | Start at login; six-target packaging | startup tests; `phase1b.desktop-builds`; `phase1b.login-start` (attested) |

**Order:**

1. S1.
2. E7.
3. E8, E9 and E10 in parallel.
4. E11.
5. M8 to M14, with M8 first and M13 independent of the route slices.
6. `phase1b.routes-cross` and the attested checks last.

## 16. Risks, settled questions and open questions

**Risks**

1. **Windows as an SSH remote.** The shell differs (`cmd` or PowerShell),
   the launcher is `.cmd`, and the named pipe must be reachable from a
   network logon. v1 never supported it. S1 decides. If it fails, Windows
   remotes are refused with a clear message in 1b.
2. **Internet exposure.** Port forwards and tunnels put the listener on
   the internet. Security still rests on the pin and step 2, which every
   route shares and Phase 0 vectors cover. Denial of service is not
   defended, and §12 says so.
3. **No agent in the daemon.** A daemon started at login, by launchd or
   systemd, may lack `SSH_AUTH_SOCK`. v1 hit this. A passphrase-protected
   key then fails with `auth_denied` and a tooltip.
4. **Quick tunnels change URLs.** Peers that were offline lose the route.
   The UI recommends a named tunnel or Funnel for lasting use.
5. **`windows-arm64` has no test machine** (open question 8).
6. **1a slices still open in the app** (M5b, M7). 1b's M slices build on
   them, so 1b's app branch starts after they land.

**Settled here**

1. **SSH setup uses a send-link invitation.** It needs no wire change and
   no new arrival kind (decision 4).
2. **Remote `pipe` over owner IPC,** not `ssh -W` (§3.3).
3. **Send-link joins never treat the host as pinned because of the
   journal** (§5.4).
4. **Spaces, chats and bots stay out of 1b** (§9).

**Open questions for the reviewers**

1. **SSH add direction.** One-way by default, with an opt-in for both ways
   (§3.6). Or keep 1a's two-way rule and show the reverse direction failing
   when B cannot reach A?
2. **ProxyJump and ProxyCommand.** Refused as in v1 (§3.1). Or allowed,
   accepting that the jump hop uses the user's own options and known
   hosts?
3. **Peer-supplied public addresses and DNS names** in tickets and hello
   routes (§1.3). Is the joiner-IP exposure to a tampered link acceptable?
   The pin still stops everything else.
4. **`expect` on SSH invitations** is host-local and answers as a wrong
   proof. Should it also be on the wire, for example a ticket field, so a
   standalone host could honour it?
5. **Link form.** `mousse://pair#…` only in 1b. Or also an
   `https://…/pair#…` handoff page now? Chat apps linkify https far more
   reliably, but it needs a static origin. The Phase 5 web-client origin
   could serve it later.
6. **Mousse not running on the remote.** Fail with
   `remote_not_running`/`remote_not_installed` (§3.5). Or start the daemon
   from the SSH session? That cannot unlock the keystore on macOS or
   Windows. Or install it, as v1 did on Linux?
7. **Upgrading the path while connected** (SSH or `ws` to LAN, on an
   interface change). Deferred to Phase 2's network-switch work, or added
   now with the path switch?
8. **`windows-arm64`.** A GitHub-hosted Arm runner for the build smoke, or
   accept INCOMPLETE for that one cell?
9. **Tunnels.** Owner-run only (§4.3). Or should Mousse manage `tailscale
   serve`/`funnel` or `cloudflared`, as v1 did?
10. **`lan: false`** for profiles turned on over SSH (§3.4 step 4). Is that
    the right default for a VPS, given that the owner can turn LAN on later?
11. **Tailnet MagicDNS names** as hints, which needs the `tailscale` CLI,
    or IP addresses only?
12. **`term` against an app-run profile** from `mousse-helper`. Out of 1b,
    or a `mousse-cli net-engine term` that splices a routed PTY?
13. **Start at login** defaults on while networking is on (§10). Or ask
    once when the first profile turns networking on?
14. **Outer `wss` verification** through the platform verifier, or
    `webpki-roots`? And should plain `ws://` routes be allowed at all?
