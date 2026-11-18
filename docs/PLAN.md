# Mousse networking engine: phased plan

Status: approved design, 2026-11-18. Code: this repository. Wire spec: [`spec/`](../spec/).

## Fixed owner decisions
- **No WebRTC, ever.**
- **No free hosted relay or meeting point.** Free users connect over LAN or bring their own route: Tailscale, SSH, a port forward, a tunnel they pay for, or their own relay.
- **Clean break.** There are no users, so v1 networking is deleted.
- **iOS 15 minimum.**
- **The browser is a client only.**
- **Pairing code:** none for a QR scanned in person. Always for a shared link and for a browser.
- **Code reuse is not a goal.**
- **Bulk over a paid relay:** Plus includes a monthly allowance. Bulk is speed-capped and never prompts. When the allowance runs out, bulk pauses and shows usage. Interactive traffic has its own funded balance.

## One-paragraph design
`mousse-net` is an open Rust engine. It owns device identity, pairing (CPace), host grants, the encrypted session, multiplexing and path choice.

- **Session:** rustls TLS 1.3 on a short-lived **session certificate** signed by each device's P-256 **identity key**. TLS proves *who* is connecting; a separate step afterwards decides *what they may do*.
- **Pipes:** it runs over any reliable byte pipe:
  - TCP: LAN, tailnet or port forward
  - SSH stdio
  - WebSocket: relay or user tunnel
  - QUIC later, direct
- **Relay:** `mousse-relay` is one small binary that joins two outgoing connections. It admits a caller only if the target's live **allow-set** lists it, and on Plus it bills the target's prepaid blocks.
- **Plus:** closed, on one VPS. It holds accounts, the encrypted directory, the lease issuer and ledger, and billing. It can never add a trusted device or read relayed traffic.
- **TypeScript app:** keeps UI, RPC meaning, sync, recovery from cursors and Teams authorization.
- **Simulation:** core, relay admission and ledger logic all do no I/O of their own. A seeded simulator runs every drill.

## Components (open unless marked)
- **`mousse-net-core`:** state machines for pairing, grants, session and mux, path choice, the allow-set and the relay protocol. CPace is implemented here over `curve25519-dalek`. No I/O. Builds for all targets including wasm32.
- **`mousse-ledger-core`:** settlement logic with no I/O, shared by the relay counters and Plus.
- **`mousse-sim`:** a seeded, deterministic simulator for core, relay and ledger. Every drill is a seed that replays in seconds.
- **`mousse-net-io`:** tokio adapters, keystores and discovery. Discovery uses `NWBrowser` on iOS, NSD on Android and mDNS on desktop.
- **`mousse-net-ffi`:**
  - UniFFI: Swift async and Kotlin suspend, `cancel(id)`, bounded batches, strict concurrency. Rust owns the tokio runtime.
  - wasm-bindgen for the browser.
- **`mousse-helper`:** desktop, CLI and headless daemon.
- **`mousse-relay`.**
- **`mousse-check`:** the owner test kit.
  - Every automated check ships with a deliberately broken build that **must print FAIL**.
  - Physical devices write signed result files (build hash, platform, outcome). The kit collects them and marks missing runs **INCOMPLETE**.
  - Manual steps are recorded as **ATTESTED**, never as PASS.
- **`spec/`:**
  - the wire spec;
  - test vectors, including rejection vectors;
  - the threat model;
  - "What the relay, Plus and the web client can see".
- **Plus (closed):** `plus-server` and `plus-web`.
- **Web client (open, static):** its own origin, with build hashes published.

## Core designs

### 1. Identity, session certificates and the authorization boundary
- **Identity key:** one ECDSA P-256 key per device, in the Secure Enclave or StrongBox/TEE where available, otherwise a keystore-wrapped software key. The spec lists which platforms use hardware. Browsers use a non-extractable WebCrypto key.
- **Session certificate:** a self-signed certificate on a fresh session key. An extension carries the identity public key (SEC1 uncompressed) and an identity signature in **fixed-width raw r‖s (64 bytes)**. The Secure Enclave and Android produce DER, which is converted. The signature covers the canonical CBOR record:

  `{domain "mousse-session-v1", session SPKI (DER), not_before, not_after ≤ 24 h, protocol version}`

  There is no role field: the host's grant is the only source of a device's role.
- **Step 1, TLS (identity only):**
  - mandatory mutual auth;
  - self-signature;
  - CertificateVerify by the session key;
  - identity signature over that same SPKI;
  - validity window with **±10 min skew**. Outside the window the handshake fails, and the app shows the neutral message in "Clock errors" below; it doesn't assume a wrong clock;
  - **the expected peer identity must match the stored pin on every connection,** not just first contact. That covers reconnects, bulk sessions and path switches. On first contact the pin comes from the ticket.
- **Step 2, after TLS (authorization):** the connection gets either a **live grant** (normal channels) or, if it shows proof of a ticket, a **join-only state** (pairing exchange only, no RPC). Anything else is closed.
- **Lifetime:** the signed window is authoritative, and the same skew rule applies everywhere. A session re-handshakes through the path-switch mechanism before its certificate expires. If re-authentication fails, the session closes at the effective deadline. Revoking or expiring a grant closes the channels bound to that grant at once.
- **Clock errors:** a certificate outside its window can't tell a wrong clock from an expired certificate. The app shows "the certificate is outside its validity window; check this device's clock" and doesn't guess which.
- **Required test vectors:** a valid but wrong identity on reconnect; a live channel at certificate expiry; a valid delegation on the wrong TLS key; an expired delegation; a valid identity with no grant attempting RPC; a DER signature where raw is required; a certificate made in a browser Worker and checked by a native verifier.
- **Browser key loss:** request `navigator.storage.persist()` and recommend installing on Safari. A lost key means re-pairing the browser.

### 2. Trust: local grants, and "remove on all my hosts"
- **Local host grants (Phase 1 onward):** each host keeps `{identity, name, role, source, authorizing owner/profile, adopted_into, granted_at}`. The source is `local` until Phase 6. Each live channel is bound to the grant that authorized it. A device can hold grants on hosts of different owners, which covers Teams. The app enforces Teams rules on every RPC.
- **Remove everywhere (Phase 4):** an admin device sends a signed removal to each of its owner's hosts over sessions, or through the encrypted directory mailbox. It shows "delivered" or "pending" for each host.
  - A **local denial is host-wide** and always wins.
  - A removal affects only grants whose stored authorizing owner matches.
- **Shared roster (Phase 6, after the paid launch).** It is its own phase:
  - **One writer per roster:** records `{roster id, writer epoch, parent hash, sequence, change}`, signed by the writer and kept durably. The genesis record is pinned. A writer transfer starts a new epoch. Losing the writer means a reset and re-pairing.
  - **Grant source:** every grant records its source, `local` or `roster R`.
    - A removal in R voids grants from R everywhere, and voids local grants **only on hosts whose owner roster is R**. A team's writer can never lock an owner out of the owner's own machine.
    - An addition never clears a local denial.
    - Adopting legacy local grants into R is an explicit step. **Adopted grants then need freshness too.**
    - A roster addition grants nothing on a host until that host's own policy accepts it, or until it is explicitly approved locally.
    - Other admins send signed change requests. The writer checks their authority when it commits. Records from an old writer epoch are refused (fenced).
  - **Forks:** hosts keep verified **removals from both branches**. They **suspend additions made after the fork, even ones already applied,** and **close any channels those grants authorized**. New additions stay frozen until the fork is resolved. Arrival order doesn't matter.
  - **Freshness:** every grant the roster covers needs a writer stamp `{roster id, head, grantee, deadline ≤ 30 d}`, including adopted grants. A grantee may carry a stamp but can never create one.
  - **Mailbox key:** rotated on removal.

### 3. Pairing (CPace)
- **Invitation kinds,** chosen by the host and fixed in its pending record:
  - **"Scan in person":** the host asks "Is the device next to you?", then one tap. A warning says that sharing the QR shares that tap.
  - **"Send link":** needs the code. Browsers always use this kind, and so does pre-approval through a link.
- **Ticket** (in the URL fragment): host identity, route manifest, invitation ID, a 128-bit single-use secret, a 10-minute expiry, the kind and the version.
- **Code exchange:**
  - The host shows a fresh 6-digit code, and the owner types it into the joining device.
  - Both run **CPace (ristretto255, SHA-512)**, pinned to draft-irtf-cfrg-cpace-21's initiator/responder profile and its key-confirmation construction. It is implemented in core and passes the draft's vectors on every target.
  - The code always reaches the joiner **independently of the link**: from the host's screen or over a separate call.
  - The digits are never transmitted.
- **Confirmation:** both directions of key confirmation bind:
  - the ticket hash, mode and version;
  - the ordered identities and roles;
  - the **peer session's** TLS exporter, not the outer one.

  Approval needs both confirmations.
- **Attempt limits:**
  - **Both engines** debit an attempt *before* doing any CPace work, including on abort.
  - The host allows 3 per invitation across all routes. The joiner allows 3 per local code-entry flow, which protects a joiner sent to a fake host.
  - Retries are keyed by attempt ID plus TLS session. Only byte-identical messages may be resent; a new session is a new, counted attempt.
  - Each side's 3-attempt cap is local state. A fake host can use up the joiner's attempts, but it can't cancel the real host's invitation.
- **Where codes are typed:** only in the installed app or a trusted, bookmarked or installed web-client origin. A handoff page reached from a link never receives a code.
- **Accept:** the host allows one enrollment per invitation across routes, with atomic consumption. Cancelling grants nothing.
- **If CPace fails its review,** ship in-person pairing only and hold back shared links and browser pairing. There is no fallback where the owner merely compares codes. Phases 0 and 1a can pass with CPace deferred, as long as the matrix marks it **DEFERRED**. "Send link" (Phase 1b) and browser pairing (Phase 5) are gated on CPace passing.

### 4. Session, mux and recovery
- **Mux:** frames `{stream id, type, len}`, credit per stream, control reserved, priority interactive > bulk, keepalive 15 s, idle timeout 45 s.
- **Bulk:**
  - **On relay routes,** bulk uses a **separate outer connection and peer session** on both legs, labelled for the relay. The relay sends interactive traffic ahead of bulk at its shared egress.
  - **On LAN, SSH and user routes,** bulk is a low-priority mux class on the same session. There is no second SSH login.
- **Recovery in the app only:** cursors (terminal history, sync checkpoints, file offsets), durable operation IDs deduplicated by the host across overlapping paths, and "outcome unknown" otherwise.
- **Path switch:** authenticate the new session, reopen from cursors, then close the old one.

### 5. Relay, routes and admission
- **Relay identity is the TLS key itself.**
  - The relay's P-256 identity key is the key in its certificate. It may be self-signed, or an ACME IP certificate for the same key, which works for browsers.
  - **Native clients pin the key** and ignore the certificate chain.
  - **Browsers use normal Web PKI checks** against an origin listed in the host-signed manifest. A valid public certificate at an origin that isn't listed is refused.
  - The privacy doc states that whoever terminates a browser's WSS connection sees relay metadata. Peer TLS inside is still pinned, so they can't see content.
- **State directory:** identity key, ACME files, the self-host allow-list and an exclusive lock. No user data, no payload and no IP logs.
- **Registration:** the target registers handle `H = hash(relay id ‖ registration key)`. It proves it holds that key against a fresh relay challenge on the live connection, so the handle can't be claimed by anyone else. Then it pushes its live **allow-set**:

  `{allowed caller keys, open invitation ids with expiry}`

  - **Caller keys are per pairing** (one per caller and host). They are enrolled with the host **through the authenticated peer session**, never through the relay. A home-relay change needs no key exchange. A relay can't see the same key used for two hosts, though IP and timing can still link them.
  - The target pushes the allow-set to **every relay in its manifest overlap**, and each one closes a removed caller's circuits.
  - **Removing a device** is one immediate allow-set update. The relay closes that caller's circuits and **nobody else is touched**.
  - **After a relay reboot,** calls are accepted only once the target re-registers and pushes its allow-set again.
- **Calling:** the caller signs a challenge bound to the live connection, the relay, `H` and the purpose `call`. The relay forwards only if that key is in `H`'s allow-set. An unlisted caller and an offline target get the same response, in the same timing class.
- **Joining:** first contact presents an open invitation ID. The relay forwards it under a **separate pre-accept budget**, small per circuit and capped per target, and keeps the circuit under that budget until the host promotes it. The host consumes the invitation atomically.
- **Route manifest:** signed by the host: `{relay identity key, endpoints, WSS origin, registration handle, sequence, expiry, region}`.
  - It travels inside sessions and as an encrypted directory entry, with old and new versions overlapping. Callers keep the highest sequence they have seen.
  - Rotation is tested through the old route, which carries the new manifest.
  - A lost relay key means a new manifest. Callers who were offline through the entire overlap re-pair.
- **Linkability:** registration handles rotate with an overlap. The privacy doc admits that IP, timing and Plus issuance can still allow correlation.
- **Self-hosted relay (Phase 3):** `mousse-relay init` writes a list of authorized targets, so operators decide who may register. There are no leases; local limits apply (connections per IP, bandwidth ceiling, bounded queues, idle timeouts).
- **Hosted relay (Phase 4):** admission is the same, plus leases.
- **Launch:** one home relay per host. Manifests already hold lists.

### 6. Leases and the ledger (Plus only, Phase 4)
- **Block:**

  `{lease id, relay id, boot id (fresh per process, authenticated at registration), target registration, class, rate cap, bytes, expiry}`

  The issuer signs it, and it never names an account.
- **Issuing:**
  - The reservation is **written to an append-only journal before signing**. The journal also records settlement and the loss budget spent, and it is replicated off the VPS. **Issuing a block and settling one both wait until the off-VPS copy confirms the write.** A restore replays the journal, so spending is never forgotten.
  - At most **one current and one pending prefetched block per registration and class**.
  - There is a ceiling across a host's overlapping registrations, and issuance stops at the account and fleet limits.
- **Relay enforcement:** counters are cumulative across reconnects, and class rate limits are **aggregate** across sockets, blocks and overlap routes. Opening parallel bulk sockets never multiplies the rate.
- **Classes:**
  - **Interactive:** a separately funded balance, preloaded, with a small hard rate cap across all blocks and connections.
  - **Bulk:** the speed cap and bounded buffering.
- **Prefetch:** the next block is requested at half spent.
  - A refill has a deadline. If it fails or misses the deadline, **only relayed bulk pauses**, and the rest serves typing.
  - For each class the app shows the remaining time: whichever comes first of funded bytes at the measured rate, or expiry.
- **Plus outage:**
  - A host holds roughly 64–128 MB: hours of typing, seconds of bulk. The duration is shown at the measured rate and can be zero.
  - A relay restart during an outage interrupts hosted service, and this is disclosed.
- **Settlement:**
  - Reports are cumulative, authenticated and idempotent per `{relay, boot, lease}`.
  - An exact refund needs a final receipt after a fence.
  - When the end is unknown, we refund the uncertain part and book it to the **operator loss budget**.
- **Exposure caps:**
  - **At launch:** one fleet-wide loss counter and a cap per account.
  - **Every** outstanding block counts against the ceiling before a new one is issued.
  - **Restoring the issuer from backup:** it waits out or fences live blocks before issuing again.
- **Charged unit:** peer ciphertext forwarded, each direction counted once. Billed bytes are compared with VPS egress.
- **Customer charge on our fleet:** the relay's figure, capped by the block.
- **Customer charge on partner relays (Phase 8 only, whether or not volume payouts are enabled):** every debit needs a verified receipt from the target, bound to the lease. The charge is the **lower** of the relay's figure and that receipt, **capped at the block's signed allowance**. With no receipt, nothing is debited. A gap above tolerance moves the account to our fleet. A final reconciliation runs even when no next prefetch happens.
- **Partners:**
  - **Volume payouts are deferred to Phase 8.** Until then, payouts are referral payments against settled subscription revenue, or fixed-rate contracts.
  - If volume payouts come later:
    - **Receipts:** signed with the target's relay-scoped key, cumulative, bound to registration, boot, lease, class and direction. They ride the prefetch request ("no receipt, no next block"), and a final reconciliation runs at close.
    - **Payouts:** on the lower matched figure, with a reconciliation window.
    - **Revenue cap:** each unit of collectible revenue is attributed once, and payouts are capped against revenue after refunds.
    - **Self-dealing test:** a partner that buys its own subscription can't come out ahead.

### 7. Multi-region
- **Manifests** list `{relay, region, key}`.
- **Callers** connect to the target's relay directly.
- **Adding a region** needs a directory entry and a relay, with no app release.
- **Two-region drills** run when region two exists.

### 8. App integration
- **Desktop:** the helper per profile, restarted on a crash.
- **CLI:** through user-restricted IPC, or headless.
- **Phone:**
  - Capacitor → Swift/Kotlin → UniFFI.
  - A **byte path** over a loopback WebSocket (127.0.0.1, strict Host and Origin, a token per launch) carries terminal and file bytes.
  - Sessions run in the foreground only.
- **Browser:** the wasm engine runs in a Worker over WSS.
- **Web client trust:** whoever serves the web client's code can see plaintext in the browser.
  - That trust is separate from the relay privacy claim.
  - The client is served from an open static origin with published hashes, plus a pinned copy users can serve themselves.

## Phases

Each phase ships something usable on its own. Phases 0–3 are the minimum product. **Plus plays no networking role until Phase 4.**

### Phase 0: Thin slice, spikes and the simulator (about 4 weeks)
- **Slice:** two desktop processes pair in person over LAN, open a terminal channel, then remove the grant.
- **Spikes** (pinned versions):
  1. **Crypto matrix:** aws-lc-rs on native (hybrid post-quantum), ring on wasm32, and a single provider also tried. Real handshakes and rejections on all nine target groups, including Worker time, entropy and storage. The negotiated key-exchange group is recorded.
  2. **Browser:** a Worker signs a P-256 session certificate that a native verifier checks, and the key survives a Worker restart.
  3. **Phone byte path:** terminal and file throughput.
  4. **Phone lifecycle:** UniFFI start, stop, cancel and cancelling a pending dial on a physical iOS 15 phone and an Android phone. This sets the Android minimum API and ABIs.
  5. **CPace:** the core implementation passes the draft's vectors on all targets, then gets a design review. If it is not ready, the spike may end DEFERRED and doesn't block Phase 0's exit.
  6. **Browser relay profile:** WSS with Web PKI at an origin listed in the manifest. A valid certificate at an unlisted origin is refused.
- **`mousse-sim`:** the first seeds cover the handshake and pairing attempt limits.
- **Design review** of the session certificate, CPace binding and relay admission before each one freezes.
- **Exit:**
  - Every spike **passes**, or its documented fallback passes; CPace may instead be **DEFERRED**.
  - A second implementation of the handshake (plus CPace confirmation, unless DEFERRED), written by a different model from the spec alone, passes every vector including the rejection vectors.
  - Every `mousse-check phase0` check has a must-fail control that prints FAIL.
- **Owner check:** `mousse-check phase0` shows PASS in every target cell (DEFERRED is allowed only for CPace), with no INCOMPLETE.

### Phase 1a: Two desktops on a LAN (in-person only)
- **Scope:**
  - the helper and TS bridge;
  - in-person invitations;
  - local grants;
  - the session, mux and authorization boundary;
  - terminal and core RPC;
  - cursors and operation IDs;
  - discovery (a rotating random mDNS instance, with a manual address fallback).
- **Exit:**
  - pairing with the internet unplugged;
  - reconnecting after a restart and after an address change;
  - removal is refused at once and closes channels.
- **Owner checks:**
  - Router cable unplugged: scan, tap, connected in under 10 s.
  - The kit drops an acknowledgement and kills the helper. The effect happens once, or shows "outcome unknown", and the kit checks the side effect itself.

### Phase 1b: User routes, CLI and "Send link"
- **Scope:**
  - `tcp` to a tailnet or port forward;
  - `ssh-stdio`;
  - `ws` through a user tunnel;
  - the CLI and remaining RPC;
  - "Send link" with CPace (only if it passed its review).
- **Exit:** the same tests over each route with Plus unreachable; six desktop builds.
- **Owner checks:**
  - Pair through a chat link by typing the code.
  - A tampered link fails.
  - Three wrong codes cancel the invitation on both sides. If CPace is DEFERRED, Phase 1b ships without "Send link", and these link checks are reported as DEFERRED.
  - The kit sends unauthenticated and ungranted traffic to every route, and none of it reaches RPC.

### Phase 2: Native phone and clean break
- **Scope:**
  - plugin, shim and UniFFI;
  - keystore P-256;
  - QR scanning and Bonjour/NSD;
  - the iOS local-network permission flow;
  - the byte path;
  - foreground reconnect;
  - a battery limit of at most 4% per hour of foreground use, set before measuring;
  - **v1 deleted everywhere.**
- **Exit:**
  - Physical iPhone (iOS 15 and latest) and Android: 50 scripted lock/reopen cycles plus 5 attested by hand.
  - Cold starts, socket counts and reconnect percentiles are reported separately from permission prompts.
  - Switching from Wi-Fi to cellular over a user route recovers within 5 s with no repeated command.
- **Owner checks:**
  - Offline Wi-Fi: scan and control a terminal.
  - Walk out of Wi-Fi range on a tailnet: the session returns.
  - Deny local-network permission: the app explains it, and access recovers once permission is granted.

### Phase 3: Self-hosted relay and the first template
- **Scope:**
  - `mousse-relay` with `init` (an authorized-target list, no leases);
  - allow-sets;
  - manifests;
  - local limits;
  - Docker and a one-command install;
  - reproducible, signed releases;
  - the privacy doc, with a review of instrumentation, persistence and crash-dump settings;
  - a minimal headless daemon;
  - **one template, deployed and upgraded by a real outside host.**
- **Exit:**
  - From a fresh $5 VPS with no domain to a first call from a cellular phone in under 5 minutes.
  - Works with UDP blocked.
  - A wrong relay key and a wrong peer identity both fail before any data.
  - A reboot keeps the identity, and calls are refused until the target re-registers.
  - A second process using the same identity won't start.
  - An unlisted caller gets the same response as an offline host.
  - **Remove one phone: it fails, while a second phone on cellular only still connects.** This holds across a relay reboot and a relay rotation.
  - Registering a handle with someone else's key fails.
  - An offline phone survives a home-relay change during the overlap.
- **Owner checks:**
  - The VPS demo.
  - **Marker test, run on a full packet capture and on a relay memory sample, each with its own positive control:** a debug build with peer encryption off must find the phrase in both; the real build finds it 0 times in both. A memory sample covers only one run.
  - The kit prints the deployed hash against a local build, the log configuration and the contents of the state directory.

### Phase 4: Plus and the paid relay (with local grants)
- **Scope:**
  - `plus-server` on one VPS without Supabase: accounts, encrypted directory and mailbox, issuer and ledger (`mousse-ledger-core`), billing;
  - the hosted relay in one region;
  - leases and classes;
  - the usage dashboard;
  - **"remove on all my hosts"**;
  - backups;
  - an **outside code review** before the paid launch.
- **Exit:** the ledger drill as `mousse-sim` seeds, plus one live run:
  - concurrent reconnects;
  - duplicate and reordered reports;
  - a relay killed before its final report;
  - Plus restored from yesterday's backup;
  - a Plus outage.

  The ledger shows usage, reserves, refunds and operator loss separately.
- **Owner checks:**
  - The abuse script prints bytes granted against bytes forwarded, including parallel bulk sockets.
  - Saturate the uplink with bulk: typing stays under the latency threshold.
  - A Plus outage at a stated byte rate lasts the displayed time.
  - Restore yesterday's backup: spent balances and booked losses are still there.
  - Use up a tiny allowance mid-copy and keep typing: the relay adds under 150 ms at the 95th percentile compared with the same idle path. Then switch to LAN and finish with no prompt and no relay charge.
  - Stop Plus: LAN, user routes and the self-hosted relay still work.
  - No relay shows an account name.

### Phase 5: Browser client
- **Scope:**
  - the wasm engine in a Worker;
  - the static open web client (a PWA, published hashes, a pinned self-served copy);
  - the `client` role;
  - pairing by link with CPace in a trusted origin;
  - **WSS** to a relay with an ACME certificate for its identity key, or to a user tunnel;
  - an **SSH loopback page** with strict Host and Origin checks.

  WSS and SSH have separate release gates.
- **Exit:**
  - Browser control through a Plus relay and through a user tunnel.
  - The SSH page works.
  - A route matrix by browser version, including iOS 15 Safari.
- **Exit (renewal):** renewing the 160-hour IP certificate keeps the pinned relay key, and the renewed certificate works on the minimum browser.
- **Owner checks:**
  - Pair a browser, then remove it: it is refused at once.
  - Clear its site data: it asks to re-pair.

### Phase 6: Shared roster (and push, if it earns its place)
- **Scope:** the roster as in §2, and the content-free APNs/FCM wake-up push for Plus, which is best effort.
- **Exit:**
  - Roster drill as seeds plus a live run: forks in both orders, a stale stamp, writer loss, adopted legacy grants.
  - **Removal from a team while the owner's personal grant survives.**
  - An adopted legacy grant without freshness expires.
  - A live grant that exists only on one fork branch is suspended in both arrival orders.
- **Owner check:** revoke a phone with the writer offline and reconnect in both orders. The phone is denied wherever that owner authorized it.

### Phase 7: Direct QUIC (gated)
- **Scope:**
  - quinn on native devices (no H3);
  - UDP address observation through the relay's UDP endpoint, for listed callers or self-hosters only;
  - candidates exchanged inside the session;
  - simultaneous open;
  - peer TLS inside;
  - the relay as fallback.
- **Gate (fleet-weighted, including failures, UDP blocked and restrictive NAT):**
  - relay bytes fall by at least 50%;
  - 9 of 10 network switches recover within 5 s;
  - no repeated commands;
  - battery stays within the Phase 2 limit plus 1% per hour.

  Otherwise it stays off.
- **WebTransport:** only if WSS shows a measured gap. Then pilot h3-webtransport, wtransport and web-transport-quinn on physical browsers, with wrong-pin rejection, fallback when UDP is blocked, authenticated refresh of certificate hashes, and recovery after every cached pin has expired.
- **Owner check:** a 1 GB copy with a direct path sends under 5 MB through the relay.

### Phase 8: Partners and the full headless server
- **Scope:**
  - the full daemon;
  - Docker, Railway, PikaPods and Elestio templates;
  - referral links with no device IDs, counted from partner reports;
  - self-host docs;
  - partner volume payouts, only with the receipt and payout-cap design from §6.
- **Exit:**
  - An operator new to Mousse deploys, upgrades, rolls back and recovers from each template.
  - A phone connects after the upgrade.
  - Referrals are checked separately.

## Cross-cutting
- **Security:**
  - design review before each security feature freezes;
  - outside code review before Phase 4;
  - fuzzing;
  - cargo-deny and cargo-audit;
  - signed, reproducible releases;
  - secrets never logged.
- **Privacy:** "What the relay, Plus and the web client can see":
  - IPs, timing and sizes;
  - handles and per-pairing keys;
  - linking by issuer and IP;
  - settlement metadata;
  - the WSS terminator;
  - web-client update trust.

  The marker test runs with a positive control on every release.
- **Testing:**
  - `mousse-sim` seeds for every drill;
  - a NAT and loss lab using network namespaces and netem;
  - a physical device matrix with signed results;
  - chaos tests;
  - `mousse-check` with must-fail controls.
- **Versioning:** the current and previous minor versions are supported. A major change means re-pairing.
- **Observability:** aggregate counters only.

## Risks and cuts
- **Phone lifecycle and byte path:** the largest effort. Background availability is cut.
- **ring on wasm** has no post-quantum hybrid, so browser sessions may be classical only. This is recorded.
- **CPace in core is our own crypto code:** about 200 lines over dalek, with draft vectors, a second implementation and a design review. If it fails, ship in-person pairing only.
- **WebTransport:** only if a WSS gap is measured.
- **Direct gate fails:** relay and user routes only.
- **Plus outage plus a relay restart:** the hosted relay is interrupted, and this is disclosed.
