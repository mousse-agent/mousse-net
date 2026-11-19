# S2: the route-policy spike

Phase 1b design §1.2, §1.4, §4.1, §4.2 and §13.3; §15 row S2. Result
recorded in §16 "Spike results (S1, S2)". Run on 2026-11-19.

Pinned: `rustls =0.23.46`, `tokio-rustls =0.26.6`,
`rustls-platform-verifier =0.7.1`, `tokio-tungstenite =0.30.0`
(`default-features = false, features = ["handshake"]`), `rcgen =0.14.10`,
`futures-util =0.3.34`.

Commands: `route-policy local | search | ws-echo ADDR [SECS] | dial-wss URL`.
`search` reads `DIAL_PARALLEL` (4) and `DIAL_TIMEOUT_MS` (2000).

## 1. Resolve once, dial the classified address (`local`)

A wss echo server on `127.0.0.1` with a leaf for `spike.invalid` from a
generated root. The client resolves `spike.invalid` once through its own
resolver (a fixed map standing in for DNS), classifies the address, opens
a `TcpStream` to that `SocketAddr`, hands it to rustls (SNI
`spike.invalid`, ALPN `http/1.1`, `rustls-platform-verifier` with the
generated root as its one extra root), then to
`tokio_tungstenite::client_async_with_config` with `mousse.1` offered and
a 65 536-byte message and frame cap.

- **No second lookup:** the system resolver cannot resolve
  `spike.invalid` (`No such host is known`), yet the dial passed, and the
  resolver counter was 1 for two dials. rustls takes only the name for
  SNI, and `client_async` only the URL for `Host`; neither resolves.
- The server saw SNI `spike.invalid`; the response selected `mousse.1`.
- Control: the platform verifier without the extra root refuses with
  `invalid peer certificate: UnknownIssuer`.
- Binary echo of 16 KiB and of exactly 65 536 bytes pass. Over the cap
  from either side is refused: `Space limit exceeded: Message too long:
  65537 > 65536`.
- §4.1's upgrade checks with `accept_hdr_async_with_config`: wrong path
  `404`, an `Origin` header `403`, no `mousse.1` `400`.
- Same results on Linux (WSL).

## 2. Bounded search (`search`), PC loopback only

Dead candidates: "refused" = a closed loopback port; "silent" = a loopback
listener that accepts TCP and never answers the TLS ClientHello. A try is
TCP connect plus the TLS handshake, under `DIAL_TIMEOUT_MS`; 1a's race,
`DIAL_PARALLEL` at once, in order.

| Scenario | Windows 11 | Linux (WSL) |
|---|---|---|
| One connect to a closed loopback port | refused after **2 045 ms** | refused in 0 ms |
| 16 dead, refused and silent alternating | 8 041 ms, every try a 2 s timeout | 4 009 ms |
| 15 dead + live 16th (the `DIAL_MAX_CANDIDATES` cap) | live wins at **6 103 ms** | 2 003 ms |
| 16 dead + live 17th (over the cap) | 8 047 ms | 4 003 ms |
| 16 refused | 8 049 ms | 1 ms |
| 16 silent | 8 035 ms | 8 006 ms |

On Windows a refused connect is retried by the TCP stack for about 2 s,
so a refused candidate holds its slot as long as a silent one (also seen
from `ssh.exe`, S1 item 7, on loopback and over the LAN). The worst case
for a full tier is `ceil(16 / 4) × 2 s = 8 s`.

## 3. cloudflared quick tunnel, observed once

On the Mac: `cloudflared 2026.11.1` (`cloudflared-darwin-arm64.tgz`,
SHA-256 checked against the release's digest) in the spike folder, run
with its own empty `HOME` and `--config` (no account, no login),
`tunnel --no-autoupdate --metrics 127.0.0.1:47111 --url
http://127.0.0.1:47110`, against `route-policy ws-echo 127.0.0.1:47110`.
From the PC: `route-policy dial-wss wss://<name>.trycloudflare.com/mousse-net/1`
with the platform verifier and no extra root. Both processes were stopped
and the binary deleted afterwards.

- Resolved once to two public addresses (104.16.x.x); dialled the first.
- Upgrade, `mousse.1` selected, binary frames: pass.
- First dial: TCP 3 ms, outer TLS 95 ms, upgrade done at 735 ms (cold
  tunnel). A second dial a minute later: upgrade done at 97 ms.
- 1 KiB echo round trip: median 11 ms (9 to 48 ms; one outlier 103 ms).
- 16 KiB echo 13 to 16 ms; **65 536-byte message passes**, 18 to 34 ms.
- Over the cap: refused by the client's cap; the server's cap reset the
  connection (`ResetWithoutClosingHandshake` at the client).
- What the listener saw: `Host` rewritten to the tunnel name, no
  `Origin`, `sec-websocket-protocol: mousse.1` kept, no extensions offered
  (no permessage-deflate), plus `x-forwarded-*` and `cf-*` headers.

## Defaults in §13.3

| Default | Holds? | Measurement |
|---|---|---|
| `TIER_HEAD_START_MS` 500 | yes | a cold quick-tunnel dial takes about 0.7 s; a tcp tier of dead candidates takes 2 to 8 s |
| `WS_DIAL_TIMEOUT_MS` 10000 | yes | cold tunnel upgrade 735 ms, warm 97 ms, plus step 1 at about 11 ms per round trip |
| `SSH_DIAL_TIMEOUT_MS` 20000 | yes | SSH session setup 15 ms to 0.43 s (S1), refused 2.1 s on Windows |
| `DIAL_FAST_TIERS_MS` 12000 | yes | 16 dead tcp candidates end in at most 8 s (Windows) |
| `DIAL_SEARCH_MS` 45000 | yes | fits the fast tiers plus one full ssh try (12 + 20 s) |

**`WS_MESSAGE_MAX_BYTES` floor: 16 384.** The writer sends messages of at
most 16 KiB (§4.2), so a lower cap would refuse a conforming peer; 16 KiB
and 64 KiB both pass through the tunnel. Allowed range: 16 384 to 65 536,
tighten only.
