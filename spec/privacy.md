# What the relay, Plus and the web client can see

Status: Phase 0 stub. It states what is true in Phase 0 and lists what later
phases must add. Each later phase updates this document before it ships.

## Phase 0 facts

- **There is no relay, no Plus and no web client in Phase 0.** Devices talk
  directly over the LAN. Nothing is sent to a Mousse server.
- **Contents are encrypted.** Channels run inside TLS 1.3 between the two
  devices. Only the two devices can read them.
- **Certificates are not visible on the wire.** In TLS 1.3 both certificates
  are encrypted, so an observer does not see identity keys.
- **What an observer on the network can see:**
  - the IP addresses and ports of both devices;
  - when they connect, for how long, and how many bytes flow in each
    direction (timing and sizes);
  - that the connection is Mousse, from the ALPN value `mousse/1` in the TLS
    handshake;
  - keepalive traffic every 15 s on an otherwise idle connection.
- **Pairing tickets** contain the host's identity key, the invitation id, the
  secret, the expiry and route hints (for example a LAN address). Anyone who
  sees the QR or link sees these. The link form keeps the ticket in the URL
  fragment, which browsers do not send to web servers.
- **Discovery** on the LAN is described here when it is built; it may reveal
  that a Mousse host is present on the network.
- **Grants and denials** stay on the host. No list of paired devices leaves
  it.

## What the far end of a connection learns

- **The identity key is a stable identifier.** It never changes for an
  endpoint, so anyone who learns it can recognise that endpoint again. A
  host sends its certificate to every caller that reaches its port, so an
  active prober on the network learns the host's identity key and can tell
  later that it is the same host. A caller sends its certificate only after
  the host's certificate passed step 1 against the caller's pin, so a caller
  reveals its identity key only to the endpoint its pin (or ticket) names.
- **A fake host learns who is joining.** A swapped "Send link" names the
  fake host's key, so step 1 passes against it, and the joiner sends its
  identity key and its `JOIN_PROOF` name before the code exchange has shown
  that the far end is the real host. The code exchange then fails, but the
  fake host keeps what it learned. To keep that small, a "Send link" joiner
  sends only the computer name in `JOIN_PROOF`, never its profile label
  ([`wire.md`](wire.md) 10.3). The label is meant to follow only after the
  host's confirmation verified; version 1 has no message for that yet, so a
  send-link grant is named after the computer.
- An in-person ticket is accepted only from the app's own scanner
  ([`wire.md`](wire.md) 10.1), so a swapped link cannot make the joiner send
  its full name to a fake host that way.

## To be filled in by later phases

These headings come from the plan. Each must say what each party can see and
how users are told.

- **IPs, timing and sizes** at a relay (Phase 3 onward).
- **Handles and per-pairing keys** used to address devices through a relay.
- **Linking by issuer and IP:** what Plus and a relay can link across
  sessions.
- **Settlement metadata** for paid relay use (Phase 4).
- **The WSS terminator:** what the party ending the outer WebSocket TLS sees.
- **Web-client update trust:** how users know which web-client build they run
  (Phase 5).
