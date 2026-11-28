# What the relay, Plus and the web client can see

Status: Phase 3. It states what is true with direct connections (Phase 0)
and through a self-hosted relay (Phase 3), and lists what later phases must
add. Each later phase updates this document before it ships.

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
  fragment, which browsers do not send to web servers. Scripts on the page
  that opens the link can still read the fragment, so any page a link
  lands on learns the whole ticket. That is why a pairing code is typed
  only in the installed app or a trusted web-client origin, never on a page
  reached from a link ([`wire.md`](wire.md) 10.6 step 2): without the code,
  a "Send link" ticket cannot pair.
- **Discovery** on the LAN uses mDNS (DNS-SD). A running host advertises:
  - the service type `_mousse._tcp.local.`, which tells everyone on the LAN
    that a Mousse host is listening;
  - an instance name `mousse-` followed by 12 random base32 characters, and
    an mDNS host name `<instance>.local.`;
  - the TCP port it listens on;
  - a TXT record with only `v=1`, the protocol version;
  - address records (A and AAAA) for the host's network interfaces.

  The instance and host names are drawn fresh at every start and every 15
  minutes. Nothing advertised names the device, its owner or its identity
  key. An observer on the LAN can still link the advertisements over time
  by IP and MAC address and by port, and can connect to learn the identity
  key (below).
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
- **Pair with IP has no pin on first contact.** A joiner shows its identity
  key, its computer name and the code's lookup (the first 4 characters) to
  whatever Mousse endpoint answers at the address it typed, before the code
  exchange has shown that it is the real host ([`wire.md`](wire.md) 10.9).
  The secret part of the code is never sent.

## Through a relay (Phase 3)

A relay ([`relay.md`](relay.md)) forwards WebSocket messages between two
legs. Everything a device says to the other device travels inside the peer
TLS session, pinned to the other device's identity key (wire.md 5.4), so
the relay forwards bytes it cannot read. What it does see:

- **IP addresses, timing and sizes.** The IP address and port of every
  connection to it, when each opens and closes, and the size and time of
  every message on each leg: so who talks to whom (by handle and caller
  fingerprint, below), when, and how much. An observer on the path between
  a device and the relay sees the same IPs, timing and sizes, and that the
  connection is a WebSocket over TLS (ALPN `http/1.1`) to that address. The
  path `/mousse-relay/1` and subprotocol `mousse-relay.1` are inside TLS.
- **Handles.** A handle is a hash of the relay id and a registration key
  ([`relay.md`](relay.md) 3). It is stable for as long as the target keeps
  that key, so the relay can recognise a target across connections and IP
  changes. A handle means nothing on another relay. A self-hosted relay
  rotates a target's key only when the target sends `SUCCESSOR`; during the
  overlap the relay knows the two handles are one target.
- **Caller key fingerprints and who calls whom.** A target's allow-set lists
  the fingerprint of each caller key it accepts, and every `CALL` carries
  the caller's key, so the relay learns which caller key opens which
  circuit to which handle. Each pairing has its own caller key: a device
  that calls two hosts uses two unrelated keys, so the relay cannot link
  those calls by key. It can still link them by IP address and timing.
- **Joins.** A joiner presents an invitation tag, a hash only a ticket
  holder can compute. The relay learns that some invitation of that handle
  was used, never the invitation id, the ticket secret or the code.
- **Registration keys and identity keys are different.** The relay never
  sees an identity key or a certificate: those travel inside the peer TLS.
- **The relay id.** Clients pin the relay by the hash of its TLS key. The
  relay's certificate carries no name and no operator details.

**What the relay keeps.** Its state directory holds only its identity key,
the operator's list of authorized registration key fingerprints (with drop
times after a `SUCCESSOR`), hashes of unused enrollment codes, its public
address, and two lock files. Allow-sets, registrations, circuits and IP
addresses live in memory only and end with the process
([`relay.md`](relay.md) 12). Its log lines carry aggregate counts and
errors only: never an IP address, handle, fingerprint or payload. `mousse-check
relay-inspect` lists the state directory and flags any other file.

**Who runs the relay.** A self-hosted relay is run by the person who owns
the devices, on a machine they rent or own. The machine's provider can see
what the relay process can see (above), and can read the identity key from
disk; with it, the provider could stand up a copy of the relay and receive
the same connections, but still not read them or get past either device's
pin.

**The WSS terminator.** The relay process itself ends the outer TLS: there
is no load balancer or CDN in front of a self-hosted relay. If an operator
puts one there, that party sees what the relay sees (above) and nothing
more, because the peer TLS runs end to end inside.

**How users are told.** Where a relay route is approved, the app must say
that the relay's operator can see which of their devices connect, when and
how much, and never what is said.

## Rate groups on hosted relays (Phase 4, decided early)

A hosted relay limits speed per **rate group**, a random 16-byte value in
each paid block (`docs/phase34-design.md` A.12). Plus draws a fresh rate
group for every relay handle, so the group itself never tells a relay
that two handles belong to the same device across a handle rotation.

What can still link them: while their rotation overlaps, both handles
carry the same caller key fingerprints in their allow-sets, so a relay can
tell they belong to one device directly, even when the IP address
changes. It also sees both handles register from the same IP address at
nearly the same time. Users are told that a hosted relay can follow a
device across handle rotations by its callers' fingerprints, IP address
and timing, but not by anything Plus puts in a paid block.

The cost of this choice: during a rotation the old handle may spend the
blocks it already holds at its own speed limit, beside the new handle.
Plus bounds that by funding only the newest handle and by allowing at most
one new handle per device and relay per day by default.
## Routes beyond the LAN (Phase 1b)

- **Port forwards and tunnels.** Any internet prober that reaches the
  listener learns the host's identity key from its TLS certificate. On a
  LAN this was already true for anyone on the network; a forward or a
  tunnel makes it global. It learns nothing else before step 2.
- **Approved destinations** learn the joiner's IP address when it dials
  them, before any pin check. That is why such destinations are dialled
  only after the owner approves them.
- **The tunnel provider** (for example cloudflared or Funnel) ends the
  outer WebSocket TLS. It sees both IP addresses, timing, sizes and the
  WebSocket path, never content: the pinned peer TLS runs inside.
- **The tailnet coordinator** sees that two of its nodes talk.
- **Over SSH**, the remote account's profile list (labels, no paths) is
  shown to whoever logs in as that OS account during SSH add.
- **Checks** never reach Plus or the internet: app checks point Plus at a
  loopback recorder, and refuse and log any other connection out of the
  test cell.

## To be filled in by later phases

These headings come from the plan. Each must say what each party can see and
how users are told.

- **Linking by issuer and IP:** what Plus and a hosted relay can link
  across sessions (Phase 4; a self-hosted relay's part is above).
- **Settlement metadata** for paid relay use (Phase 4).
- **Web-client update trust:** how users know which web-client build they run
  (Phase 5).
