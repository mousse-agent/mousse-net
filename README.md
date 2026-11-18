# mousse-net

The open networking engine for [Mousse](https://github.com/mousse-agent/mousse).

It owns device identity, pairing, host grants, the encrypted session, multiplexing and path choice. It also includes `mousse-relay`, a small relay anyone can run. Mousse uses it to connect your computers and phones over the local network, your own routes (Tailscale, SSH, a port forward or a tunnel) or a relay.

Status: under construction (Phase 0). See [docs/PLAN.md](docs/PLAN.md) for the design and phases, and [spec/](spec/) for the wire spec.

License: MIT.
