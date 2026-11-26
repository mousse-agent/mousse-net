# Headless daemon

One Mousse endpoint on a server with no app (design `docs/phase34-design.md`
§B.13). The standalone CLI drives it.

    mousse-helper --state ~/.local/share/mousse-helper serve --headless --listen-ip 0.0.0.0

- **First start** makes the endpoint if the state directory has none. The
  identity key goes in the OS keystore if one takes it; otherwise (a server
  with no Secret Service, or a locked keychain over SSH) in an owner-only
  file, `identity.secret` (mode `0600`, in a `0700` folder). `--key-file`
  picks the file even when a keystore is there. `init --headless` does the
  same without serving. The file key is protected by file permissions only:
  anyone with root on the server, or a copy of its disk, has the key
  (`spec/threat-model.md`). On macOS a helper with no stable signature (ad
  hoc or unsigned) always uses the file, never the Keychain.
- **Pairing:** `invite --qr` prints the ticket as a QR code in the terminal
  for the phone's in-app scanner, and asks "Is the device next to you?" for
  each request. `invite --link` shows a code to type on the joining device
  instead.
- **One process per endpoint:** a second process for the same endpoint (the
  same state directory, or a copy of it) refuses to start; another
  profile's endpoint, in its own state directory, starts alongside.
- **Other commands:** `peers`, `grants`, `remove`, `term`, `stop`, with the
  same `--state` (or `MOUSSE_HELPER_STATE`).

## systemd

`crates/mousse-helper/systemd/mousse-helper.service` is a user unit, so the
terminals it serves run as you:

    install -D -m 0755 mousse-helper ~/.local/bin/mousse-helper
    install -D -m 0644 mousse-helper.service ~/.config/systemd/user/mousse-helper.service
    systemctl --user daemon-reload
    systemctl --user enable --now mousse-helper
    loginctl enable-linger "$USER"

A Docker example waits for Phase 8.

## Check

`phase3.headless` (`checks/phase3.toml`) runs
`cargo test -p mousse-helper --features test-in-person --test headless` on
Linux and macOS, on loopback without mDNS: the endpoint made on first start
with its owner-only key file, re-tightened if loosened; a second process
refused for the same folder and for a copy of it while another profile
starts; the terminal QR code, read by a QR decoder, pairs a device that then
runs a command; and the shipped unit's command line starts the daemon.
Control `no-endpoint-lock` (no endpoint lock) must fail it.
