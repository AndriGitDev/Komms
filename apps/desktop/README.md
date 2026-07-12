# Komms Desktop

Application **A1** ([03 — Architecture](../../docs/03-architecture.md)): a
[Tauri](https://tauri.app) shell over `kult-ffi`'s embedded node runtime —
the exact library surface the mobile shells consume, dogfooded on the
desktop. The shell adds **no protocol logic**: delivery states, errors, and
security indicators are the node's own, verbatim.

## What it does

- **Create / unlock / restore** an encrypted store at the gate; restoring
  takes a `.kkr` backup file plus its 24-word mnemonic.
- **Pair out-of-band**: share your prekey bundle as a QR code or pasteable
  hex (interoperable with `kult bundle` / `kult add`), or add a contact
  from their kult address alone via DHT lookup.
- **Message** with honest delivery states — `queued` → `sent` (handed to a
  link) → `delivered` (end-to-end encrypted receipt came back), plus the
  "held — will send when a faster link exists" verdict on airtime-budgeted
  mesh links.
- **Verify** contacts by safety number: identical digits and QR on both
  ends, compared out-of-band, with a visible verified badge.
- **Transport indicators**: NAT verdict, LAN peers discovered over mDNS,
  queued and bridged-in-transit counts, live listen addresses.
- **Backup** to a single encrypted file; the sealing mnemonic is shown
  exactly once and stored nowhere.
- **Network settings** (listen addresses, bootstrap peers, relays,
  mailboxes, sneakernet spool, Meshtastic radio, bridging) persist as
  `settings.json` in the data directory — the same knobs as `kultd`'s
  flags, and no secrets.

## Layout

```
apps/desktop/
├── ui/                     # dependency-free HTML/CSS/JS — no bundler, no npm
└── src-tauri/
    ├── src/session.rs      # everything the app can do, webview-agnostic (tested)
    ├── src/commands.rs     # Tauri IPC: one-line async wrappers, spawn_blocking
    ├── src/qr.rs           # SVG QR rendering (bundles, addresses, safety numbers)
    └── tests/desktop_e2e.rs# two app backends: pair, message, verify, backup/restore
```

This is deliberately its own cargo workspace: the Tauri/GTK dependency tree
stays out of the core crates' lockfile and cargo-deny surface (the app has
its own `deny.toml`, same posture). The core is reached only through the
path dependency on `kult-ffi`.

## Build & run

Linux needs the WebKitGTK stack (Debian/Ubuntu):

```sh
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev
```

Then, from `apps/desktop/src-tauri`:

```sh
cargo run                  # debug build, launches the app
cargo test                 # unit + two-node end-to-end tests (no webview needed)
cargo run --features meshtastic   # with USB Meshtastic radio support
```

Installable bundles (`.deb`, `.rpm`, AppImage) need the Tauri CLI once:
`cargo install tauri-cli --locked`, then `cargo tauri build` from this
directory.

## Security notes

- The webview is locked down: strict CSP, no Tauri plugins, no filesystem /
  shell / network capabilities — the frontend reaches the world only
  through the audited command surface in `commands.rs`.
- The store passphrase exists in the webview only inside the unlock form
  and crosses IPC once per unlock; it is never persisted by the shell.
- QR codes render black-on-white on their own card regardless of theme —
  phone cameras need the contrast.
