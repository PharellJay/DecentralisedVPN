# DecentralisedVPN

A peer-to-peer VPN with no central server. Your traffic leaves the internet from another
peer's IP address, routed through two hops so no single peer sees both who you are and
where you're going. See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, threat model
and known limitations. **Read the limitations before relying on it.**

**Status:** MVP (milestones M1–M4), Linux only, IPv4 only. Installs as a Debian/Ubuntu
package with a background service and a desktop app.

**Lend to use:** you can only route your traffic through the network while your own
machine lends its IP to others as an exit. `dvpn connect` does both at once. See
[DESIGN.md §3.9](docs/DESIGN.md) for how this works, and for why a modified client could
skip it.

## Build

Requires Rust 1.85+ (edition 2024).

```sh
cargo build --release
```

`connect` and `run --exit` create TUN devices and change routes, so they need root. A node
run under `sudo` uses root's own identity, in `/root/.local/share/dvpn` unless you pass
`--data-dir`.

## Install as an app (Debian / Ubuntu)

This builds two packages:
- `dvpn`: the command and a background service;
- `dvpn-gui`: a desktop app with a tray icon.

```sh
cargo install cargo-deb
# The desktop app needs WebKitGTK headers to build (not to run):
sudo apt install pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev
cargo deb                  # target/debian/dvpn_<version>_amd64.deb
cargo deb -p dvpn-gui      # target/debian/dvpn-gui_<version>_amd64.deb
sudo apt install ./target/debian/dvpn_*.deb ./target/debian/dvpn-gui_*.deb
```

Installing adds you to the `dvpn` group. Log out and back in once, then open **dvpn**
from your applications menu. If you used `dvpn install` before, remove that older copy
with `sudo rm /usr/local/bin/dvpn`, since it comes first on your PATH.

- The first time, it shows what lending means and asks you to accept.
- Add a bootstrap peer under **Bootstrap peer**, then press **Connect**.
- To help the network without using the VPN yourself, press **Start lending** under
  **Lending** (or **Lend without connecting** in the tray menu). Tick **Start lending
  when this computer starts** to keep lending after every restart.
- Closing the window keeps the tray icon. **Quit** closes the app but leaves the VPN as
  it is. **Turn off** disconnects and stops lending.

The service (`dvpn daemon`, run by systemd) does the networking as root. The app, the
`dvpn` dashboard and `dvpn ctl` are its clients and need no sudo.
- **When it runs:** it starts at boot, idle: it does nothing on the network until you
  lend or connect, or until it starts lending by itself if lending at boot is on. If
  that fails (e.g. no network yet), it tries again every 30 s. **Turn off** stops it
  until the next boot.
- **Who can control it:** only root and members of the `dvpn` group can open its
  control socket (`/run/dvpn/control.sock`).
- **Where its data is:** `/var/lib/dvpn`. Its options are in `/etc/default/dvpn`.
- **Logs:** `journalctl -u dvpn`, or `dvpn ctl logs`.

To give another account control: `sudo usermod -aG dvpn <user>`.
Removing the packages keeps the node's keys; `sudo apt purge dvpn` deletes them.

### `dvpn ctl`: the service from the command line

```sh
dvpn ctl status                 # lending, VPN, exits; --json for everything
dvpn ctl terms                  # what lending means
dvpn ctl accept-exit-risk
dvpn ctl add-bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...
dvpn ctl lend                   # lend without connecting the VPN yourself
dvpn ctl lend-at-boot on        # lend from every boot (off to stop)
dvpn ctl connect
dvpn ctl max-ping 80            # or: dvpn ctl random
dvpn ctl disconnect             # lending keeps running
dvpn ctl off                    # disconnect and stop lending
dvpn ctl logs
```

## Use it

### The dashboard (TUI)

With the packages installed, `dvpn` opens the dashboard as a client of the service. It
needs no sudo, and closing it (`q`) leaves the VPN running. `x` turns it off.

Without the packages, the dashboard runs everything itself, as root. This is the easiest
way to try dvpn from a source build. The first time, point it at any peer you know:

```sh
target/release/dvpn tui --bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...
```

It asks for your password through `sudo` itself, and creates your identity if there
isn't one yet. Then it explains that using the VPN means lending your IP and asks you
to accept. After that it offers to install the `dvpn` command to
`/usr/local/bin/dvpn`. If you accept, starting it again later is just:

```sh
dvpn            # from any terminal; the same as `dvpn tui`
```

Peers from the last run are remembered, so `--bootstrap` isn't needed again.
`sudo dvpn install` installs or updates the command at any time (the dashboard copies
the binary, so re-run it after rebuilding). `sudo dvpn uninstall` removes it; your
keys and settings stay. The dashboard runs as root, so its data is in
`/root/.local/share/dvpn`, and `sudo dvpn status` shows its state.

The dashboard shows:
- **Lending:** whether others can use your exit (directly or through a relay), and
  active sessions;
- **VPN:** disconnected, waiting for lending, connecting, connected (with exit, relay
  and tunnel IP), reconnecting or paused.
  - **Until the first connection is up,** your traffic still goes out normally, and the
    dashboard says "Not protected yet".
  - **From then on,** traffic is blocked whenever the tunnel is down (reconnecting,
    paused), never leaked.
  - Warnings such as DNS not going through the tunnel are shown here too;
- **Exit selection:** random, or max ping with a live count of how many measured exits
  are within your limit, before you connect;
- the recent log.

| Key | Action |
|---|---|
| `c` / `d` | connect / disconnect the VPN (lending keeps running) |
| `l` | with the service: lend without connecting |
| `b` | with the service: lend from boot, on / off |
| `m` | switch between random and max-ping mode |
| `+` / `-` | raise / lower the ping limit by 10 ms |
| `r` | measure exits again |
| `q`, `Esc`, Ctrl-C | quit: disconnects, stops lending, restores your network |

It takes the same options as `connect`. A changed mode applies from the next circuit.

### Join as a relay

Relays only ever see encrypted traffic.

```sh
dvpn init
dvpn run                                    # on a LAN, peers find each other via mDNS
dvpn run --bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...   # or point at any peer
```

### Connect: route your traffic through the network, and lend your IP in return

The first time, `dvpn` explains what lending means: other users' traffic leaves
through your connection, so complaints about misuse may reach you first. You accept
with `--accept-exit-risk` (or `y` in the dashboard).

```sh
sudo dvpn init
sudo dvpn connect --accept-exit-risk --bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...
sudo dvpn status          # in another terminal
```

`connect` first brings up your exit, including firewall rules that it removes again
when it stops. It waits until your exit is published and reachable by others,
directly or through a relay if you're behind NAT. Only then does it connect you. If
lending stays down for 2 minutes while you're connected, your traffic is blocked until
it recovers.

**Choosing an exit.** By default, any exit is picked at random, which is the most
private option. To favour speed instead, pass `--max-ping <ms>`:

```sh
sudo dvpn connect --max-ping 80 ...
```

`dvpn` then measures the latency to several exits through encrypted test circuits, so
exits never see your IP. It picks one at random among those within 80 ms, and
`dvpn status` shows how many qualified, e.g. "3 of 5 dedicated exits within 80 ms
(fastest 23 ms)". If none qualify, it doesn't connect and keeps retrying.

Either way, exits run by other users who lend while connected are used only if no
dedicated exit (`dvpn run --exit`) fits. You switch to a dedicated exit as soon as
one is available.

While connected:
- all IPv4 traffic goes through `dvpn0`,
- IPv6 is blocked,
- DNS goes through the tunnel to `--dns` (default `9.9.9.9`, via systemd-resolved).

- Nothing can start a connection to your machine through the tunnel; only replies
  to your own connections come in. (The exit is untrusted, and would otherwise reach
  services listening on your machine.)

Protection starts once the first circuit is up; until then your traffic goes out
normally. After that, if the circuit drops, traffic is **blocked** (not leaked) until a
new one is up. Ctrl-C, closing the terminal or `kill` disconnects and restores your
routes and firewall. If dvpn is killed with `kill -9` or crashes, the next start
cleans up after it. `sudo scripts/exit-teardown.sh` also does it by hand.

### Lend only: be an exit without using the VPN

```sh
sudo dvpn run --exit --accept-exit-risk     # --wan <if> if the default route's device is wrong
```

`dvpn` sets up IPv4 forwarding, NAT and the forwarding restrictions itself, and removes
them on exit. If it was killed and couldn't clean up, run
`sudo scripts/exit-teardown.sh`. `scripts/exit-setup.sh` shows the same rules for
anyone who wants to review them or apply them by hand.

The exit refuses traffic to:
- private networks, including your own LAN,
- the exit machine itself,
- SMTP,
- anything listed with `--exit-deny <cidr>`.

Each session is rate-limited (`--exit-rate-mbps`): the default is 20 Mbit/s for
`run --exit` and 10 Mbit/s for `connect`.

### Configuration

After the first successful join, peers are cached in `peers.json`, so later runs need no
bootstrap address. Bootstrap peers can also be listed in `<data-dir>/config.json`:

```json
{ "bootstrap": ["/ip4/203.0.113.7/tcp/4001/p2p/12D3KooW..."] }
```

### Behind NAT

By default (`--reachability auto`), the node uses AutoNAT to work out whether it is
reachable from the internet.
- If it is behind NAT, it reserves slots on up to two relay peers and attempts hole
  punching.
- On a server with a public IP, use `--reachability public`.
- In a LAN-only network, run at least one node with
  `--reachability public --allow-private-addrs`.

### Options

All commands accept `--data-dir` and `--debug`. Run `dvpn <command> --help` for the full
list.

| Command | Main options |
|---|---|
| `run` | `--listen`, `--bootstrap`, `--reachability`, `--no-relay`, `--relay-rate-mbps`, `--exit`, `--accept-exit-risk`, `--wan`, `--exit-deny`, `--exit-max-sessions`, `--exit-rate-mbps` |
| `tui` (or no command) | same as `connect`, plus `--local` to run in-process even with the service installed |
| `install` / `uninstall` | — |
| `daemon` | same as `connect`, plus `--socket`; data in `/var/lib/dvpn` by default |
| `ctl <command>` | `--socket`; commands: `status`, `lend`, `lend-at-boot`, `connect`, `disconnect`, `off`, `random`, `max-ping`, `measure`, `terms`, `accept-exit-risk`, `add-bootstrap`, `logs` |
| `connect` | `--bootstrap`, `--max-ping <ms>`, `--dns <ip\|none>`, `--tun-name`, `--listen`, `--reachability`, `--accept-exit-risk`, `--wan`, `--exit-deny`, `--exit-max-sessions`, `--exit-rate-mbps` |
| `status` | — |

## Try it on a throwaway network

```sh
cargo build
sudo scripts/netns-demo.sh
```

This builds a small fake internet out of network namespaces: a relay, three exits
with about 10, 40 and 80 ms of latency (one behind NAT), and a web server that tells
you which IP it sees. Then it opens the dashboard as a user behind a home router.
Connect, try max-ping mode, and from another terminal run
`sudo ip netns exec dvt-client curl -s http://203.0.113.80/` to see your traffic
leave from an exit's IP. Quitting the dashboard removes the whole network. Your own
network, DNS and `/usr/local/bin` are not touched.

## Test

```sh
cargo test                       # no root needed (the dvpn crate; the app: cargo build -p dvpn-gui)
sudo scripts/netns-test.sh       # real TUN, routes and NAT in throwaway namespaces
```

| Test | What it starts | What it checks |
|---|---|---|
| `tests/discovery.rs` | real nodes on localhost | DHT discovery and rejoining from the peer cache |
| `tests/circuits.rs` | real nodes on localhost | end-to-end 2-hop circuits; refusal by non-exit and non-relay nodes |
| `tests/nat.rs` | real nodes on localhost | AutoNAT, relay reservations, an exit behind NAT |
| `tests/tunnel_crypto.rs` | a client and exit joined by an in-memory relay | the relay can't read, tamper with or replay traffic; an impostor exit is rejected |
| `tests/keepalive.rs` | a client and exit on an in-memory pipe, with a simulated clock | idle tunnels stay up; an exit that silently stops answering is detected; the exit frees silent sessions |
| `tests/lending.rs` | real nodes on localhost | when lending counts as ready (public, behind NAT); `connect` refuses to run without lending and builds no circuit until it is ready |
| `tests/selection.rs` | real nodes on localhost | dedicated exits before other users' exits; max-ping measures through test circuits, picks within the limit, and reports when nothing qualifies |
| `src/tui.rs` (unit tests) | the dashboard rendered into a test buffer | consent screen, lending states, connected/waiting/paused, max-ping availability |
| `tests/daemon.rs` | the service on a temporary socket (lending can't start without root) | socket permissions, consent before anything starts, start failures reported to clients, bootstrap peers validated and saved, several clients at once, malformed requests |
| `tests/data_path.rs` | real nodes, with in-memory devices instead of TUN | the full packet path, exit policy and anti-spoofing; the status socket |
| `scripts/netns-test.sh` | real TUN devices, routes and NAT in network namespaces (needs root) | identity swapping as seen by a web server, exit policy, kill switch, reconnect, a silently frozen exit, firewall and route cleanup, an exit behind NAT, another user's exit used only as a last resort, then left for a dedicated exit; max-ping mode; kill-switch routes surviving reconnects |
