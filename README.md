# DecentralisedVPN

A peer-to-peer VPN with no central server. Your traffic leaves the internet from another
peer's IP address, routed through two hops so no single peer sees both who you are and
where you're going. See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, threat model
and known limitations. **Read the limitations before relying on it.**

**Status:** MVP (milestones M1–M4), Linux only, IPv4 only. Installs as a Debian/Ubuntu
desktop app, backed by a background service.

**Lend to use:** you can only route your traffic through the network while your own
machine lends its IP to others as an exit. The app does both at once. See
[DESIGN.md §3.9](docs/DESIGN.md) for how this works, and for why a modified client could
skip it.

dvpn is used through its desktop app. There is no command-line tool or terminal
dashboard for users: the `dvpn` binary is the background service the app controls, and
the package installs it outside your PATH.

## Install (Debian / Ubuntu)

Requires Rust 1.85+ (edition 2024). This builds two packages:
- `dvpn`: the background service;
- `dvpn-gui`: the desktop app, with a tray icon.

```sh
cargo install cargo-deb
# The desktop app needs WebKitGTK headers to build (not to run):
sudo apt install pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev
cargo deb                  # target/debian/dvpn_<version>_amd64.deb
cargo deb -p dvpn-gui      # target/debian/dvpn-gui_<version>_amd64.deb
sudo apt install ./target/debian/dvpn_*.deb ./target/debian/dvpn-gui_*.deb
```

Installing adds you to the `dvpn` group. Log out and back in once, then open **dvpn**
from your applications menu. Older versions could install a `dvpn` command to
`/usr/local/bin`; if you did that, remove it with `sudo rm /usr/local/bin/dvpn`.

## Use it

- The first time, the app shows what lending means and asks you to accept.
- Add a bootstrap peer under **Bootstrap peer**, then press **Connect**. Peers are
  remembered after the first successful join, so this is needed only once.
- To help the network without using the VPN yourself, press **Start lending** under
  **Lending** (or **Lend without connecting** in the tray menu). **Start lending when
  this computer starts** is ticked by default, so once you've accepted the terms dvpn
  lends after every restart; untick it to stop that.
- Closing the window keeps the tray icon. **Quit** closes the app but leaves the VPN as
  it is. **Turn off** disconnects and stops lending.

The app shows:
- **Lending:** whether others can use your exit (directly or through a relay), and
  active sessions;
- **VPN:** disconnected, waiting for lending, connecting, connected (with exit, relay
  and tunnel IP), reconnecting or paused, plus warnings such as DNS not going through
  the tunnel;
- **Exit selection:** random, or max ping with a live count of how many measured exits
  are within your limit;
- the recent log.

### How connecting works

Connecting first brings up your exit, including firewall rules that are removed again
when it stops. dvpn waits until your exit is published and reachable by others,
directly or through a relay if you're behind NAT. Only then does it connect you. If
lending stays down for 2 minutes while you're connected, your traffic is blocked until
it recovers.

**Choosing an exit.** By default, any exit is picked at random, which is the most
private option. To favour speed instead, choose **Max ping** and a limit. dvpn then
measures the latency to several exits through encrypted test circuits, so exits never
see your IP, and picks one at random among those within the limit. If none qualify, it
doesn't connect and keeps retrying.

Either way, exits run by other users who lend while connected are used only if no
dedicated exit fits. You switch to a dedicated exit as soon as one is available.

While connected:
- all IPv4 traffic goes through `dvpn0`,
- IPv6 is blocked,
- DNS goes through the tunnel (default `9.9.9.9`, via systemd-resolved),
- nothing can start a connection to your machine through the tunnel; only replies
  to your own connections come in. (The exit is untrusted, and would otherwise reach
  services listening on your machine.)

Protection starts once the first circuit is up; until then your traffic goes out
normally, and the app says "Not protected yet". After that, if the circuit drops,
traffic is **blocked** (not leaked) until a new one is up. Turning off, or stopping the
service, restores your routes and firewall. If the service crashes, its next start
cleans up after it; `sudo /usr/share/dvpn/exit-teardown.sh` also does it by hand.

Your exit refuses traffic to private networks (including your own LAN), your machine
itself and SMTP. Each session is rate-limited to 10 Mbit/s.

### The service

The service (run by systemd) does the networking as root; the app is its client and
needs no sudo.
- **When it runs:** it starts at boot, idle: it does nothing on the network until you
  lend or connect, or until it starts lending by itself if lending at boot is on (the
  default, once the lending terms are accepted). If that fails (e.g. no network yet),
  it tries again every 30 s. **Turn off** stops it until the next boot.
- **Who can control it:** only root and members of the `dvpn` group can open its
  control socket (`/run/dvpn/control.sock`).
- **Where its data is:** `/var/lib/dvpn`. Its options (DNS server, rate limits, exit
  deny list, …) are in `/etc/default/dvpn`.
- **Logs:** in the app, or `journalctl -u dvpn`.

To give another account control: `sudo usermod -aG dvpn <user>`.
Removing the packages keeps the node's keys; `sudo apt purge dvpn` deletes them.

### Behind NAT

The service uses AutoNAT to work out whether it is reachable from the internet. If it
is behind NAT, it reserves slots on up to two relay peers and attempts hole punching.

## Running network infrastructure

The network also needs bootstrap peers and, ideally, dedicated exits on servers. These
run the same binary by hand, built from source (`cargo build --release`). These
commands are for operators and the tests, not for users:

```sh
dvpn init
dvpn run --reachability public                 # a relay and bootstrap peer
sudo dvpn run --exit --accept-exit-risk         # a dedicated exit (--wan <if> if needed)
dvpn status                                     # the running node's state, as JSON
```

A node run under `sudo` uses root's own identity, in `/root/.local/share/dvpn` unless
you pass `--data-dir`. A dedicated exit sets up IPv4 forwarding, NAT and the forwarding
restrictions itself, and removes them on exit (`sudo scripts/exit-teardown.sh` if it
was killed). `scripts/exit-setup.sh` shows the same rules for review. Besides the
refusals above, `--exit-deny <cidr>` adds more; its sessions are rate-limited to
20 Mbit/s by default.

In a LAN-only network, run at least one node with
`--reachability public --allow-private-addrs`. Bootstrap peers can also be listed in
`<data-dir>/config.json`:

```json
{ "bootstrap": ["/ip4/203.0.113.7/tcp/4001/p2p/12D3KooW..."] }
```

All commands accept `--data-dir` and `--debug`; `dvpn <command> --help` has the rest.

| Command | Main options |
|---|---|
| `run` | `--listen`, `--bootstrap`, `--reachability`, `--no-relay`, `--relay-rate-mbps`, `--exit`, `--accept-exit-risk`, `--wan`, `--exit-deny`, `--exit-max-sessions`, `--exit-rate-mbps` |
| `daemon` | the service, started by systemd: `--bootstrap`, `--max-ping <ms>`, `--dns <ip\|none>`, `--tun-name`, `--listen`, `--reachability`, `--wan`, `--exit-deny`, `--exit-max-sessions`, `--exit-rate-mbps`, `--socket` |
| `connect` | the same as `daemon` without `--socket`, in the foreground; used by the end-to-end test |
| `init`, `status` | — |

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
| `tests/daemon.rs` | the service on a temporary socket (lending can't start without root) | socket permissions, consent before anything starts, start failures reported to clients, lending at boot, bootstrap peers validated and saved, several clients at once, malformed requests |
| `tests/data_path.rs` | real nodes, with in-memory devices instead of TUN | the full packet path, exit policy and anti-spoofing; the status socket |
| `scripts/netns-test.sh` | real TUN devices, routes and NAT in network namespaces (needs root) | identity swapping as seen by a web server, exit policy, kill switch, reconnect, a silently frozen exit, firewall and route cleanup, an exit behind NAT, another user's exit used only as a last resort, then left for a dedicated exit; max-ping mode; kill-switch routes surviving reconnects |
