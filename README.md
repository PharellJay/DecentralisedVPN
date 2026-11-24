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

Then open **dvpn** from your applications menu; there's nothing to set up. Anyone
signed in at this computer can use the app (via polkit). For other accounts, e.g. over
SSH, an administrator can run `sudo usermod -aG dvpn <user>`; that applies at once,
without logging out. Older versions could install a `dvpn` command to
`/usr/local/bin`; if you did that, remove it with `sudo rm /usr/local/bin/dvpn`.

## Update

Get the new source, then build and install both packages again. Settings, bootstrap
peers and the node's keys in `/var/lib/dvpn` are kept.

```sh
git pull
cargo deb && cargo deb -p dvpn-gui
sudo apt install ./target/debian/dvpn_*.deb ./target/debian/dvpn-gui_*.deb
```

- If `target/debian` still holds older packages, the wildcard picks those up too.
  Delete them first, or name the new version's files.
- Rebuilding without a version change? Use `sudo apt reinstall` with the same files,
  since `apt install` skips a version that's already installed.
- The service restarts by itself during the update, which disconnects you if you're
  connected. Quit and reopen the app (tray icon → Quit) so the new app runs too.
- After every install, update or reinstall, the app shows the lending terms again.
  Nothing lends until you accept them. If lending at boot is on, it starts as soon as
  you accept, and your earlier choice is kept.

## Uninstall

```sh
sudo apt remove dvpn-gui dvpn
```

This stops the service and removes the app, and with it any firewall rules or routes
a crashed connection left behind. The node's keys and settings in `/var/lib/dvpn`
stay, so reinstalling continues where you left off. To delete those too:

```sh
sudo apt purge dvpn-gui dvpn
rm -rf ~/.local/share/dev.dvpn.desktop   # the app's window data, for each user
```

The `dvpn` user and group remain. They own no files and can't sign in, but
`sudo userdel dvpn; sudo groupdel dvpn` removes them if you want them gone.

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
- **VPN:** disconnected, waiting for lending, connecting, connected (with the IP your
  traffic appears to come from, the kind of exit, latency, data sent and received, and
  whether packets go as UDP datagrams), reconnecting or paused, plus warnings such as
  DNS not going through the tunnel;
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

Once connected, packets travel as UDP datagrams through the relay where possible, so
a lost packet doesn't hold up the others (smoother on Wi-Fi and mobile, and for calls
and games). Where UDP is blocked, they go over the circuit's encrypted stream instead,
and dvpn switches back and forth by itself.

While connected:
- all IPv4 traffic goes through `dvpn0`,
- IPv6 is blocked,
- nothing leaves your machine outside the tunnel, except to your LAN and dvpn's own
  traffic, even if your network pushes routes around it,
- DNS goes through the tunnel, encrypted (default `9.9.9.9` with DNS-over-TLS, via
  systemd-resolved), so the exit can't read it,
- nothing can start a connection to your machine through the tunnel; only replies
  to your own connections come in. (The exit is untrusted, and would otherwise reach
  services listening on your machine.)

Protection starts the moment you click **Connect** and lasts until you disconnect:
while connecting, if the circuit drops, or if something fails, traffic is **blocked**
(not leaked) and dvpn reconnects by itself. If the service crashes while connected,
traffic stays blocked and its next start reconnects. Disconnecting, turning off or
stopping the service restores your routes and firewall;
`sudo /usr/share/dvpn/exit-teardown.sh` removes leftovers by hand.

Your exit only carries common services: the web, DNS, email (but not direct
connections to mail servers, the usual route for spam), SSH, chat, calls and the like.
Other ports, such as file sharing, are refused, and so is traffic to private networks
(including your own LAN), your machine and your router's public address. Each session
is rate-limited to 10 Mbit/s. The same goes for other users' exits you might use: they
are a last resort, and the app tells you when you're on one.

To the network, your computer is a new node every time dvpn starts, restarts, your
computer changes networks or your internet provider gives you a new address (lending
and the VPN restart then too), so peers can't recognise it from one session to the
next. It isn't announced on your local network.

### The service

The service (run by systemd) does the networking, as its own user `dvpn` with only
network-administration rights, not as root; the app is its client and needs no sudo.
- **When it runs:** it starts at boot, idle: it does nothing on the network until you
  lend or connect, or until it starts lending by itself if lending at boot is on (the
  default, once the lending terms are accepted). If that fails (e.g. no network yet),
  it tries again every 30 s. **Turn off** stops it until the next boot.
- **Who can control it:** anyone signed in at this computer (polkit action
  `dev.dvpn.control`), and members of the `dvpn` group, through its control socket
  (`/run/dvpn/control.sock`).
- **Where its data is:** `/var/lib/dvpn`. Its options (DNS server, rate limits, exit
  deny list, …) are in `/etc/default/dvpn`.
- **Logs:** in the app. `journalctl -u dvpn` keeps only warnings, so your usage
  history isn't written to disk.

To give another account control (e.g. over SSH): `sudo usermod -aG dvpn <user>`. It
applies right away.
Removing the packages keeps the node's keys; `sudo apt purge dvpn` deletes them (see
[Uninstall](#uninstall)).

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
refusals above, `--exit-deny <cidr>` adds more. Unlike users' exits, a dedicated exit forwards every port
except SMTP (TCP 25). Its sessions are rate-limited to 20 Mbit/s by default, and it keeps
the identity `dvpn init` created, so its bootstrap address stays valid.

Complaints about traffic from a dedicated exit reach its operator. `--exit-notice`
serves a page on port 80 of the exit's address that explains it is a dvpn exit and
keeps no logs (like a Tor exit notice); `--exit-contact abuse@example.org` adds a
contact, and `--exit-notice-listen` picks another address or port.

Relays must be reachable on UDP port 4002 as well as their listen ports, for the
datagram path (`--datagram-port` changes it). Without it, circuits through them still
work, over streams only.

In a LAN-only network, run at least one node with
`--reachability public --allow-private-addrs`; `--mdns` lets nodes find each other there.
Bootstrap peers can also be listed in
`<data-dir>/config.json`:

```json
{ "bootstrap": ["/ip4/203.0.113.7/tcp/4001/p2p/12D3KooW..."] }
```

All commands accept `--data-dir` and `--debug`, and `run`, `connect` and `daemon` accept
`--mdns`, `--datagram-port` and `--no-datagrams`; `dvpn <command> --help` has the rest.

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
| `tests/circuits.rs` | real nodes on localhost | end-to-end 2-hop circuits; the switch to datagrams, and staying on the stream through a relay without them; refusal by non-exit and non-relay nodes |
| `tests/nat.rs` | real nodes on localhost | AutoNAT, relay reservations, an exit behind NAT |
| `tests/tunnel_crypto.rs` | a client and exit joined by an in-memory relay | the relay can't read, tamper with or replay traffic; an impostor exit is rejected |
| `tests/keepalive.rs` | a client and exit on an in-memory pipe, with a simulated clock | idle tunnels stay up; an exit that silently stops answering is detected; the exit frees silent sessions |
| `tests/lending.rs` | real nodes on localhost | when lending counts as ready (public, behind NAT); `connect` refuses to run without lending and builds no circuit until it is ready |
| `tests/selection.rs` | real nodes on localhost | dedicated exits before other users' exits; max-ping measures through test circuits, picks within the limit, and reports when nothing qualifies |
| `tests/daemon.rs` | the service on a temporary socket (lending can't start without root) | socket permissions, consent before anything starts, start failures reported to clients, lending at boot, bootstrap peers validated and saved, several clients at once, malformed requests |
| `tests/data_path.rs` | real nodes, with in-memory devices instead of TUN | the full packet path, exit policy and anti-spoofing; the status socket |
| `scripts/netns-test.sh` | real TUN devices, routes and NAT in network namespaces (needs root) | identity swapping as seen by a web server, exit policy, UDP datagrams and the fall-back to the stream when the relay's UDP is blocked, kill switch, reconnect, a silently frozen exit, firewall and route cleanup, an exit behind NAT, another user's exit used only as a last resort, then left for a dedicated exit; max-ping mode; kill-switch routes surviving reconnects |
