# DecentralisedVPN

A peer-to-peer VPN with no central server. Your traffic leaves the internet from another
peer's IP address, routed through two hops so no single peer sees both who you are and
where you're going. See [docs/DESIGN.md](docs/DESIGN.md) for the architecture, threat model
and known limitations. **Read the limitations before relying on it.**

**Status:** MVP (milestones M1–M3), Linux only, IPv4 only.

## Build

Requires Rust 1.85+ (edition 2024).

```sh
cargo build --release
```

`connect` and `run --exit` create TUN devices and change routes, so they need root. A node
run under `sudo` uses root's own identity, in `/root/.local/share/dvpn` unless you pass
`--data-dir`.

## Use it

### Join as a relay

Relays only ever see encrypted traffic.

```sh
dvpn init
dvpn run                                    # on a LAN, peers find each other via mDNS
dvpn run --bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...   # or point at any peer
```

### Connect: route your traffic through the network

```sh
sudo dvpn init
sudo dvpn connect --bootstrap /ip4/203.0.113.7/tcp/4001/p2p/12D3KooW...
sudo dvpn status          # in another terminal
```

While connected:
- all IPv4 traffic goes through `dvpn0`,
- IPv6 is blocked,
- DNS goes through the tunnel to `--dns` (default `9.9.9.9`, via systemd-resolved).

If the circuit drops, traffic is **blocked** (not leaked) until a new one is up. Ctrl-C
disconnects and restores your routes.

### Act as an exit: lend your IP to others

Read the warning `dvpn` prints first. Other people's traffic will appear to come from
you.

```sh
sudo scripts/exit-setup.sh eth0             # your internet-facing interface
sudo dvpn run --exit --accept-exit-risk
sudo scripts/exit-teardown.sh               # when you stop being an exit
```

The exit refuses traffic to:
- private networks, including your own LAN,
- the exit machine itself,
- SMTP,
- anything listed with `--exit-deny <cidr>`.

Each session is rate-limited (`--exit-rate-mbps`, default 20).

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
| `run` | `--listen`, `--bootstrap`, `--reachability`, `--no-relay`, `--relay-rate-mbps`, `--exit`, `--exit-deny`, `--exit-max-sessions`, `--exit-rate-mbps` |
| `connect` | `--bootstrap`, `--dns <ip\|none>`, `--tun-name` |
| `status` | — |

## Test

```sh
cargo test                       # no root needed
sudo scripts/netns-test.sh       # real TUN, routes and NAT in throwaway namespaces
```

| Test | What it starts | What it checks |
|---|---|---|
| `tests/discovery.rs` | real nodes on localhost | DHT discovery and rejoining from the peer cache |
| `tests/circuits.rs` | real nodes on localhost | end-to-end 2-hop circuits; refusal by non-exit and non-relay nodes |
| `tests/nat.rs` | real nodes on localhost | AutoNAT, relay reservations, an exit behind NAT |
| `tests/tunnel_crypto.rs` | a client and exit joined by an in-memory relay | the relay can't read, tamper with or replay traffic; an impostor exit is rejected |
| `tests/keepalive.rs` | a client and exit on an in-memory pipe, with a simulated clock | idle tunnels stay up; an exit that silently stops answering is detected; the exit frees silent sessions |
| `tests/data_path.rs` | real nodes, with in-memory devices instead of TUN | the full packet path, exit policy and anti-spoofing; the status socket |
| `scripts/netns-test.sh` | real TUN devices, routes and NAT in network namespaces (needs root) | identity swapping as seen by a web server, exit policy, kill switch, reconnect, a silently frozen exit, route cleanup, an exit behind NAT |
