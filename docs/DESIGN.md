# DecentralisedVPN — Design (Phase 1)

Status: **draft, awaiting approval**. No implementation code exists yet.

## 0. What "identity swapping" means here

Every participant runs the same binary. As a **client**, your traffic leaves the
internet from another peer's IP address instead of yours. As a **relay** (on by
default, opt-out) you forward opaque ciphertext between other peers. As an
**exit** (strictly opt-in, `--exit`) you lend your IP address to other users'
traffic. There is no central server, account, or authority.

## 1. Threat model

### Assets
- Contents of the user's traffic.
- The link "real IP of user ⇄ destinations visited".
- The node's private keys.

### Security goals
- G1: No relay, exit, or observer can read traffic the user sends *over TLS/HTTPS*;
  no relay or observer can read *any* of the user's traffic.
- G2: No single node learns both the user's IP and the user's destinations.
- G3: Private keys never leave the machine.
- G4: Nothing about traffic (contents, destinations, peer IPs) is written to disk or
  logs by default.

### Adversaries

| Adversary | Can learn / do | Cannot learn / do |
|---|---|---|
| **Malicious exit** | Destinations (IP:port), DNS queries, contents of non-TLS traffic, traffic volume/timing, the entry relay's IP. Can tamper with non-TLS traffic. Can drop traffic. | Client's IP or long-term identity (client is anonymous in the exit handshake). Contents of TLS traffic. |
| **Malicious entry relay** | Client's IP and node ID, which exit is used, ciphertext volume/timing. Can drop or delay traffic. | Destinations, contents (end-to-end encrypted to the exit). Cannot forge or modify packets undetected (AEAD). |
| **Colluding entry + exit** | Can correlate by timing and deanonymize the client. | Contents of TLS traffic. |
| **Passive local observer (ISP, Wi-Fi)** | That the user runs DecentralisedVPN, the entry relay's IP, traffic volume/timing. | Destinations, contents. |
| **Global passive observer** | Can correlate entry and exit traffic by timing → deanonymize. | Contents of TLS traffic. |
| **Sybil attacker** (runs many nodes) | Raises the probability of controlling both hops of a circuit; can poison/eclipse DHT lookups. | Cannot forge another node's signed records. |
| **Compromised bootstrap peer** | Learns the IP of nodes that bootstrap through it; can feed them a malicious peer set (eclipse). | Has no special authority: it's an ordinary peer. |
| **Malicious client (towards exits)** | Uses the exit's IP for abuse. Could try to reach the exit's LAN or spoof source IPs. | Blocked from private ranges and spoofing by exit policy (§3.6). |

### Honest limitations

| Limitation | Mitigation | Status |
|---|---|---|
| Exit sees and can modify plaintext (non-HTTPS) traffic and DNS. | Documented prominently; recommend HTTPS-only + DNS-over-HTTPS in the browser. | **Partially mitigated** (user behaviour) |
| Exit operators are legally exposed: abuse traffic appears to come from their IP. | Exit is opt-in only, with a warning at enable time; restrictive default exit policy (no SMTP, no private ranges); per-circuit rate limits. | **Partially mitigated**. The operator still carries liability; the software cannot remove it. |
| Timing correlation (colluding entry+exit or global observer). | Message size padding to fixed buckets; guard persistence reduces exposure over time. No cover traffic in MVP. | **Unmitigated** against a capable adversary |
| Sybil / eclipse attacks on discovery. | Disjoint Kademlia query paths, /16 subnet diversity between hops, signed records, guard persistence, multiple bootstrap sources. | **Partially mitigated**. A well-resourced attacker can still win. No decentralised system fully solves this without a cost or identity mechanism. |
| First-ever join needs one known peer address (or a LAN peer). | `--bootstrap` flag, config file, mDNS, cached peers from previous runs. | **Inherent** to any serverless network |
| 2 hops: a colluding entry+exit pair deanonymizes. | 3-hop circuits are planned for later. | **Unmitigated** in MVP |
| Entry relay learns the client uses the network. | None in MVP (no bridges/obfuscation). | **Unmitigated** |
| Traffic leaks if the tunnel drops or for IPv6. | Kill switch: route stays on TUN and packets are dropped while reconnecting; IPv6 blackholed while connected. | **Mitigated** (M3) |
| The client's own DHT lookups connect directly to arbitrary peers, and one of them may be its exit. That exit then sees the client's IP doing DHT traffic and could try to correlate it with circuit timing. | Once connected, every lookup (including candidate refreshes) goes through the tunnel; only the initial discovery before the first circuit is direct. | **Partially mitigated** (M3) |
| An exit behind NAT is reached through Circuit Relay v2, whose libp2p default limits are 2 min / 128 KiB per relayed connection, unless DCUtR hole punching upgrades it to a direct connection. | DCUtR is enabled. In practice a NATed exit holds outbound connections to the relays, which carry the splice directly. | **Partially mitigated** |
| The kill switch only protects while `dvpn connect` runs. If the process is killed or crashes, the TUN device vanishes and normal routing resumes. | Reconnects forever instead of giving up; Ctrl-C restores routes cleanly. | **Partially mitigated** |
| A silently vanished exit (host gone, no TCP reset) is only noticed when the transport times out. | End-to-end tunnel keepalive (§3.4): detected within 30–36 s; the exit also frees silent sessions after 60 s. | **Mitigated** |
| `connect` and `run --exit` run as root for their whole lifetime. | None yet (no privilege drop after setup). | **Unmitigated** |

## 2. Architecture overview

```
 Client C                     Entry relay R                  Exit E                 Internet
 ┌──────────┐  libp2p (Noise)  ┌──────────┐  libp2p (Noise)  ┌──────────┐   NAT
 │ TUN dvpn0│══════════════════│  splice  │══════════════════│ TUN+NAT  │──────────▶ dest
 └──────────┘                  └──────────┘                  └──────────┘
      └──────────── inner Noise_NK session (C ⇄ E, end-to-end) ─────────┘
 R sees: C's IP, E's ID, ciphertext       E sees: R's IP, destinations, never C
```

Layers:
1. **Transport** (libp2p): TCP + QUIC, Noise XX encryption, Yamux multiplexing.
2. **Discovery**: Kademlia DHT + mDNS + bootstrap list + peer cache.
3. **Reachability**: AutoNAT, DCUtR hole punching, Circuit Relay v2 fallback.
4. **Circuits**: a splice through R, with an end-to-end Noise_NK session to E.
5. **Tunnel**: TUN device on the client; TUN + NAT + policy on the exit.

## 3. Components

### 3.1 Identity
- `dvpn init` generates:
  - an Ed25519 libp2p identity keypair (node ID), and
  - an X25519 static keypair for the exit handshake (used only if the node is an exit).
- Stored in `$XDG_DATA_HOME/dvpn/` (default `~/.local/share/dvpn/`): directory `0700`,
  key files `0600`. Refuse to start if permissions are looser.
- Keys are zeroized in memory on drop (`zeroize`) and never logged.

### 3.2 Discovery (no central server)
- **Kademlia DHT** (`libp2p-kad`), with `disjoint_query_paths` enabled to resist eclipse
  attacks on lookups.
- **mDNS** for zero-config discovery on the LAN.
- **Bootstrap peers**: supplied via `--bootstrap <multiaddr>` or the config file. No
  hardcoded authority; any peer can bootstrap anyone.
- **Peer cache**: known-good peer addresses are saved locally (`0600`) so later runs need
  no bootstrap. Can be disabled with `--no-peer-cache`.
- **Signed records** published in the DHT:
  - `ExitRecord { peer_id, noise_static_pubkey, exit_policy_summary, expires_at }`,
    signed by the node's Ed25519 key, under provider key `dvpn/exit/v1`.
  - Relays advertise under provider key `dvpn/relay/v1`.
  - Records expire after 1 h and are republished. Records with an invalid signature,
    or whose `peer_id` doesn't match the signer, are dropped.

### 3.3 NAT traversal
- **AutoNAT** detects whether the node is publicly reachable.
- **DCUtR** does hole punching between NAT'd peers.
- **Circuit Relay v2** (libp2p) is the fallback so NAT'd nodes remain reachable for
  control traffic. Exits and entry relays should be publicly reachable or hole-punched;
  circuits are not built on top of relay-v2 hops in MVP.

### 3.4 Circuit construction (2 hops)
1. C selects an exit E from `dvpn/exit/v1` records and an entry relay R from
   `dvpn/relay/v1`, requiring:
   - R ≠ E,
   - R and E in different IPv4 /16 subnets.

   R is a **guard**: once chosen it is persisted and reused for 30 days unless
   unreachable. This limits how often a client is exposed to a fresh, possibly
   malicious, entry.
2. C opens a libp2p stream `/dvpn/splice/1` to R, containing `SpliceRequest { exit: PeerId }`.
3. R dials E, opens `/dvpn/exit/1`, and pipes bytes in both directions without
   interpreting them. R forwards nothing about C.
4. Through that pipe, C runs a **Noise_NK_25519_ChaChaPoly_BLAKE2s** handshake (`snow`)
   against E's static key from the signed ExitRecord.
   - NK means C has no static key, so E cannot identify or link the client.
   - Ephemeral keys provide forward secrecy.
5. E answers with an `ExitHello { assigned_ip: 10.77.x.y, mtu }` inside the Noise session.
6. Data phase: IP packets are carried as Noise transport messages. Each message is:
   - length-prefixed,
   - padded to size buckets (256 / 512 / 1024 / 1500 bytes) to reduce size
     fingerprinting,
   - AEAD-protected, so tampered, replayed or reordered messages are rejected and the
     session is torn down.
7. Keepalive: an empty packet, which padding makes indistinguishable from any small
   packet.
   - C sends one after 10 s without sending or receiving anything. It checks every
     4–6 s at random, so keepalives have no fixed rhythm.
   - E answers each keepalive with one, through the session's rate limit. The reply is
     the same size as the request, so there is no amplification.
   - C treats the circuit as dead after 30 s with nothing from E, and reconnects.
     This catches exits that vanish without closing anything (power loss, a dropped
     link).
   - E drops a session after 60 s with nothing from C, freeing its session slot and
     IP address.

This composes standard, audited building blocks (libp2p Noise, the Noise Framework via
`snow`). **No custom cryptographic primitives or handshakes are written.**

### 3.5 Client tunnel (`dvpn connect`)
- Creates TUN `dvpn0` with the IP assigned by the exit; requires `CAP_NET_ADMIN`.
- The first circuit is retried with backoff (1 s up to 30 s), with a fresh DHT lookup
  between attempts. The DHT can still hold records of exits that went offline until
  they expire. No routes exist until the first circuit is up.
- Routing:
  - `0.0.0.0/1` and `128.0.0.0/1` via `dvpn0`, which override the default route
    without replacing it,
  - a host route to the entry relay's IP via its original route, to avoid a routing loop.
    When reconnecting, each candidate relay is exempted the same way.
- DNS: `--dns` (default 9.9.9.9) is set as the only resolver for `dvpn0` via
  systemd-resolved (`resolvectl`, routing domain `~.`), so queries go through the
  tunnel. The exit can see them. `--dns none` leaves DNS alone.
- IPv4 only in MVP; IPv6 is blackholed while connected.
- Kill switch: if the circuit drops, routes remain and packets are dropped until a new
  circuit is built.
- All route changes are reverted on exit (including on Ctrl-C).

### 3.6 Exit (`dvpn run --exit`)
- Opt-in, with an explicit warning about legal exposure the first time it is enabled.
- TUN `dvpn-exit` at `10.77.0.1/16`, IPv4 forwarding, nftables masquerade from
  `10.77.0.0/16` to the WAN interface.
  - This needs root and changes system state, so it is done by a separate reviewed
    script (`scripts/exit-setup.sh` / `exit-teardown.sh`) that the operator runs. The
    binary itself never edits firewall rules.
- **Exit policy**, enforced in userspace before a packet is written to the TUN:
  - deny RFC1918, loopback, link-local, CGNAT, multicast, reserved ranges, and every
    network the exit host is attached to, including its own addresses. This keeps
    clients away from the operator's LAN and from services on the exit host.
  - deny TCP 25 (SMTP), and non-first TCP fragments (their port can't be checked),
  - extra networks via `--exit-deny <cidr>`,
  - anti-spoofing: a packet's source IP must equal the circuit's assigned IP, otherwise
    it is dropped.
- Limits: max sessions (`--exit-max-sessions`, default 64) and bandwidth per session
  and direction (`--exit-rate-mbps`, default 20).
- `exit-setup.sh` repeats the essential rules in nftables as a second layer:
  - forward only to the WAN interface,
  - no private destinations or SMTP,
  - drop all input from the TUN to the host.

### 3.7 Relay
- Enabled by default with caps: 64 concurrent splices, and 20 Mbit/s per splice and
  direction (`--relay-rate-mbps`). Disable with `--no-relay`.
- A relay only ever sees ciphertext between two peers and does not expose its IP as a
  traffic source on the internet.

### 3.8 Local control & privacy
- `dvpn status` talks to the running node over a Unix socket at
  `<data-dir>/control.sock` (`0600`, inside the `0700` data directory).
  - If that path is too long for a Unix socket, it uses
    `$XDG_RUNTIME_DIR/dvpn-<hash>.sock` instead.
  - It never uses a world-writable directory such as `/tmp`.
  - Only one node per data directory can run at a time.
- Default logging is `info` with no peer IPs, destinations or packet data. `--debug`
  enables more detail, but those fields are still redacted.
- No telemetry and no phone-home.

## 4. Stack

**Language: Rust (edition 2024)**
- Rust 1.93.1 is already installed and Go is not.
- Memory safety without GC suits a packet-forwarding daemon.
- rust-libp2p is mature (Kademlia, DCUtR, AutoNAT, Relay v2, Noise, QUIC).
- `snow` is a well-established Noise implementation.

Single crate, one binary `dvpn`:

```
src/
  main.rs        CLI (init | run | connect | status)
  identity.rs    key generation, storage, permission checks
  records.rs     signed ExitRecord / relay records
  node.rs        libp2p swarm + behaviour composition
  discovery.rs   kad, mdns, bootstrap, peer cache
  circuit.rs     splice protocol + Noise_NK client/exit sessions
  framing.rs     length-prefix + padding buckets
  tunnel.rs      client TUN + routing + kill switch
  exit.rs        exit TUN, policy, IP assignment, anti-spoofing
  control.rs     Unix-socket status API
tests/           multi-node integration tests
scripts/         exit-setup.sh / exit-teardown.sh / netns test harness
```

### Dependency list (exact versions verified on crates.io, 2026-10-31)

| Crate | Version | Purpose |
|---|---|---|
| `libp2p` | 0.57.1 | features: `tokio, tcp, quic, noise, yamux, kad, mdns, identify, autonat, dcutr, relay, ping, macros, ed25519, serde` |
| `libp2p-stream` | 0.5.0-alpha | raw byte streams for `/dvpn/splice/1` and `/dvpn/exit/1` (compatible with libp2p-swarm 0.48; **alpha**, see note) |
| `snow` | 0.10.0 | Noise_NK end-to-end session client⇄exit |
| `tokio` | 1.54.1 | async runtime (`full`) |
| `futures` | 0.3.34 | stream utilities |
| `tun-rs` | 2.8.16 | TUN device (`async` feature) |
| `ipnet` | 2.12.2 | CIDR handling for exit policy / IP pool |
| `serde` | 1.0.229 | (`derive`) record & config serialization |
| `postcard` | 1.1.3 | compact binary wire encoding for records/control messages |
| `serde_json` | 1.0.154 | config file + `status` output |
| `zeroize` | 1.9.1 | wipe secret keys from memory |
| `clap` | 4.6.7 | CLI (`derive`) |
| `directories` | 6.0.0 | XDG data/config paths |
| `tracing` | 0.1.44 | logging |
| `tracing-subscriber` | 0.3.23 | log output / filtering |
| `anyhow` | 1.0.104 | error handling (binary) |
| `thiserror` | 2.0.21 | typed errors (modules) |
| `tempfile` | 3.27.0 | **dev-only**: isolated data dirs in tests |

Notes:
- `libp2p-stream` is published as alpha. The alternative is a hand-written
  `NetworkBehaviour`/`ConnectionHandler` (~300 lines, no extra dependency). I recommend
  the crate for MVP speed.
- No separate Ed25519/X25519 crates: libp2p-identity handles node keys and `snow` handles
  X25519 internally.
- `bincode` deliberately not used (3.0.0 is a non-functional release); `postcard` is used
  instead.

## 5. Scope

### MVP (Phase 2)
- **M1:** `init`, identity storage with permission checks, `run` with DHT + mDNS +
  bootstrap + peer cache. Test: 3 local nodes discover each other.
- **M2:** signed records, splice protocol, Noise_NK client⇄exit session, framing/padding.
  Tests:
  - a relay cannot decrypt the payload,
  - the exit never receives the client's IP or ID,
  - tampered packets are rejected,
  - a node without `--exit` refuses exit streams.

  No root needed (in-memory endpoints instead of TUN).
- **M3:** client TUN + routing + kill switch, exit TUN + policy + anti-spoofing,
  `status`, exit setup scripts. Test: end-to-end through Linux network namespaces
  (client / relay / exit / "internet"), proving traffic leaves from the exit's address.
  **Requires sudo; will ask first.**

### Later (not in MVP)
- 3-hop circuits.
- Cover traffic / timing defences.
- IPv6.
- Exit "family" declarations.
- Bandwidth measurement and weighting.
- Pluggable transports / bridges.
- macOS / Windows / mobile.
- GUI.
- Incentives.

## 5a. Implementation notes (M1–M3)

- **Reachability modes** (`--reachability`):
  - `auto` (default): AutoNAT decides. Kademlia serves the DHT only once an external
    address is confirmed. Behind NAT, the node reserves up to 2 Relay v2 slots, and a
    failed relay is retried after 30 s.
  - `public`: the operator asserts the node is reachable, so its usable listen addresses
    are treated as confirmed external addresses. This also enables its Relay v2 server,
    which libp2p keeps disabled until an external address is confirmed.
  - `private`: always reserve relay slots; never serve the DHT.
- **LAN-only networks:** AutoNAT ignores private addresses by default, so at least one
  node needs `--reachability public --allow-private-addrs`.
- **DHT hygiene:** every node validates inbound records (`StoreInserts::FilterBoth`).
  - Only `/dvpn/exit-record/v1/<peer>` records are stored, and only when they are signed
    by `<peer>`, unexpired, at most 70 min in the future, and newer than the stored copy.
  - Only `dvpn/exit/v1` and `dvpn/relay/v1` provider records are stored. Kademlia itself
    rejects provider announcements made on behalf of another peer.
- **Records** use libp2p's `SignedEnvelope` (domain-separated Ed25519 signatures) rather
  than a custom signing format.
- **Exit records** carry the exit's blocked TCP ports as the policy summary.
- **`dvpn connect`** runs a client-only node (`Reachability::Outbound`): no listener,
  no DHT serving, no relay reservations, and no relaying.
- **Route and address changes** shell out to `ip` and `resolvectl` instead of using
  netlink directly. This added no dependencies.
  - Because of this, `connect` and `run --exit` need real root (`sudo`): file
    capabilities set with `setcap` don't pass to child processes.
  - Inside a network namespace, `resolvectl` still talks to the host's
    systemd-resolved, so use `--dns none` there.
- **Testing:** `scripts/netns-test.sh` runs real TUN devices, routes and NAT in
  throwaway namespaces. It covers both a public exit and an exit behind NAT.

## 6. Decisions (approved)

1. Architecture: 2 hops, Noise_NK end-to-end, exit opt-in, relaying on by default.
2. Rust and the dependency list above (including the alpha `libp2p-stream`).
3. The exit uses an operator-run nftables setup script; the binary never edits the
   firewall itself.
