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
| Every user's IP is published in the DHT as an exit (a consequence of lend-to-use), so anyone can list dvpn users. | None; it's what lending requires. It also means a complaint about an exit IP can be checked against the public exit list. | **Inherent** |
| The bypass rule matches the listen port (4001) as a source port for any local process, so an app binding that port bypasses the tunnel. | Only root-run or deliberately configured apps bind a fixed source port. | **Accepted** |
| Running `dvpn` from a user-writable build directory under sudo means whoever can write that file gets root. | Use the installed `/usr/local/bin/dvpn` (root-owned) day to day. | **Documented** |
| DHT query responses can still contain addresses other peers advertised. | Identify addresses are filtered (§3.8); responses come from libp2p's Kademlia and are not filtered yet. | **Partially mitigated** |
| "Lend to use" is enforced only by the official client; a modified client can use the network without lending. | Exits can't verify it without de-anonymising clients (§3.9). | **Inherent** |
| Every user is an exit, so every user carries an exit operator's legal exposure. | Consent required once; restrictive exit policy; lower default limits for `connect`. | **Partially mitigated**. The software cannot remove it. |
| libp2p dials that don't reuse the listen port go through our own tunnel while connected. They still work, just with an extra hop. | Replies from the listen ports, lent traffic and the entry relay bypass the tunnel. | **Partially mitigated** |
| An exit's `kind` (dedicated or user) is self-declared. A node can claim to be dedicated to attract clients. | Signed with the rest of the record. It only orders exits that are all equally untrusted. | **Inherent** |
| Max-ping mode narrows the set of exits a client uses, which makes its choice more predictable than random mode. | The pick is random within the limit, not the fastest. Random mode stays the default. | **Partially mitigated** (user's trade-off) |
| Max-ping test circuits briefly use a session slot on each probed exit, and the entry relay sees several circuits open at once. | At most 8 probes per tier; unused test circuits close immediately. | **Partially mitigated** |
| The bypass table holds the default route from when lending started. Changing networks (e.g. a different Wi-Fi) while running leaves it stale. | Restart `dvpn` after changing networks. | **Unmitigated** |

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
- `connect` always lends as well (§3.9): no circuit is built until this machine's own
  exit is usable by others.
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
  - That only works if `/etc/resolv.conf` points at resolved's stub (`127.0.0.53`).
    Otherwise queries go to the local resolver, outside the tunnel, so the client
    warns in the log, the TUI and `dvpn status`.
- IPv4 only in MVP; IPv6 is blackholed while connected. If the blackhole can't be
  installed and the host has an IPv6 default route, connecting is refused (fail
  closed).
- **Inbound firewall** (`ip dvpn-client`, installed with the routes; failure to install
  refuses the connection): on `dvpn0`, only `established,related` is accepted. The
  exit is untrusted and could otherwise open connections to services listening on
  the client.
- **Kill switch.**
  - Protection starts when the routes are installed, after the first circuit.
    Before that, traffic goes out normally. `protected` in `dvpn status` and
    "Not protected yet" in the TUI say so. The routes can't go in earlier, because
    the client's first DHT discovery needs direct connectivity.
  - From then on, if the circuit drops, routes remain and packets are dropped until a
    new circuit is built.
- **Teardown.** Everything is reverted when `connect` or the TUI stops, on SIGINT,
  SIGTERM or SIGHUP (closing the terminal). The signal handlers are installed before
  any system change.
  - After SIGKILL or a crash, the next start removes the leftovers, unless another
    dvpn runs in the same network namespace.
  - The original `ip_forward` is kept in `/run/dvpn-ip-forward-<netns>` so it can be
    restored then.

### 3.6 Exit (`dvpn run --exit`, and part of every `dvpn connect`)
- Requires explicit consent the first time it is enabled (`--accept-exit-risk`, or
  the TUI consent screen). The notice (`LENDING_WARNING` in `src/lend.rs`) is
  deliberately calm, but it must stay accurate:
  - it states that complaints about misuse may reach the lender first, and that some
    providers forbid sharing a connection;
  - it claims only what the exit policy and logging actually do.
- TUN `dvpn-exit` at `10.77.0.1/16`, IPv4 forwarding, nftables masquerade from
  `10.77.0.0/16` to the WAN interface (`--wan`, default: the default route's device).
  - Set up by the binary when lending starts and removed when it stops (`src/lend.rs`),
    in the same way routes are. It refuses to start if a `dvpn` table already
    exists.
  - After a crash or `kill -9`, `scripts/exit-teardown.sh` removes the leftovers.
    `scripts/exit-setup.sh` remains for operators who want to inspect or apply the
    rules by hand.
- **Exit policy**, enforced in userspace before a packet is written to the TUN:
  - deny RFC1918, loopback, link-local, CGNAT, multicast, reserved ranges, and every
    network the exit host is attached to, including its own addresses. This keeps
    clients away from the operator's LAN and from services on the exit host.
  - deny TCP 25 (SMTP), and non-first TCP fragments (their port can't be checked),
  - extra networks via `--exit-deny <cidr>`,
  - anti-spoofing: a packet's source IP must equal the circuit's assigned IP, otherwise
    it is dropped.
- Limits: max sessions (`--exit-max-sessions`) and bandwidth per session and direction
  (`--exit-rate-mbps`).
  - Defaults are 64 sessions at 20 Mbit/s for `run --exit`.
  - Defaults are 16 sessions at 10 Mbit/s for `connect`, to protect the user's own
    connection.
- **Sessions per relay** are capped at max/4 (minimum 2). Exits can't identify clients,
  but this stops a single relay, and so a single client, from taking every slot.
- The nftables table repeats the essential rules as a second layer, and adds one:
  nothing may start a connection *towards* clients through `dvpn-exit` (only
  `established,related`).
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
  - libp2p error messages embed peer addresses. Every one we turn into text (dial
    errors, stream errors, listen errors, relay circuit addresses) goes through
    `addrs::redact` first, because it can reach logs, the TUI and `dvpn status`.
- **Untrusted addresses.** A relay dials only public or relay-circuit addresses from a
  client's splice request, and only those are taken from peers' identify info into
  the DHT. Otherwise a client or peer could make nodes connect to their own loopback
  or LAN. `--allow-private-addrs` lifts this for LAN-only networks.
- No telemetry and no phone-home.

### 3.9 Lend to use
Using the network requires lending to it: `dvpn connect` and the TUI always run an
exit too, and there is no way to connect without one.

- **Readiness.** Lending is *ready* when all of these hold:
  - the forwarder runs,
  - our exit record is published and still valid,
  - we are reachable: directly (public, or confirmed by AutoNAT) or through a Circuit
    Relay v2 reservation.
- **Gate.** The client builds no circuit until lending is ready, and keeps waiting
  for as long as it takes.
  - While connected, it checks every 5 s.
  - If lending stays down for 2 min, it closes the circuit, keeps the kill-switch
    routes so traffic is blocked, and reconnects once lending is back.
  - Rebuilding a circuit never waits on readiness, so lending and the tunnel can't
    deadlock.
- **Routing.** Lending must not depend on our own tunnel. Policy routing
  (wg-quick style) sends two kinds of traffic via the original default route
  (table 7700):
  - packets arriving on `dvpn-exit` (lent traffic),
  - packets from the node's listen ports (replies to peers that dial us, and libp2p
    dials that reuse the listen port).

  Each gets `lookup main suppress_prefixlength 1` (pref 7700), so LAN and host routes
  still apply, then `lookup 7700` (pref 7701). The client's `/1` routes therefore never
  capture lent traffic, even while its own tunnel is blocked.
- **Address collisions.** Every exit hands out addresses from `10.77.0.0/16`, so a
  remote exit could assign us an address our own exit has leased.
  - Leases start at a random point.
  - Our tunnel address is reserved in our own pool.
  - A circuit whose address is already leased locally is dropped and retried.
- **Enforcement is client-side only.** An exit can't check that a client also
  lends without learning who the client is, which Noise_NK deliberately prevents
  (§3.4). A modified client can skip lending. Honest clients make freeloading less
  common, but it can't be prevented.

### 3.10 Exit selection
- **Tiers.** Each exit record carries a signed, self-declared `kind`:
  - `Dedicated`: from `dvpn run --exit`.
  - `User`: from `dvpn connect`, a user lending while connected.

  Clients choose among dedicated exits. They use another user's exit only when no
  dedicated exit fits the selection mode. While on a user's exit, the client checks
  every 30 s for a dedicated exit. When one can be built it switches
  (make-before-break), without a gap.
- **Random mode** (default, `connect` without `--max-ping`): any exit in the tier, picked
  uniformly at random. This is the most private mode, since the choice reveals nothing
  about the client.
- **Max-ping mode** (`--max-ping <ms>`):
  - **Test circuits.** Up to 8 random candidates from the tier get a test circuit
    (client → entry relay → exit), opened in parallel. Through each, 3 encrypted
    keepalives are timed and the fastest counts.
  - **Exits never see the client's IP.** That rules out pinging exits directly,
    since every probed exit would learn the IP and could link it to the session
    opened moments later.
  - **The pick is random.** One exit within the limit is picked uniformly at random,
    not simply the fastest, so repeated connections show no pattern. Its test
    circuit becomes the connection, and the other test circuits close.
  - **Reporting.** The result is shown in `dvpn status` (`probe`), and in the log as
    "*n* of *m* dedicated exits within *x* ms (fastest *y* ms)".
  - **If nothing qualifies,** in either tier, the client doesn't connect: it reports
    the fastest exit it found and retries with backoff.
- The mode is read before every circuit attempt, so it can be changed while running
  (used by the TUI).

### 3.11 TUI (`sudo dvpn tui`)
- A single process runs the node, lending and the VPN client, and draws a dashboard
  with ratatui and crossterm. It is built the same way as `connect` (`start_session` in
  `main.rs`), so the two can't drift apart.
- **Consent.** The first-run consent screen replaces `--accept-exit-risk`. Declining
  quits without changing anything.
- **Lending** runs for the whole session.
- **The VPN client** runs as a task. Disconnecting aborts it, and dropping it restores
  routes and DNS exactly as Ctrl-C does for `connect`.
- **Quitting** (`q`, Ctrl-C or SIGTERM) disconnects first, then stops lending, which
  restores the firewall and policy routes, then stops the node.
- **Selection mode** lives in the shared state that the client reads before every
  circuit, so changing it takes effect at the next reconnect or switch to a dedicated
  exit.
- **Measurements.** `measure_exits` probes the exits once (§3.10); the count within
  the limit is then recomputed locally as the limit changes, without probing again.
- **Logs** go to an in-memory ring buffer (500 lines) shown in the log panel, with the
  same filter and redaction as on stderr.
- **Rendering** is a pure function of a `View` struct, tested with ratatui's
  `TestBackend`.
- **Starting it.** `dvpn` with no command is `dvpn tui`.
  - Started without root, `tui`, `install` and `uninstall` re-run themselves as
    `sudo <same binary> <same arguments>`, and say so first. Other commands never
    escalate.
  - The first run creates the identity. Any other identity problem, such as wrong
    permissions, still stops it.
- **Install.** After consent, the TUI offers once to install the command
  (`src/install.rs`).
  - It copies the running binary to `/usr/local/bin/dvpn`, mode 0755, writing a
    temporary file and renaming it so the copy is atomic. That directory is on
    sudo's `secure_path`.
  - It is a copy rather than a link, so it survives moving or rebuilding the source.
    Updating it means running `dvpn install` again.
  - Declining is remembered in the data directory.

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
scripts/         exit-setup.sh / exit-teardown.sh / netns-test.sh (root harness) /
                 netns-demo.sh (try the TUI) / netns-lib.sh (shared namespace helpers)
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
| `ratatui` | 0.29.0 | TUI rendering (M4b) |
| `crossterm` | 0.28.1 | terminal input for the TUI (`event-stream`), same version ratatui uses |
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

1. Architecture: 2 hops, Noise_NK end-to-end, relaying on by default. Exits were
   opt-in; since M4 every connecting user also lends (§3.9), with consent required once.
2. Rust and the dependency list above (including the alpha `libp2p-stream`).
3. ~~The exit uses an operator-run nftables setup script; the binary never edits the
   firewall itself.~~ Superseded in M4: the binary installs and removes the exit's
   firewall and policy routes itself (§3.6, §3.9), so lending works from one command
   or the TUI.
4. M4: using the network requires lending (§3.9), enforced in the official client
   only. Single-process TUI run with `sudo dvpn tui`.
5. M4: exit selection (§3.10): latency is measured through test circuits, never by
   pinging exits directly; random mode is the default; other users' exits are used
   only when no dedicated exit fits the mode.
