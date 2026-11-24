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
| **BitTorrent DHT nodes near the rendezvous keys** (§3.2) | See which IPs look up or announce dvpn's keys; can answer lookups with only their own nodes (eclipse of a newcomer). | Can't impersonate dvpn peers: a found address is only a first contact, authenticated by libp2p and then replaced by dvpn's own DHT. |
| **Malicious client (towards exits)** | Uses the exit's IP for abuse. Could try to reach the exit's LAN or spoof source IPs. | Blocked from private ranges and spoofing by exit policy (§3.6). |

### Honest limitations

| Limitation | Mitigation | Status |
|---|---|---|
| Exit sees and can modify plaintext (non-HTTPS) traffic and DNS. | Documented prominently; recommend HTTPS-only + DNS-over-HTTPS in the browser. | **Partially mitigated** (user behaviour) |
| Exit operators are legally exposed: abuse traffic appears to come from their IP. | Exit is opt-in only, with a warning at enable time; restrictive default exit policy (no SMTP, no private ranges); per-circuit rate limits. | **Partially mitigated**. The operator still carries liability; the software cannot remove it. |
| Timing correlation (colluding entry+exit or global observer). | Message size padding to fixed buckets; guard persistence reduces exposure over time. No cover traffic in MVP. | **Unmitigated** against a capable adversary |
| Sybil / eclipse attacks on discovery. | Disjoint Kademlia query paths, /16 subnet diversity between hops, signed records, guard persistence, multiple bootstrap sources. | **Partially mitigated**. A well-resourced attacker can still win. No decentralised system fully solves this without a cost or identity mechanism. |
| First-ever join needs one reachable peer. | Rendezvous on the BitTorrent DHT (§3.2): lending nodes that others can reach announce themselves there, and a node with no peers looks them up. Also invite links (`dvpn://join?peer=…`) that any user can copy from the app and send, `--bootstrap`, the config file, cached peers from previous runs, mDNS with `--mdns`. No list is built in: there's no authority to run it. | **Mitigated**. It still needs at least one reachable lending node somewhere, and depends on the BitTorrent DHT being reachable (some networks block it) |
| A stable node ID would let peers, relays and DHT observers recognise a computer across days and networks. | Users' nodes (`connect`, the service) use a new identity every session: on every start, restart, network change and change of public address (§3.1). mDNS, which announces the node to its LAN, is off unless `--mdns` is given. | **Mitigated**. The guard relay is kept across sessions on purpose (§3.3), so it can still link the networks a user connects from. |
| 2 hops: a colluding entry+exit pair deanonymizes. | 3-hop circuits are planned for later. | **Unmitigated** in MVP |
| Entry relay learns the client uses the network. | None in MVP (no bridges/obfuscation). | **Unmitigated** |
| Traffic leaks if the tunnel drops or for IPv6. | Kill switch (§3.5): a firewall lets nothing leave except through the tunnel, to the LAN or as dvpn's own traffic, from connect until disconnect; IPv6 is refused and blackholed. | **Mitigated** |
| Routes more specific than ours, pushed by a rogue DHCP server (option 121) or router advertisement ("TunnelVision"), steer traffic around the tunnel. | The kill switch filters by outgoing interface, not by route: such traffic is refused. A LAN only counts as local up to a /16. | **Mitigated** (traffic is blocked, not leaked) |
| The client's own DHT lookups connect directly to arbitrary peers, and one of them may be its exit. That exit then sees the client's IP doing DHT traffic and could try to correlate it with circuit timing. | Once connected, every lookup (including candidate refreshes) goes through the tunnel; only the initial discovery before the first circuit is direct. | **Partially mitigated** (M3) |
| An exit behind NAT is reached through Circuit Relay v2, whose libp2p default limits are 2 min / 128 KiB per relayed connection, unless DCUtR hole punching upgrades it to a direct connection. | DCUtR is enabled. In practice a NATed exit holds outbound connections to the relays, which carry the splice directly. | **Partially mitigated** |
| The kill switch outlives the client but not the firewall table: a reboot clears it. | The service keeps it from connect until disconnect and restarts a failed client or node by itself. After a crash, the table stays and the restarted service reconnects. Ctrl-C (or a disconnect) removes it cleanly. | **Mitigated** for the service; `dvpn connect` run by hand protects while it runs |
| If the service crashes repeatedly while connected, traffic stays blocked until it's back (or the machine restarts). | Disconnect in the app, or `sudo systemctl restart dvpn`; removing the package removes the firewall. | **Accepted**: failing closed is the point |
| The kill switch recognises dvpn's own traffic by its cgroup. For `dvpn connect` run by hand, that is the whole session scope it runs in, so other programs started from the same terminal session pass too. | The service has its own cgroup (`dvpn.service`). Without cgroup v2, only routes protect, and the app says so. | **Accepted** (operator tool) |
| A silently vanished exit (host gone, no TCP reset) is only noticed when the transport times out. | End-to-end tunnel keepalive (§3.4): detected within 30–36 s; the exit also frees silent sessions after 60 s. | **Mitigated** |
| `connect` and `run --exit`, started by hand, run as root for their whole lifetime. | The service, which is how people use dvpn, isn't root: it runs as the system user `dvpn` with `CAP_NET_ADMIN` as its only privilege, sandboxed by systemd (read-only system directories, no home directories), and the desktop app runs unprivileged (§3.12). Taking over the service gives network administration, not the machine. | **Mitigated** for the service; the commands are for servers and tests |
| Whoever is signed in at this computer, and members of the `dvpn` group, can turn the VPN and lending on or off, and add bootstrap peers. | Only a fixed set of actions passes through the socket (§3.12). Administrators can narrow the polkit action `dev.dvpn.control`. | **Accepted**: like NetworkManager's VPN control |
| Every user's IP is published in the DHT as an exit (a consequence of lend-to-use), so anyone can list dvpn users. | None; it's what lending requires. It also means a complaint about an exit IP can be checked against the public exit list. | **Inherent** |
| The bypass rule matches the listen port (4001) as a source port for any local process, so an app binding that port bypasses the tunnel. | With the kill switch filtering output, such packets are refused unless they come from dvpn itself or answer a connection a peer started. | **Mitigated** |
| Running `dvpn` from a user-writable build directory under sudo means whoever can write that file gets root. | Users never run it: the package installs it root-owned in `/usr/libexec/dvpn/` and only systemd starts it. Operators running `run --exit` by hand should install a root-owned copy. | **Documented** |
| DHT query responses can still contain addresses other peers advertised. | Identify addresses are filtered (§3.8); responses come from libp2p's Kademlia and are not filtered yet. | **Partially mitigated** |
| "Lend to use" is enforced only by the official client; a modified client can use the network without lending. | Exits can't verify it without de-anonymising clients (§3.9). | **Inherent** |
| Every user is an exit, so every user carries an exit operator's legal exposure. | Consent required once; users' exits only carry common services (a reduced port list, §3.6), which keeps out most traffic that draws complaints (file sharing, scanning, spam); lower default limits. | **Partially mitigated**. The software cannot remove it. |
| On another user's exit, services outside its port list (e.g. games, BitTorrent, some VoIP) don't work. | Such exits are a last resort: clients prefer dedicated exits, which forward every port but SMTP, and move to one as soon as it's up. The app says when a user's exit is in use. | **Accepted**: protects lenders |
| libp2p dials that don't reuse the listen port go through our own tunnel while connected. They still work, just with an extra hop. | Replies from the listen ports, lent traffic and the entry relay bypass the tunnel. | **Partially mitigated** |
| An exit's `kind` (dedicated or user) is self-declared. A node can claim to be dedicated to attract clients. | Signed with the rest of the record. It only orders exits that are all equally untrusted. | **Inherent** |
| The datagram path's packet layer is dvpn's own composition of standard primitives, not an established protocol. | Modelled on WireGuard's data packets (AEAD per packet, counters, replay window, key ratchet); unit tests cover tampering, replays, reordering and key changes. The handshake stays Noise. | **Partially mitigated**: needs an external review |
| Networks that block UDP (some company, hotel and public Wi-Fi) get no datagram path. | Packets stay on the circuit's stream, which works as before, just with TCP-over-TCP's stalls on lossy links. | **Mitigated** (graceful fallback) |
| Max-ping mode narrows the set of exits a client uses, which makes its choice more predictable than random mode. | The pick is random within the limit, not the fastest. Random mode stays the default. | **Partially mitigated** (user's trade-off) |
| Max-ping test circuits briefly use a session slot on each probed exit, and the entry relay sees several circuits open at once. | At most 8 probes per tier; unused test circuits close immediately. | **Partially mitigated** |
| Lending is built for the network it started on (WAN interface, local networks, bypass table). | Lending checks every 10 s; on a change it is reported down and the service restarts it, and the VPN with it, for the new network (§3.9). `dvpn run --exit` and `dvpn connect` only report it. | **Mitigated** for the service |
| An exit behind a home router has a public address that isn't on any of its interfaces; through hairpin NAT, clients could reach the router or port forwards into the lender's LAN. | The exit refuses the addresses peers see it at (§3.6). | **Mitigated** |
| A DHT node keeps a limited number of providers per key and ignores newcomers once full, so whoever registers first could fill the exit and relay lists. | Provider keys are split into 8 shards, each holding 64 providers, and a node may only announce itself in its own shard (§3.2). Filling them takes hundreds of always-on nodes. | **Partially mitigated** (Sybil, see above) |

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
2. **Discovery**: Kademlia DHT + mDNS + bootstrap list + peer cache + rendezvous on the BitTorrent DHT.
3. **Reachability**: AutoNAT, DCUtR hole punching, Circuit Relay v2 fallback.
4. **Circuits**: a splice through R, with an end-to-end Noise_NK session to E.
5. **Tunnel**: TUN device on the client; TUN + NAT + policy on the exit.

## 3. Components

### 3.1 Identity
- **Users' nodes** (`connect` and the service) generate a new identity in memory for
  every session: a new node ID and exit key on every start, restart and network change.
  Nothing links one session to the next on the network.
  - A new public address with nothing changed on the host (an internet provider
    reassigning it, often daily) also starts a new session. It counts once two peers
    report the same new address, and at most once per 30 minutes, so a router
    alternating between uplinks can't keep the service restarting. The exit record, signed with
  that session's key, goes with it.
- **Servers** (`run`: bootstrap peers and dedicated exits) keep a stable identity, since
  others reach them by it (`/p2p/<id>` in bootstrap addresses). `dvpn init` generates
  an Ed25519 libp2p identity keypair (node ID).
- An exit's X25519 static key for the handshake (§3.4) is never stored. Every node
  makes a new one when it starts and replaces it every 24 h, publishing the new one in
  its exit record right away, which the node ID signs. The replaced key is still
  accepted for 70 minutes, as long as records with it can be valid. A key stolen from
  a running exit thus lets an attacker impersonate it for a day at most, and no key
  can be read from the disk. `exit_static.key` files from earlier versions are deleted.
- Stored in `$XDG_DATA_HOME/dvpn/` (default `~/.local/share/dvpn/`): directory `0700`,
  key files `0600`. Refuse to start if permissions are looser.
- Keys are zeroized in memory on drop (`zeroize`) and never logged.

### 3.2 Discovery (no central server)
- **Kademlia DHT** (`libp2p-kad`), with `disjoint_query_paths` enabled to resist eclipse
  attacks on lookups.
- **mDNS** for zero-config discovery on the LAN, only with `--mdns`: it announces the
  node (and so that this computer runs dvpn) to everyone on the network.
- **Bootstrap peers**: supplied via `--bootstrap <multiaddr>` or the config file. No
  hardcoded authority; any peer can bootstrap anyone.
- **Invite links**: `dvpn://join?peer=<multiaddr>&peer=…` (at most 4 peers). The app
  shows one to copy: the user's bootstrap peers, then the relays it is connected to
  (servers with a stable ID and a public address), never the user's own node, whose
  ID changes every session. Anything that takes a bootstrap address (the app's field,
  `Action::AddBootstrap`) also takes a link and adds all its peers. The desktop file
  registers the `dvpn` scheme, so clicking a link opens the app with the link filled
  in; it is added only when the user confirms, since a stranger's link could lead to
  peers that show a newcomer a false view of the network.
- **Rendezvous on the BitTorrent DHT** (`src/rendezvous.rs`), for a first contact without
  any server of ours. It borrows the BitTorrent Mainline DHT, which millions of
  BitTorrent clients keep running (BEP 5), through the `mainline` crate.
  - *Keys.* `BLAKE2s("dvpn/rendezvous/v1/<shard>/<day>")` cut to 20 bytes, for 4 shards
    and the UTC day. They're opaque keys, not torrents.
  - *Searching.* A node whose routing table is still empty 10 s after starting (no peer
    cache, bootstrap peer or invite link worked) looks up today's and yesterday's keys.
    It dials up to 16 of the IP:port pairs it finds, over TCP and QUIC, without a peer
    ID. A peer that speaks dvpn's Kademlia joins the routing table (identify), and the
    node bootstraps from it. While nobody is found it searches again after 30 s,
    doubling up to 5 minutes. Connecting waits up to 60 s for a first peer.
  - *Announcing.* Only lending nodes announce, every 15 minutes, with their TCP listen
    port, in their own shard. They must be reachable: AutoNAT says so, or the public
    IP the DHT sees is on one of their own interfaces (a node alone in the network has
    nobody to run AutoNAT with). A user's node must also see the DHT report its real
    IP: on its own interface, or the one two dvpn peers confirmed. While connected, the
    DHT would see its exit's IP instead. A dedicated exit (`run --exit`) skips that
    check, since it never routes its own traffic through a tunnel.
  - *Privacy.* A lending node's IP is already public in its exit record (§1, "anyone can
    list dvpn users"), so announcing it adds no new exposure. A node that isn't lending
    never announces. Searching shows the node's IP to the few DHT nodes asked.
  - *Footprint.* Each search or announcement is a short-lived DHT client with a fresh
    node ID, closed when done. It never runs long enough for the library's adaptive
    mode to start serving the DHT (15 minutes), so dvpn nodes never store or serve
    strangers' torrent lists.
  - *Eclipse.* Nodes placed next to the keys could answer with only their own peers.
    The daily key change and the shards make that cost more, and dvpn's own DHT
    (disjoint paths, signed records) replaces the first contact at once. It's the same
    risk as a malicious bootstrap peer.
  - *Off switch.* "Find peers automatically" in the app (`config.json`
    `"rendezvous": false`), or `--no-rendezvous`.
- **Peer cache**: known-good peer addresses are saved locally (`0600`) so later runs need
  no bootstrap. Can be disabled with `--no-peer-cache`. Each save replaces it with the
  peers known now; if dvpn doesn't run for 30 days, its entries expire and the file is
  deleted, like an expired guard choice (§3.3), so other users' IPs don't stay on disk.
- **Signed records** published in the DHT:
  - `ExitRecord { peer_id, noise_static_pubkey, exit_policy_summary, expires_at }`,
    signed by the node's Ed25519 key. Exits announce themselves as providers of
    `/dvpn/exit/v2/<shard>`, relays of `/dvpn/relay/v2/<shard>`.
  - **Shards.** A node's shard is the last byte of its peer ID modulo 8, and DHT nodes
    store a provider only under its own shard. Lookups ask all 8 in parallel. With a
    single key, the 20 providers libp2p keeps per key by default (ignoring newcomers
    once full) would cap the network and hand it to whoever came first; with 8 shards
    of 64, filling them takes hundreds of always-on nodes.
  - An exit counts as published only once the record was stored and the provider
    entry announced; a failed attempt is retried after 30 s.
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
2. C opens a libp2p stream `/dvpn/splice/2` to R, containing
   `SpliceRequest { exit, addrs, datagrams }`.
3. R dials E, opens `/dvpn/exit/2`, sends E a `RelayHello` with E's half of the
   datagram offer (§3.4a), answers C with its half, and then pipes bytes in both
   directions without interpreting them. R forwards nothing about C.
4. Through that pipe, C runs a **Noise_NK_25519_ChaChaPoly_BLAKE2s** handshake (`snow`)
   against E's static key from the signed ExitRecord.
   - NK means C has no static key, so E cannot identify or link the client.
   - Ephemeral keys provide forward secrecy.
   - The prologue is `dvpn-circuit-v2` followed by E's peer ID, so the handshake is
     bound to the exit C meant to reach, not only to its key.
   - The first message carries only the protocol version: it is protected by the
     exit's static key alone (not forward-secret) and can be replayed, so nothing
     sensitive may ever go in it (a unit test enforces that it is one byte).
   - E tries its current key, then the one it replaced (§3.1).
5. E answers with an `ExitHello { assigned_ip: 10.77.x.y, mtu, datagram_keys }` inside
   the Noise session. That message is encrypted with keys from both ephemeral keys, so
   the datagram keys (§3.4a) are forward secret like the session's.
6. Data phase on the stream: IP packets are carried as Noise transport messages, until
   the datagram path works (§3.4a). Each message is:
   - length-prefixed,
   - padded to size buckets (256 / 512 / 1024 / 1362 bytes) to reduce size
     fingerprinting; the MTU is 1360,
   - AEAD-protected, so tampered, replayed or reordered messages are rejected and the
     session is torn down.
   - **Rekeying.** Each direction switches to a new key every 16384 messages (both
     sides count the same messages), so a key read later from an endpoint's memory
     decrypts only a window of a long session.
   - Length prefix and ciphertext go out in one write.
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
`snow`, ChaCha20-Poly1305 and BLAKE2s from RustCrypto). **No custom cryptographic
primitives or handshakes are written.** The datagram layer (§3.4a) is our own
composition of those primitives, modelled on WireGuard's data packets; it has not been
reviewed externally.

### 3.4a Datagram path
A stream delivers everything in order, so one lost packet holds back every packet
after it, and TCP connections inside the tunnel retransmit on top of the stream's own
retransmissions ("TCP over TCP"): stalls and collapsing throughput on lossy links,
and delay for calls and games. So packets go as UDP datagrams when they can
(`src/datagram.rs`), next to the circuit's stream.

- **Topology.** Every node has one UDP socket (port 4002, `--datagram-port`; any free
  port if taken; `--no-datagrams` turns it off). C and E send datagrams only to R, at
  the IP of their libp2p connection to it. R is publicly reachable, so an exit behind
  NAT needs no hole punching: its own datagrams open its NAT, and R answers to the
  address they came from. E never learns C's address, as on the stream.
- **Offer.** R gives each side, over the stream, its own random 64-bit circuit ID and
  32-byte hop key. The IDs and keys differ per hop.
- **Two layers.** `[circuit id][counter][hop ciphertext]`, where the hop plaintext is
  `[e2e counter][e2e ciphertext]` and the e2e plaintext the padded packet.
  - Per hop (ChaCha20-Poly1305 with the hop key, the header as associated data): R
    forwards only what authenticates, re-encrypted for the other hop, so the bytes
    before and after R differ and an observer of both links can't match them. R learns
    each side's address from its newest authenticated datagram only, so a replayed old
    datagram from elsewhere can't redirect the circuit, and R never sends to an address
    that didn't prove the key: no reflection or amplification.
  - End to end (ChaCha20-Poly1305 with keys E sent in `ExitHello`): R can't read or
    alter packets.
  - Each layer rejects replays with a 1024-packet sliding window, so reordering is
    tolerated and duplicates aren't.
  - The e2e keys move forward every 16384 packets (`k' = BLAKE2s(k ‖ "dvpn ratchet")`;
    the epoch follows from the counter), and earlier keys are forgotten: the same
    forward secrecy within a session as on the stream. A receiver keeps the previous
    epoch's key for stragglers and catches up at most 4 epochs at a time.
- **Switching.** Packets go over the stream until a valid datagram arrives from the
  other end, then as datagrams. Both ends probe with keepalives (every 0.5 s for 10 s,
  then every 5 s) while no datagrams arrive. After 20 s without one, packets go over
  the stream again and probing resumes. Keepalives after 10 s of datagram silence go
  over the stream as well, so a path that dies mid-session can't make the client give
  up the circuit before packets have switched back.
- **Limits.** R rate-limits forwarded datagrams per circuit and direction like
  splices, dropping what exceeds the rate. The relayed circuit ends with the splice.
- **Sizes.** A full packet (1362 padded + 56 bytes of headers and tags + 28 for IP and
  UDP) is 1446 bytes, so it fits DS-Lite (1460) and PPPoE (1492) links unfragmented.

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
  tunnel. `--dns none` leaves DNS alone.
  - **Encrypted** with DNS-over-TLS (`--dns-over-tls yes`, the default), so the exit
    can't read the queries. Well-known resolvers (Quad9, Cloudflare, Google) are set
    with their TLS name, so resolved checks the certificate. `opportunistic` falls
    back to plain DNS (an exit can force that); `no` turns it off. If resolved can't
    do it, the client warns.
  - **Stray DNS is redirected** (table `ip dvpn-dns`, while a client runs): any query
    on port 53 that would leave outside `dvpn0` (to a resolver on the LAN, because
    `/etc/resolv.conf` doesn't point at resolved's stub, a local forwarder such as
    dnsmasq, or resolved's queries over other links) is DNATed to the tunnel's DNS
    server, and DNS-over-TLS (853) outside the tunnel is refused. Names on a LAN-only
    resolver (e.g. `nas.lan`) therefore don't resolve while connected. Only resolved
    encrypts, so without its stub DNS goes through the tunnel in plain text and the
    app warns that the exit can read it.
- IPv4 only in MVP; IPv6 is refused and blackholed while connected.
- **Kill switch** (`src/platform/linux/tunnel.rs`, tables `ip dvpn-client` and `ip6 dvpn-client`).
  Installed when the user connects, before anything else, and removed only when they
  disconnect; failing to install it refuses the connection.
  - **Outgoing:** a packet may leave only through `dvpn0`, `lo` or `dvpn-exit`, to the
    LAN (private ranges, link-local, multicast, and attached networks of at least a
    /16), as dvpn's own traffic (its cgroup v2, e.g. `system.slice/dvpn.service`), as
    a reply to a connection a peer started, or as an ICMP error. Everything else is
    rejected. Because this filters by interface, not by route, routes pushed by a
    rogue DHCP server or router advertisement can't steer traffic around the tunnel.
    IPv6 may only reach link-local, multicast and ULA addresses.
  - **Incoming:** on `dvpn0`, only `established,related` is accepted. The exit is
    untrusted and could otherwise open connections to services listening on the
    client.
  - **From the first click.** dvpn's own traffic is exempt, so the first DHT discovery
    works while everything else is already blocked: there is no unprotected phase
    before the first circuit.
  - **Failures block, never leak.** If the circuit drops, the client fails, the node
    stops or the network changes, the kill switch stays and the service brings the
    connection back (§3.12).
  - Without cgroup v2 (or if nftables refuses the rule), only the inbound part is
    installed and protection relies on routes; the app says "Not fully protected".
- **Teardown.** Everything is reverted on disconnect, and when `connect` stops on
  SIGINT, SIGTERM or SIGHUP. The signal handlers are installed before any system
  change.
  - After SIGKILL or a crash of the service while connected, the kill switch stays and
    the restarted service reconnects. Otherwise the next start removes leftovers
    (including IPv6 blackholes), unless another dvpn runs in the same network
    namespace. Removing the package removes them too.
  - The original `ip_forward` is kept in `dvpn-ip-forward-<netns>` (in
    `/run/dvpn-state/` for the service, `/run/` for the commands) so it can be
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
  - Set up by the binary when lending starts and removed when it stops
    (`src/platform/linux/exit.rs`),
    in the same way routes are. It refuses to start if a `dvpn` table already
    exists.
  - After a crash or `kill -9`, `scripts/exit-teardown.sh` removes the leftovers.
    `scripts/exit-setup.sh` remains for operators who want to inspect or apply the
    rules by hand.
- **Exit policy**, enforced in userspace before a packet is written to the TUN:
  - deny every IANA special-purpose range (`addrs::SPECIAL_PURPOSE_V4`, shared with the
    firewall), and every network the exit host is attached to, including its own
    addresses. This keeps clients away from the operator's LAN and from services on
    the exit host.
  - deny the exit's own **public** addresses as peers see them (identify's observed
    address, AutoNAT's confirmed ones; the 16 most recent). Behind a home router
    that's the router's WAN address, which isn't on any interface of the host:
    without this, a client could reach port forwards into the LAN, or the router,
    through hairpin NAT.
  - **ports** (`policy::Ports`), by exit kind:
    - dedicated exits forward every port except TCP 25 (SMTP);
    - users' exits forward only common services, a "reduced exit policy" like Tor's
      (`REDUCED_TCP_PORTS`, `REDUCED_UDP_PORTS`): the web (80, 443, 8080, …, QUIC),
      DNS, NTP, mail retrieval and submission (not 25), SSH, XMPP, IRC over TLS, git,
      OpenVPN, STUN for calls, Mumble, and ICMP. Other ports and protocols are refused.
      Lenders accepted lending, not answering for arbitrary traffic, and these exits
      are only used when no dedicated exit fits;
  - non-first fragments whose port can't be checked,
  - extra networks via `--exit-deny <cidr>`,
  - anti-spoofing: a packet's source IP must equal the circuit's assigned IP, otherwise
    it is dropped.
- Limits: max sessions (`--exit-max-sessions`) and bandwidth per session and direction
  (`--exit-rate-mbps`).
- **Return path** (`src/exit.rs`): a dedicated exit's TUN device has one queue per core
  (up to 4, Linux multi-queue TUN), each read by its own task; the kernel spreads
  packets over them by flow. Sessions are spread over the queues for writing. The
  table of which session owns which address is a read-write lock, read once per
  packet. Users' exits use one queue.
- **Exit notice** (`src/notice.rs`, dedicated exits with `--exit-notice`): a static page
  on port 80 of the exit's address (`--exit-notice-listen`) for whoever looks up an
  address they saw traffic from. It explains that the traffic came from dvpn users the
  exit can't identify and that it keeps no logs, plus an optional `--exit-contact`.
  Every request gets the same page; at most 32 connections are served at once and
  only the request head is read. Users' exits don't offer it: it would announce to
  anyone scanning that a home connection is a VPN exit.
  - Defaults are 64 sessions at 20 Mbit/s for `run --exit`.
  - Defaults are 16 sessions at 10 Mbit/s for `connect`, to protect the user's own
    connection.
- **Sessions per relay** are capped at max/2 (minimum 2). Exits can't identify clients,
  but this stops a single relay, and so a single client, from taking every slot. Not
  tighter, because entry relays are the few dedicated servers.
- The exit's handshake times out after 5 s, so a stalled handshake holds a slot only
  briefly. Relays run at most 8 splices per requesting peer, and every node caps
  connections (64 pending and 512 established incoming, 8 per peer).
- The nftables table repeats the essential rules as a second layer, and adds one:
  nothing may start a connection *towards* clients through `dvpn-exit` (only
  `established,related`).
  - forward only to the WAN interface,
  - no special-purpose destinations, none of the exit's own public addresses (set
    `self_deny`), the same port policy (`Ports::nft_rules`),
  - drop all input from the TUN to the host,
  - if IPv4 forwarding was off before lending, forward nothing but lent traffic: the
    host doesn't become a router for its LAN neighbours.

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
- Default logging is `info` with no peer IPs, destinations or packet data, and no
  remote peer IDs (those only with `--debug`). `--debug` enables more detail, but
  addresses are still redacted.
  - The service writes only warnings to the journal, which is kept on disk: info
    lines tell when the VPN was used, which shouldn't outlive the session. The app
    shows the recent info lines from memory.
  - Errors from `ip`/`nft` have every IP address replaced with `<ip>`, since their
    arguments hold relay addresses.
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
- **Network changes.** The firewall, the deny list and the bypass table are built for
  the network lending started on. Lending checks the default route and the host's
  networks every 10 s; on a change it reports itself down (no longer ready) and the
  service restarts lending, and the VPN if it was on, for the new network.
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
  - `User`: from the service or `dvpn connect`: a user's machine,
    lending while connected or on its own (§3.12).

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
  (used by the app).

### 3.11 User interface: the desktop app only
- People use dvpn only through the desktop app (§3.12). The terminal dashboard
  (`dvpn tui`), `dvpn ctl` and `dvpn install` were removed on 2026-11-23.
- The `dvpn` binary is the service (`daemon`) plus commands for operators and the
  tests (`init`, `run`, `connect`, `status`). The package installs it outside PATH, in
  `/usr/libexec/dvpn/`.
- `connect` stays because `scripts/netns-test.sh` drives the client through it; it
  starts sessions the same way as the service (`start_session` in `main.rs`), so the
  two can't drift apart.

### 3.12 Service and desktop app (`dvpn daemon`, `dvpn-gui`)
The desktop app is the unprivileged client of a service that isn't root either.

- **Service.** `dvpn daemon` runs under systemd (`packaging/dvpn.service`), with its
  data in `/var/lib/dvpn`.
  - **Its own user, not root.** It runs as the system user `dvpn` (`dvpn.sysusers`)
    with `CAP_NET_ADMIN` as its only capability (bounding and ambient set), which
    `ip`, `nft` and `resolvectl` inherit. That covers TUN devices, routes, nftables
    and `ip_forward` (a network sysctl). Two things need polkit: asking whether the
    app's process may control the service (the action `dev.dvpn.control` names user
    `dvpn` as its owner), and setting DNS on the tunnel device through
    systemd-resolved (`/usr/share/polkit-1/rules.d/60-dvpn.rules` allows this user
    exactly `set-dns-servers`, `set-domains`, `set-dns-over-tls` and `revert`). The
    ip_forward backup lives in its runtime directory `/run/dvpn-state` (kept across
    restarts, so a crashed run's value is restored). On upgrade systemd hands the
    existing `/var/lib/dvpn` to the new user.
  - It starts at boot (and on demand through `dvpn.socket`), **idle**: no node, no
    lending, nothing on the network until a client asks it to lend or connect.
  - It owns one `Controller` and handles requests one at a time, so actions never race.
  - **What the user asked for is kept.** From connect until disconnect it holds the
    kill switch (§3.5). If the client fails, it is restarted after 5 s; if the node
    stops, lending (and the VPN) restart after 5 s; on a network change, at once.
    Traffic stays blocked meanwhile.
  - **After a crash while connected** the kill switch is still there; the restarted
    service finds it and reconnects instead of unblocking traffic.
  - **Lending on its own.** `Action::Lend` (the app's "Start lending") starts lending
    without connecting the VPN, for users who want
    to volunteer their connection. Exits only exist while someone lends, so this keeps
    the network usable when few people are connected.
    - It needs the same one-time consent, and uses the same limits as `connect`.
    - Its exit record says `User`, as when connected. The kind is signed into the
      record, so it can't change when the user later connects.
  - **Lending at boot** (`Action::SetLendAtBoot`, saved as `lend_at_boot` in the
    service's `config.json`) makes the service start lending by itself when it starts.
    - It is on by default (a missing `config.json` or field counts as on), so lending
      starts at boot once the terms are accepted; the user turns it off to opt out.
    - Turning it on needs the lending terms accepted; a service that finds it on
      without them stays idle and logs why.
    - A failed start (the network may not be up yet at boot), or a node that stops
      later, is retried every 30 s.
    - "Turn off" stops that until the service starts again; turning the setting off
      stops it for good. Changing the setting starts or stops nothing by itself.
  - Lending also starts with the first connect, and stays up after a disconnect.
    "Turn off" (`Action::Stop`) ends both.
  - SIGTERM disconnects, stops lending, restores routes, DNS and the firewall, then
    exits.
  - At startup it removes firewall and routing rules a crashed predecessor left
    behind (`platform::exit::recover_stale_state`), unless another root `dvpn` is running.
- **Control socket.** `/run/dvpn/control.sock`, mode 0666: anyone may connect, and the
  service decides per connection (peer credentials) whom it answers
  (`platform::service::Access`):
  - root, and the service's own user;
  - members of the `dvpn` group, read from `/etc/group` and `/etc/passwd` when
    connecting, so adding someone works at once, without logging out;
  - whoever polkit allows the action `dev.dvpn.control`
    (`/usr/share/polkit-1/actions/dev.dvpn.policy`): by default anyone signed in at
    this computer (active local session), without a password, like NetworkManager's
    VPN control. Answers are reused for 5 minutes per process.
  - Others get `Denied` with instructions for every request.
  - The protocol is one JSON request per line, each answered by one JSON line
    (`control::Request` and `Response`).
  - `{"cmd":"watch","logs":true}` turns a connection into a feed instead: the
    service pushes an `Update` when its state changes (the whole `View` without its
    logs) and when log lines are written (only the new ones; the first update has the
    last 200). While anyone watches, the service builds the `View` once per second
    and sends it only if it changed; otherwise it builds none.
  - Requests can only choose among fixed `Action`s: accept the terms, lend, lend at
    boot on/off, connect, disconnect, turn off, set the selection, measure, add or
    remove a bootstrap peer. No paths,
    commands or system settings pass through.
  - A bootstrap address must parse as a multiaddr ending in `/p2p/<id>`. It is written
    only to the service's own `config.json`, and a running node contacts it at once.
    The `View` lists the saved ones, so the app can show and remove them.
  - Request lines over 64 KiB close the connection. Each connection has its own task,
    so one slow client can't block the others.
  - The service's settings (DNS, rate limits, listen addresses) come from
    `/etc/default/dvpn`, which only root can edit, not from the socket.
- **Consent** is still required once per data directory. The app shows the terms,
  and the service records acceptance only when asked to (`Action::AcceptExitRisk`).
- **Packages** (`cargo deb`, `cargo deb -p dvpn-gui`):
  - `dvpn` holds the binary (in `/usr/libexec/dvpn/`, not on PATH), the units, the
    sysusers entry for the `dvpn` group and `/etc/default/dvpn`. Installing it adds the installing user (from `SUDO_USER` or
    `PKEXEC_UID`) to the group, and the polkit action that lets whoever is signed in use
    the app; nothing needs setting up and nobody needs to log out. Purging it deletes
    `/var/lib/dvpn`, including the identity keys.
  - `dvpn-gui` holds the Tauri app, its menu entry and an autostart entry.
- **Desktop app** (`gui/`, Tauri 2): a tray icon and a window, both showing the
  service's `View`. One watch connection feeds both (the window through the Tauri
  event `update`); nothing polls. Actions use connections of their own.
  - Closing the window keeps the tray icon. Quitting the app leaves the VPN running,
    and the menu says so.
  - At login, `--hidden` exits quietly if this account can't use the service.
  - Only one instance runs; starting it again shows the window.
  - Desktop notifications say when the VPN is up, and when a failure blocks traffic.
  - The consent screen asks separately whether to lend at every start.
  - The frontend is static HTML, CSS and JS, with no npm build step. The webview's
    CSP allows only the app's own files.

## 4. Stack

**Language: Rust (edition 2024)**
- Rust 1.93.1 is already installed and Go is not.
- Memory safety without GC suits a packet-forwarding daemon.
- rust-libp2p is mature (Kademlia, DCUtR, AutoNAT, Relay v2, Noise, QUIC).
- `snow` is a well-established Noise implementation.

One binary `dvpn` (plus the desktop app in `gui/`). Everything that depends on the
operating system is in `src/platform/`; the rest is shared by every platform:

```
src/
  main.rs        the service (daemon) and operator commands (init | run | connect | status)
  identity.rs    keys: stable for servers, new every session for users
  records.rs     signed ExitRecord / relay records, provider shards
  node.rs        libp2p swarm: kad, mdns, relay, AutoNAT, DCUtR, publishing, circuits
  circuit.rs     splice protocol + Noise_NK client/exit sessions
  framing.rs     length-prefix + padding buckets
  client.rs      the VPN client: circuit, TUN, reconnects
  select.rs      exit selection (random, max ping), guards
  exit.rs        exit forwarding, rate limits
  policy.rs      exit policy: destinations, ports, anti-spoofing
  lend.rs        lending: exit TUN, readiness, network changes
  controller.rs  the service's state machine (what the app sees and does)
  control.rs     the control protocol (JSON lines)
  daemon.rs      the service loop
  dns.rs         DNS-over-TLS settings
  notice.rs      the exit notice page (dedicated exits)
  platform/      the OS-specific parts behind one interface (see platform/mod.rs):
    linux/tunnel.rs   capture routes, DNS pinning, kill switch (iproute2, resolved, nftables)
    linux/exit.rs     forwarding, NAT, exit firewall, policy routing
    linux/net.rs      default route, attached networks (read over netlink, linux/netlink.rs)
    linux/ipc.rs      Unix control socket, peer credentials
    linux/service.rs  systemd socket activation, signals, access (polkit, /etc/group)
    linux/files.rs    owner-only files
    linux/cmd.rs      running ip/nft/resolvectl (changes to routes, firewall and DNS
                      only, a few per connection; without blocking the async runtime)
tests/           multi-node integration tests
scripts/         exit-setup.sh / exit-teardown.sh / netns-test.sh (root harness) /
                 netns-lib.sh (shared namespace helpers)
```

### Dependency list (exact versions verified on crates.io, 2026-10-31)

| Crate | Version | Purpose |
|---|---|---|
| `libp2p` | 0.57.1 | features: `tokio, tcp, quic, noise, yamux, kad, mdns, identify, autonat, dcutr, relay, ping, macros, ed25519, serde` |
| `libp2p-stream` | 0.5.0-alpha | raw byte streams for `/dvpn/splice/2` and `/dvpn/exit/2` (compatible with libp2p-swarm 0.48; **alpha**, see note) |
| `snow` | 0.10.0 | Noise_NK end-to-end session client⇄exit |
| `chacha20poly1305` | 0.10.1 | the datagram path's AEAD (already used inside `snow`) |
| `blake2` | 0.10.6 | the datagram path's key ratchet (already used inside `snow`) |
| `tokio` | 1.54.1 | async runtime (`full`) |
| `futures` | 0.3.34 | stream utilities |
| `tun-rs` | 2.8.16 | TUN device (`async` feature), multi-queue on dedicated exits |
| `netlink-packet-route`, `netlink-packet-core`, `netlink-sys` | 0.28.0, 0.8.2, 0.8.8 | reading routes and addresses from the kernel (Linux; the versions libp2p already uses) |
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
- macOS / Windows / mobile (the Linux desktop app is in §3.12).
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
   or the app.
4. M4: using the network requires lending (§3.9), enforced in the official client
   only. ~~Single-process TUI run with `sudo dvpn tui`.~~ Superseded: the desktop app
   and the service (§3.11, §3.12) are the only user interface.
5. M4: exit selection (§3.10): latency is measured through test circuits, never by
   pinging exits directly; random mode is the default; other users' exits are used
   only when no dedicated exit fits the mode.
