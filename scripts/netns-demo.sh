#!/usr/bin/env bash
# Try the dvpn dashboard on a throwaway network: a relay, three dedicated exits with
# different latencies (one behind NAT), and a web server that shows which IP it sees.
# You are a user behind a home router. Needs root. Everything lives in network
# namespaces prefixed dvt-, which are deleted when you quit the dashboard; your own
# network, DNS and /usr/local/bin are not touched.
#
# Usage: sudo scripts/netns-demo.sh [path/to/dvpn]   (default: target/debug/dvpn)
#
#                    core router (dvt-core)
#     198.51.100.0/24 "internet" bridge                  203.0.113.0/24
#   relay .10  exit-a .20  exit-b .21  nat1 .41  home .30    web .80 (shows your IP)
#             (+10 ms)    (+80 ms)      |        |
#                                    exit-c     you: dvt-client, 192.168.1.2
#                                   (+40 ms,
#                                   behind NAT)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$ROOT/target/debug/dvpn}")"
WORK="$(mktemp -d /tmp/dvpn-demo.XXXXXX)"
NAMESPACES=(dvt-core dvt-web dvt-relay dvt-exit-a dvt-exit-b dvt-nat1 dvt-exit-c dvt-home dvt-client)
COMMON=(--no-mdns --allow-private-addrs)
PIDS=()

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (run cargo build first)" >&2; exit 1; }
for ns in "${NAMESPACES[@]}"; do
    if ip netns list | grep -qw "$ns"; then
        echo "namespace $ns already exists (another demo or test running?); delete it first" >&2
        exit 1
    fi
done

cleanup() {
    echo "stopping the demo network…"
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$WORK"
    echo "logs: $WORK"
}
trap cleanup EXIT

# shellcheck source=scripts/netns-lib.sh
source "$ROOT/scripts/netns-lib.sh"

# ---------------------------------------------------------------- network
for ns in "${NAMESPACES[@]}"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
make_core
on_bridge dvt-relay 198.51.100.10
on_bridge dvt-exit-a 198.51.100.20
on_bridge dvt-exit-b 198.51.100.21
on_bridge dvt-nat1 198.51.100.41
on_bridge dvt-home 198.51.100.30
nat_router dvt-nat1 10.1.0.1/24 dvt-exit-c 10.1.0.2/24
nat_router dvt-home 192.168.1.1/24 dvt-client 192.168.1.2/24

# Extra latency on each exit's link, so max-ping mode has something to choose from.
delay() { # <ns> <ms>
    nsx "$1" tc qdisc add dev eth0 root netem delay "$2ms" 2>/dev/null \
        || echo "note: could not add ${2} ms latency to $1 (tc netem unavailable); continuing without it"
}
delay dvt-exit-a 10
delay dvt-exit-b 80
delay dvt-exit-c 40

# A web server that answers with the address it sees you coming from.
cat > "$WORK/whoami.py" <<'EOF'
import http.server

class WhoAmI(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"the internet sees you as {self.client_address[0]}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

http.server.HTTPServer(("203.0.113.80", 80), WhoAmI).serve_forever()
EOF
nsx dvt-web python3 "$WORK/whoami.py" >> "$WORK/web.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------- dvpn nodes
init() { nsx "$1" "$BIN" --data-dir "$WORK/$2" init | awk '{print $3}'; }
start() { # <ns> <name> <dvpn args...>
    local ns=$1 name=$2; shift 2
    nsx "$ns" "$BIN" --data-dir "$WORK/$name" "$@" >> "$WORK/$name.log" 2>&1 &
    PIDS+=($!)
}
lending() { nsx "$1" "$BIN" --data-dir "$WORK/$2" status 2>/dev/null | grep -q '"lending_ready": true'; }

RELAY=$(init dvt-relay relay)
BOOT=/ip4/198.51.100.10/tcp/4001/p2p/$RELAY
start dvt-relay relay run "${COMMON[@]}" --listen /ip4/198.51.100.10/tcp/4001 --reachability public
for exit in a b; do
    ip=$([[ $exit == a ]] && echo 20 || echo 21)
    init "dvt-exit-$exit" "exit-$exit" > /dev/null
    start "dvt-exit-$exit" "exit-$exit" run "${COMMON[@]}" --listen "/ip4/198.51.100.$ip/tcp/4001" \
        --reachability public --no-relay --exit --accept-exit-risk --bootstrap "$BOOT"
done
init dvt-exit-c exit-c > /dev/null
start dvt-exit-c exit-c run "${COMMON[@]}" --listen /ip4/10.1.0.2/tcp/4001 --no-relay --exit \
    --accept-exit-risk --bootstrap "$BOOT"

printf "starting the network (relay + 3 exits)…"
for exit in a b c; do
    for _ in $(seq 90); do lending "dvt-exit-$exit" "exit-$exit" && break; printf "."; sleep 1; done
done
echo " ready."

# The demo identity is throwaway, and its install offer would put this build into
# your real /usr/local/bin; use `sudo dvpn install` for that instead.
mkdir -p -m 0700 "$WORK/you"
printf 'declined\n' > "$WORK/you/install-declined" && chmod 0600 "$WORK/you/install-declined"

cat <<EOF

Your machine is dvt-client, behind a home router whose public IP is 198.51.100.30.
Exits: exit-a 198.51.100.20 (~10 ms), exit-b 198.51.100.21 (~80 ms),
       exit-c behind NAT, public IP 198.51.100.41 (~40 ms).

In the dashboard: press y to accept lending, then c to connect.
  m switches to max-ping mode; with +/- set e.g. 50 ms and see how many exits fit.
In another terminal, see which IP the internet sees for you:
  sudo ip netns exec dvt-client curl -s http://203.0.113.80/
(198.51.100.30 means no VPN; .20, .21 or .41 means you're out through an exit.)

Press q in the dashboard to quit; the demo network is removed afterwards.
EOF
read -rp "Press Enter to open the dashboard… " _
nsx dvt-client "$BIN" --data-dir "$WORK/you" tui "${COMMON[@]}" --bootstrap "$BOOT" --dns none || true
