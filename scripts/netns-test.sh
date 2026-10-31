#!/usr/bin/env bash
# End-to-end test with real TUN devices, routes and NAT, inside Linux network
# namespaces. Needs root. Everything it creates lives in namespaces prefixed dvt-,
# which are deleted on exit; the host's own network is not touched.
#
# Usage: sudo scripts/netns-test.sh [path/to/dvpn]   (default: target/debug/dvpn)
#
#                       core router (dvt-core)
#        198.51.100.0/24 "internet" bridge        203.0.113.0/24
#   relay .10   relay2 .11   exit .20   home .30   nat1 .41      web .80
#                                  |        |          |
#                       192.168.50.1 LAN  client   exit2 (10.1.0.2, behind NAT)
#                       (must stay       192.168.1.2
#                        unreachable)    (behind home NAT)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$ROOT/target/debug/dvpn}")"
WORK="$(mktemp -d /tmp/dvpn-netns.XXXXXX)"
NAMESPACES=(dvt-core dvt-relay dvt-relay2 dvt-exit dvt-web dvt-home dvt-client dvt-nat1 dvt-exit2)
COMMON=(--no-mdns --allow-private-addrs)
declare -A PID
PASS=0
FAIL=0

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "binary not found: $BIN (run cargo build first)" >&2; exit 1; }
for ns in "${NAMESPACES[@]}"; do
    if ip netns list | grep -qw "$ns"; then echo "namespace $ns already exists; delete it first" >&2; exit 1; fi
done

cleanup() {
    for pid in "${PID[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    # Throwaway test identities and logs: hand them to the invoking user for reading.
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$WORK"
    echo "logs and data: $WORK"
}
trap cleanup EXIT

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
check() {
    local what=$1; shift
    if "$@" >/dev/null 2>&1; then echo "PASS  $what"; PASS=$((PASS + 1)); else echo "FAIL  $what"; FAIL=$((FAIL + 1)); fi
}
not() { ! "$@"; }
wait_until() {
    local secs=$1; shift
    for _ in $(seq "$secs"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    return 1
}

# ---------------------------------------------------------------- topology
for ns in "${NAMESPACES[@]}"; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done

veth() { # <ns-a> <if-a> <ns-b> <if-b>
    ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
    nsx "$1" ip link set "$2" up
    nsx "$3" ip link set "$4" up
}
on_bridge() { # <ns> <address>
    local port="b-${1#dvt-}"
    veth dvt-core "$port" "$1" eth0
    nsx dvt-core ip link set "$port" master br0
    nsx "$1" ip addr add "$2/24" dev eth0
    nsx "$1" ip route add default via 198.51.100.1
}
nat_router() { # <ns> <inside-subnet-gw/24> <host-ns> <host-addr/24>
    veth "$1" lan0 "$3" eth0
    nsx "$1" ip addr add "$2" dev lan0
    nsx "$3" ip addr add "$4" dev eth0
    nsx "$3" ip route add default via "${2%/*}"
    nsx "$1" sysctl -qw net.ipv4.ip_forward=1
    nsx "$1" nft -f - <<'EOF'
table ip nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" masquerade
    }
}
EOF
}

nsx dvt-core sysctl -qw net.ipv4.ip_forward=1
nsx dvt-core ip link add br0 type bridge
nsx dvt-core ip addr add 198.51.100.1/24 dev br0
nsx dvt-core ip link set br0 up
veth dvt-core w-web dvt-web eth0
nsx dvt-core ip addr add 203.0.113.1/24 dev w-web
nsx dvt-web ip addr add 203.0.113.80/24 dev eth0
nsx dvt-web ip route add default via 203.0.113.1

on_bridge dvt-relay 198.51.100.10
on_bridge dvt-relay2 198.51.100.11
on_bridge dvt-exit 198.51.100.20
on_bridge dvt-home 198.51.100.30
on_bridge dvt-nat1 198.51.100.41
nat_router dvt-home 192.168.1.1/24 dvt-client 192.168.1.2/24
nat_router dvt-nat1 10.1.0.1/24 dvt-exit2 10.1.0.2/24

# The exit's private LAN, with a service that clients must never reach.
nsx dvt-exit ip link add lan0 type dummy
nsx dvt-exit ip addr add 192.168.50.1/24 dev lan0
nsx dvt-exit ip link set lan0 up

mkdir -p "$WORK/www" && echo ok > "$WORK/www/index.html"
serve() { # <ns> <addr> <port> <log>
    nsx "$1" python3 -m http.server "$3" --bind "$2" --directory "$WORK/www" >> "$WORK/$4" 2>&1 &
    PID["http-$1-$3"]=$!
}
serve dvt-web 203.0.113.80 80 web.log
serve dvt-web 203.0.113.80 25 smtp.log
serve dvt-exit 192.168.50.1 8080 exit-lan.log
serve dvt-exit 198.51.100.20 8081 exit-host.log

# ---------------------------------------------------------------- helpers
init() { nsx "$1" "$BIN" --data-dir "$WORK/$2" init | awk '{print $3}'; }
start() { # <ns> <name> <dvpn args...>
    local ns=$1 name=$2; shift 2
    nsx "$ns" "$BIN" --data-dir "$WORK/$name" "$@" >> "$WORK/$name.log" 2>&1 &
    PID[$name]=$!
}
stop() { kill "-${2:-INT}" "${PID[$1]}" 2>/dev/null || true; wait "${PID[$1]}" 2>/dev/null || true; unset "PID[$1]"; }
status() { nsx "$1" "$BIN" --data-dir "$WORK/$2" status; }
http_ok() { [[ "$(nsx "$1" curl -s --max-time 4 -o /dev/null -w '%{http_code}' "$2")" == 200 ]]; }
web_saw() { grep -q "^$1 " "$WORK/web.log"; }
circuit_up() { status dvt-client client | grep -q '"assigned_ip"'; }
circuit_down() { status dvt-client client | grep -q '"circuit": null'; }

RELAY=$(init dvt-relay relay)
BOOT=/ip4/198.51.100.10/tcp/4001/p2p/$RELAY
init dvt-exit exit > /dev/null
init dvt-client client > /dev/null

# ---------------------------------------------------------------- scenario A: public exit
echo "== scenario A: client behind home NAT, public exit"
start dvt-relay relay run "${COMMON[@]}" --listen /ip4/198.51.100.10/tcp/4001 --reachability public
DVPN_STATE_FILE="$WORK/exit.state" nsx dvt-exit "$ROOT/scripts/exit-setup.sh" eth0 > /dev/null
EXIT_ARGS=(run "${COMMON[@]}" --listen /ip4/198.51.100.20/tcp/4001 --reachability public --no-relay
           --exit --accept-exit-risk --bootstrap "$BOOT")
start dvt-exit exit "${EXIT_ARGS[@]}"
start dvt-client client connect "${COMMON[@]}" --bootstrap "$BOOT" --dns none

check "client builds a circuit" wait_until 90 circuit_up
check "all IPv4 is routed into dvpn0" bash -c "ip netns exec dvt-client ip route | grep -q '^0.0.0.0/1 dev dvpn0'"
check "IPv6 is blackholed" bash -c "ip netns exec dvt-client ip -6 route | grep -q 'blackhole ::/1'"
check "web is reachable through the tunnel" http_ok dvt-client http://203.0.113.80/
check "web server sees the exit's IP" web_saw 198.51.100.20
check "web server never sees the client's IP" not web_saw 198.51.100.30
check "(sanity) exit LAN service is up" http_ok dvt-exit http://192.168.50.1:8080/
check "exit's private LAN is unreachable" not http_ok dvt-client http://192.168.50.1:8080/
check "(sanity) exit host service is up" http_ok dvt-relay http://198.51.100.20:8081/
check "exit host's own services are unreachable" not http_ok dvt-client http://198.51.100.20:8081/
check "(sanity) port 25 is reachable without the tunnel" http_ok dvt-relay http://203.0.113.80:25/
check "SMTP (TCP 25) is blocked by the exit" not http_ok dvt-client http://203.0.113.80:25/
check "exit reports one session" bash -c "ip netns exec dvt-exit '$BIN' --data-dir '$WORK/exit' status | grep -q '\"exit_sessions\": 1'"

echo "== kill switch"
stop exit KILL
check "client notices the lost circuit" wait_until 20 circuit_down
check "no traffic while the exit is down" not http_ok dvt-client http://203.0.113.80/
check "nothing leaked from the client's IP" not web_saw 198.51.100.30
start dvt-exit exit "${EXIT_ARGS[@]}"
check "client reconnects when the exit returns" wait_until 120 http_ok dvt-client http://203.0.113.80/
check "still nothing from the client's IP" not web_saw 198.51.100.30

echo "== silent exit (frozen: its connections stay open, nothing answers)"
kill -STOP "${PID[exit]}"
check "client notices the silent exit via keepalives" wait_until 50 circuit_down
check "no traffic while the exit is frozen" not http_ok dvt-client http://203.0.113.80/
check "nothing leaked from the client's IP" not web_saw 198.51.100.30
kill -CONT "${PID[exit]}"
check "client reconnects when the exit wakes up" wait_until 120 http_ok dvt-client http://203.0.113.80/

echo "== disconnect"
stop client INT
check "dvpn0 routes are removed" not bash -c "ip netns exec dvt-client ip route | grep -q dvpn0"
check "IPv6 blackhole is removed" not bash -c "ip netns exec dvt-client ip -6 route | grep -q blackhole"
check "(sanity) direct traffic works again" http_ok dvt-client http://203.0.113.80/
stop exit INT

# ---------------------------------------------------------------- scenario B: exit behind NAT
echo "== scenario B: exit behind NAT"
init dvt-relay2 relay2 > /dev/null
EXIT2=$(init dvt-exit2 exit2)
start dvt-relay2 relay2 run "${COMMON[@]}" --listen /ip4/198.51.100.11/tcp/4001 --reachability public --bootstrap "$BOOT"
DVPN_STATE_FILE="$WORK/exit2.state" nsx dvt-exit2 "$ROOT/scripts/exit-setup.sh" eth0 > /dev/null
start dvt-exit2 exit2 run "${COMMON[@]}" --listen /ip4/10.1.0.2/tcp/4001 --no-relay --exit --accept-exit-risk --bootstrap "$BOOT"
exit2_natted() { status dvt-exit2 exit2 | grep -q '"reachability": "Private"' && ! status dvt-exit2 exit2 | grep -q '"relay_reservations": 0'; }
check "exit2 detects NAT and reserves a relay" wait_until 60 exit2_natted

# The stopped exit's record is still in the DHT, so the client must skip it.
: > "$WORK/web.log"
start dvt-client client connect "${COMMON[@]}" --bootstrap "$BOOT" --dns none
uses_exit2() { status dvt-client client | grep -q "\"exit\": \"$EXIT2\""; }
web_via_exit2() { uses_exit2 && http_ok dvt-client http://203.0.113.80/; }
check "client builds a circuit to the NATed exit" wait_until 120 uses_exit2
check "web is reachable through the NATed exit" wait_until 20 web_via_exit2
check "web server sees the NATed exit's public IP" web_saw 198.51.100.41
check "web server never sees the client's IP" not web_saw 198.51.100.30
echo "info  exit2 hole punches: $(status dvt-exit2 exit2 | grep -o '"hole_punches": [0-9]*')"
stop client INT

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
