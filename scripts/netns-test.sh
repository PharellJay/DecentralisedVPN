#!/usr/bin/env bash
# End-to-end test with real TUN devices, routes, firewall rules and NAT, inside Linux
# network namespaces. Needs root. Everything it creates lives in namespaces prefixed
# dvt-, which are deleted on exit; the host's own network is not touched.
#
# Usage: sudo scripts/netns-test.sh [path/to/dvpn]   (default: target/debug/dvpn)
#
#                         core router (dvt-core)
#          198.51.100.0/24 "internet" bridge                203.0.113.0/24
#   relay .10  relay2 .11  exit .20  home .30  home2 .31  nat1 .41   web .80
#                              |        |         |         |
#                   192.168.50.1 LAN  client   client2    exit2 (10.1.0.2)
#                   (must stay      192.168.1.2 192.168.2.2
#                    unreachable)
#
# Every client also lends its IP (that's required to connect), so clients request
# their own path (/c1, /c2) and the web server's log shows whose traffic left where.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$(realpath "${1:-$ROOT/target/debug/dvpn}")"
WORK="$(mktemp -d /tmp/dvpn-netns.XXXXXX)"
NAMESPACES=(dvt-core dvt-relay dvt-relay2 dvt-exit dvt-web dvt-home dvt-client dvt-home2 dvt-client2 dvt-nat1 dvt-exit2)
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
    for pid in "${PID[@]}"; do kill -CONT "$pid" 2>/dev/null || true; kill "$pid" 2>/dev/null || true; done
    sleep 1
    for ns in "${NAMESPACES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
    # Throwaway test identities and logs: hand them to the invoking user for reading.
    [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$WORK"
    echo "logs and data: $WORK"
}
trap cleanup EXIT

# shellcheck source=scripts/netns-lib.sh
source "$ROOT/scripts/netns-lib.sh"
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

make_core

on_bridge dvt-relay 198.51.100.10
on_bridge dvt-relay2 198.51.100.11
on_bridge dvt-exit 198.51.100.20
on_bridge dvt-home 198.51.100.30
on_bridge dvt-home2 198.51.100.31
on_bridge dvt-nat1 198.51.100.41
nat_router dvt-home 192.168.1.1/24 dvt-client 192.168.1.2/24
nat_router dvt-home2 192.168.2.1/24 dvt-client2 192.168.2.2/24
nat_router dvt-nat1 10.1.0.1/24 dvt-exit2 10.1.0.2/24

# The exit's private LAN, with a service that clients must never reach.
nsx dvt-exit ip link add lan0 type dummy
nsx dvt-exit ip addr add 192.168.50.1/24 dev lan0
nsx dvt-exit ip link set lan0 up

mkdir -p "$WORK/www" && for f in index.html c1 c2; do echo ok > "$WORK/www/$f"; done
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
web_saw() { # <source-ip> [path]
    grep -q "^$1 .*\"GET ${2:-/}" "$WORK/web.log"
}
circuit_up() { status dvt-client client | grep -q '"assigned_ip"'; }
circuit_down() { status dvt-client client | grep -q '"circuit": null'; }
lending() { status "$1" "$2" | grep -q '"lending_ready": true'; }
kill_switch_routes() { # <ns>: both halves of IPv4 still captured by dvpn0
    local routes; routes=$(nsx "$1" ip route)
    grep -q '^0.0.0.0/1 dev dvpn0' <<< "$routes" && grep -q '^128.0.0.0/1 dev dvpn0' <<< "$routes"
}
no_lending_leftovers() { # <ns>
    ! nsx "$1" nft list table ip dvpn >/dev/null 2>&1 && ! nsx "$1" nft list table ip dvpn-client >/dev/null 2>&1 \
        && ! nsx "$1" ip rule | grep -q '770[01]:'
}
tunnel_ip() { status dvt-client client | grep -o '"assigned_ip": "[0-9.]*"' | grep -o '[0-9.]*$'; }
exit_reaches_client_service() { local ip; ip=$(tunnel_ip); [[ -n $ip ]] && http_ok dvt-exit "http://$ip:8082/"; }
WEB=http://203.0.113.80

RELAY=$(init dvt-relay relay)
BOOT=/ip4/198.51.100.10/tcp/4001/p2p/$RELAY
init dvt-exit exit > /dev/null
CLIENT=$(init dvt-client client)
CLIENT_ARGS=(connect "${COMMON[@]}" --bootstrap "$BOOT" --dns none --accept-exit-risk)

# ---------------------------------------------------------------- scenario A: public exit
echo "== scenario A: client behind home NAT, public exit"
start dvt-relay relay run "${COMMON[@]}" --listen /ip4/198.51.100.10/tcp/4001 --reachability public
EXIT_ARGS=(run "${COMMON[@]}" --listen /ip4/198.51.100.20/tcp/4001 --reachability public --no-relay
           --exit --accept-exit-risk --bootstrap "$BOOT")
start dvt-exit exit "${EXIT_ARGS[@]}"
start dvt-client client "${CLIENT_ARGS[@]}"

check "client lends its IP (exit published, reachable via relay)" wait_until 120 lending dvt-client client
check "client builds a circuit" wait_until 90 circuit_up
check "all IPv4 is routed into dvpn0" bash -c "ip netns exec dvt-client ip route | grep -q '^0.0.0.0/1 dev dvpn0'"
check "IPv6 is blackholed" bash -c "ip netns exec dvt-client ip -6 route | grep -q 'blackhole ::/1'"
check "web is reachable through the tunnel" http_ok dvt-client $WEB/c1
check "web server sees the exit's IP" web_saw 198.51.100.20 /c1
check "web server never sees the client's IP" not web_saw 198.51.100.30
check "(sanity) exit LAN service is up" http_ok dvt-exit http://192.168.50.1:8080/
check "exit's private LAN is unreachable" not http_ok dvt-client http://192.168.50.1:8080/
check "(sanity) exit host service is up" http_ok dvt-relay http://198.51.100.20:8081/
check "exit host's own services are unreachable" not http_ok dvt-client http://198.51.100.20:8081/
check "(sanity) port 25 is reachable without the tunnel" http_ok dvt-relay http://203.0.113.80:25/
check "SMTP (TCP 25) is blocked by the exit" not http_ok dvt-client http://203.0.113.80:25/
serve dvt-client 0.0.0.0 8082 client-service.log
check "(sanity) a service on the client is up, and the tunnel IP is known" bash -c \
    "[[ \"\$(ip netns exec dvt-client curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8082/)\" == 200 ]] \
     && ip netns exec dvt-client '$BIN' --data-dir '$WORK/client' status | grep -q '\"assigned_ip\": \"10.77'"
check "the exit can't connect to services on the client through the tunnel" not exit_reaches_client_service
check "exit reports one session" bash -c "ip netns exec dvt-exit '$BIN' --data-dir '$WORK/exit' status | grep -q '\"exit_sessions\": 1'"

echo "== kill switch"
stop exit KILL
check "client notices the lost circuit" wait_until 20 circuit_down
check "no traffic while the exit is down" not http_ok dvt-client $WEB/c1
check "nothing leaked from the client's IP" not web_saw 198.51.100.30
# A killed exit can't clean up; the next start must recover on its own.
start dvt-exit exit "${EXIT_ARGS[@]}"
check "an exit restarted after kill -9 cleans up the leftovers itself" \
    wait_until 30 grep -q "left behind by a dvpn that didn't shut down cleanly" "$WORK/exit.log"
check "client reconnects when the exit returns" wait_until 120 http_ok dvt-client $WEB/c1
check "kill-switch routes survive the reconnect" kill_switch_routes dvt-client
check "still nothing from the client's IP" not web_saw 198.51.100.30

echo "== silent exit (frozen: its connections stay open, nothing answers)"
kill -STOP "${PID[exit]}"
check "client notices the silent exit via keepalives" wait_until 50 circuit_down
check "no traffic while the exit is frozen" not http_ok dvt-client $WEB/c1
check "nothing leaked from the client's IP" not web_saw 198.51.100.30
kill -CONT "${PID[exit]}"
check "client reconnects when the exit wakes up" wait_until 120 http_ok dvt-client $WEB/c1
check "kill-switch routes survive the second reconnect" kill_switch_routes dvt-client

echo "== disconnect by closing the terminal (SIGHUP)"
stop client HUP
check "dvpn0 routes are removed" not bash -c "ip netns exec dvt-client ip route | grep -q dvpn0"
check "IPv6 blackhole is removed" not bash -c "ip netns exec dvt-client ip -6 route | grep -q blackhole"
check "lending firewall and routing rules are removed" no_lending_leftovers dvt-client
check "(sanity) direct traffic works again" http_ok dvt-client $WEB/
stop exit INT
check "a cleanly stopped exit leaves nothing behind" no_lending_leftovers dvt-exit

# ---------------------------------------------------------------- scenario B: exit behind NAT
echo "== scenario B: exit behind NAT"
init dvt-relay2 relay2 > /dev/null
EXIT2=$(init dvt-exit2 exit2)
start dvt-relay2 relay2 run "${COMMON[@]}" --listen /ip4/198.51.100.11/tcp/4001 --reachability public --bootstrap "$BOOT"
EXIT2_ARGS=(run "${COMMON[@]}" --listen /ip4/10.1.0.2/tcp/4001 --no-relay --exit --accept-exit-risk --bootstrap "$BOOT")
start dvt-exit2 exit2 "${EXIT2_ARGS[@]}"
exit2_natted() { status dvt-exit2 exit2 | grep -q '"reachability": "Private"' && ! status dvt-exit2 exit2 | grep -q '"relay_reservations": 0'; }
check "exit2 detects NAT and reserves a relay" wait_until 60 exit2_natted

# The stopped exit's record is still in the DHT, so the client must skip it.
: > "$WORK/web.log"
start dvt-client client "${CLIENT_ARGS[@]}"
uses_exit2() { status dvt-client client | grep -q "\"exit\": \"$EXIT2\""; }
web_via_exit2() { uses_exit2 && http_ok dvt-client $WEB/c1; }
check "client builds a circuit to the NATed exit" wait_until 120 uses_exit2
check "web is reachable through the NATed exit" wait_until 20 web_via_exit2
check "web server sees the NATed exit's public IP" web_saw 198.51.100.41 /c1
check "web server never sees the client's IP" not web_saw 198.51.100.30
echo "info  exit2 hole punches: $(status dvt-exit2 exit2 | grep -o '"hole_punches": [0-9]*')"

# ---------------------------------------------------------------- scenario C: users lend to each other
# Exits lent by other users are used only when no dedicated exit works, and clients
# move back to a dedicated exit as soon as one is up. client2 uses max-ping mode.
echo "== scenario C: other users' exits only as a last resort"
: > "$WORK/web.log"
init dvt-client2 client2 > /dev/null
stop exit2 KILL
check "teardown script cleans up after a killed exit, restoring ip_forward" bash -c \
    "ip netns exec dvt-exit2 '$ROOT/scripts/exit-teardown.sh' && ! ip netns exec dvt-exit2 nft list table ip dvpn \
     && ! ip netns exec dvt-exit2 ip rule | grep -q '770[01]:' && [[ \$(ip netns exec dvt-exit2 sysctl -n net.ipv4.ip_forward) == 0 ]]"
# client1 now has no exit but its own (which it never uses), so its VPN is blocked,
# while it keeps lending. Its kill-switch routes are in place the whole time.
check "client1 is blocked while no other exit exists" wait_until 60 not http_ok dvt-client $WEB/c1
check "client1 keeps lending while its own VPN is blocked" lending dvt-client client
start dvt-client2 client2 connect "${COMMON[@]}" --bootstrap "$BOOT" --dns none --accept-exit-risk --max-ping 2000
uses() { status "$1" "$2" | grep -q "\"exit\": \"$3\""; } # <ns> <name> <exit-peer-id>
check "client2 falls back to client1's exit (no dedicated exit is up)" wait_until 150 uses dvt-client2 client2 "$CLIENT"
check "client2's status says it's on another user's exit" bash -c \
    "ip netns exec dvt-client2 '$BIN' --data-dir '$WORK/client2' status | grep -q '\"exit_is_user\": true'"
check "client2 reports its ping measurement" bash -c \
    "ip netns exec dvt-client2 '$BIN' --data-dir '$WORK/client2' status | grep -q '\"within_limit\": [1-9]'"
check "client2 reaches the web through client1" wait_until 20 http_ok dvt-client2 $WEB/c2
check "web server sees client2's traffic from client1's IP" web_saw 198.51.100.30 /c2

start dvt-exit2 exit2 "${EXIT2_ARGS[@]}"
check "client1 picks the dedicated exit2, not client2's exit" wait_until 150 uses dvt-client client "$EXIT2"
check "client1 reaches the web through exit2" wait_until 20 http_ok dvt-client $WEB/c1
check "client1's kill-switch routes are still in place" kill_switch_routes dvt-client
check "client2 moves from client1's exit to the dedicated exit2" wait_until 120 uses dvt-client2 client2 "$EXIT2"
check "client2 reaches the web through exit2" wait_until 20 http_ok dvt-client2 $WEB/c2
check "web server sees client2's traffic from exit2's IP" web_saw 198.51.100.41 /c2
check "client1's traffic never leaves from its own IP" not web_saw 198.51.100.30 /c1
check "client2's traffic never leaves from its own IP" not web_saw 198.51.100.31 /c2
stop client2 INT
stop client INT
check "client1 leaves nothing behind" no_lending_leftovers dvt-client
check "client2 leaves nothing behind" no_lending_leftovers dvt-client2

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
