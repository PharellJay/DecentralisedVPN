#!/usr/bin/env bash
# Prepares this machine for `dvpn run --exit`:
#   - enables IPv4 forwarding (the previous value is saved for exit-teardown.sh),
#   - NATs the exit's client pool (10.77.0.0/16) out of <wan-interface>,
#   - lets client traffic leave only through <wan-interface>, never to private ranges
#     or SMTP, and never to services on this host.
# The dvpn binary itself never changes firewall rules. Run as root.
#
# Usage: sudo scripts/exit-setup.sh <wan-interface>
set -euo pipefail

WAN="${1:?usage: exit-setup.sh <wan-interface>}"
TUN="${DVPN_EXIT_TUN:-dvpn-exit}"
POOL="10.77.0.0/16"
STATE="${DVPN_STATE_FILE:-/run/dvpn-exit.state}"

[[ $EUID -eq 0 ]] || { echo "exit-setup.sh must run as root" >&2; exit 1; }
ip link show "$WAN" >/dev/null 2>&1 || { echo "no such interface: $WAN" >&2; exit 1; }
if nft list table ip dvpn >/dev/null 2>&1; then
    echo "the dvpn nftables table already exists; run exit-teardown.sh first" >&2
    exit 1
fi

sysctl -n net.ipv4.ip_forward > "$STATE"
sysctl -qw net.ipv4.ip_forward=1

nft -f - <<EOF
table ip dvpn {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr $POOL oifname "$WAN" masquerade
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "$TUN" oifname != "$WAN" drop
        iifname "$TUN" ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } drop
        iifname "$TUN" tcp dport 25 drop
    }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "$TUN" drop
    }
}
EOF

echo "exit NAT enabled via $WAN; previous ip_forward=$(cat "$STATE") saved in $STATE"
