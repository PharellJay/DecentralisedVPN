#!/usr/bin/env bash
# Removes what lending leaves behind if dvpn didn't shut down cleanly (or what
# scripts/exit-setup.sh installed): the dvpn nftables table, dvpn's policy-routing
# rules and table, and, if exit-setup.sh saved it, the previous IPv4 forwarding
# setting. Run as root.
set -euo pipefail

STATE="${DVPN_STATE_FILE:-/run/dvpn-exit.state}"
BYPASS_TABLE=7700
RULE_PREFS=(7700 7701)

[[ $EUID -eq 0 ]] || { echo "exit-teardown.sh must run as root" >&2; exit 1; }

if nft list table ip dvpn >/dev/null 2>&1; then
    nft delete table ip dvpn
    echo "removed the dvpn nftables table"
else
    echo "no dvpn nftables table found"
fi

removed=0
for pref in "${RULE_PREFS[@]}"; do
    while ip -4 rule del pref "$pref" 2>/dev/null; do removed=$((removed + 1)); done
done
ip -4 route flush table "$BYPASS_TABLE" 2>/dev/null || true
echo "removed $removed dvpn routing rules"

# dvpn itself saves the original setting per network namespace.
NS_ID=$(readlink /proc/self/ns/net | tr -dc '0-9')
if [[ ! -f "$STATE" && -f "/run/dvpn-ip-forward-$NS_ID" ]]; then
    STATE="/run/dvpn-ip-forward-$NS_ID"
fi
if [[ -f "$STATE" ]]; then
    sysctl -qw net.ipv4.ip_forward="$(cat "$STATE")"
    echo "restored ip_forward=$(cat "$STATE")"
    rm -f "$STATE"
fi
