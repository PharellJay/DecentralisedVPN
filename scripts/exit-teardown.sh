#!/usr/bin/env bash
# Undoes scripts/exit-setup.sh: removes the dvpn nftables table and restores the
# previous IPv4 forwarding setting. Run as root.
set -euo pipefail

STATE="${DVPN_STATE_FILE:-/run/dvpn-exit.state}"

[[ $EUID -eq 0 ]] || { echo "exit-teardown.sh must run as root" >&2; exit 1; }

if nft list table ip dvpn >/dev/null 2>&1; then
    nft delete table ip dvpn
    echo "removed the dvpn nftables table"
else
    echo "no dvpn nftables table found"
fi

if [[ -f "$STATE" ]]; then
    sysctl -qw net.ipv4.ip_forward="$(cat "$STATE")"
    echo "restored ip_forward=$(cat "$STATE")"
    rm -f "$STATE"
fi
