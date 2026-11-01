# Shared helpers for scripts/netns-test.sh and scripts/netns-demo.sh: building a fake
# internet out of network namespaces (all prefixed dvt-). Source it; don't run it.
#
#   dvt-core: router between the 198.51.100.0/24 "internet" bridge (br0, .1) and the
#             web network 203.0.113.0/24 (dvt-web at .80)

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

veth() { # <ns-a> <if-a> <ns-b> <if-b>
    ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
    nsx "$1" ip link set "$2" up
    nsx "$3" ip link set "$4" up
}

# The core router, the internet bridge, and the web server's network.
make_core() {
    nsx dvt-core sysctl -qw net.ipv4.ip_forward=1
    nsx dvt-core ip link add br0 type bridge
    nsx dvt-core ip addr add 198.51.100.1/24 dev br0
    nsx dvt-core ip link set br0 up
    veth dvt-core w-web dvt-web eth0
    nsx dvt-core ip addr add 203.0.113.1/24 dev w-web
    nsx dvt-web ip addr add 203.0.113.80/24 dev eth0
    nsx dvt-web ip route add default via 203.0.113.1
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
