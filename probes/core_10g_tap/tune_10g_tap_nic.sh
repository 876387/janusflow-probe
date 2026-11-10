#!/usr/bin/env bash
# JanusFlow (雅努斯流 · janusflow.cn / JanusFlow.net / atooli.com)
# Core Network 10G/40G Optical TAP / Switch SPAN Mirror NIC Hardening & Offload Lockdown Script
# Usage: sudo bash tune_10g_tap_nic.sh <mirror_iface>

set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
    echo "Usage: sudo bash $0 <mirror_iface> (e.g. eth1, ens2f0)" >&2
    exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "{\"status\":\"error\",\"iface\":\"$IFACE\",\"message\":\"Interface not found\"}" >&2
    exit 1
fi

# 1. Put mirror interface into silent RX-only promiscuous mode (flush IPs, disable ARP & IPv6 SLAAC)
ip addr flush dev "$IFACE" || true
ip link set dev "$IFACE" arp off multicast on promisc on up
if [[ -w "/proc/sys/net/ipv6/conf/${IFACE}/disable_ipv6" ]]; then
    echo 1 > "/proc/sys/net/ipv6/conf/${IFACE}/disable_ipv6" || true
fi

# 2. Disable all packet-coalescing offloads (TSO / GSO / GRO / LRO / RXVLAN) to preserve wire packet lengths
if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$IFACE" tso off gso off gro off lro off rxvlan off 2>/dev/null || \
    ethtool -K "$IFACE" tso off gso off gro off 2>/dev/null || true

    # 3. Maximize RX ring buffer size (try 4096, fallback to 2048)
    ethtool -G "$IFACE" rx 4096 2>/dev/null || ethtool -G "$IFACE" rx 2048 2>/dev/null || true

    # 4. Configure symmetric RSS Toeplitz hash key so bidirectional 5-tuples hit the same RX queue
    ethtool -X "$IFACE" hkey 6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a 2>/dev/null || true

    TSO_ST=$(ethtool -k "$IFACE" | awk -F': ' '/tcp-segmentation-offload/{print $2}' | awk '{print $1}')
    GSO_ST=$(ethtool -k "$IFACE" | awk -F': ' '/generic-segmentation-offload/{print $2}' | awk '{print $1}')
    GRO_ST=$(ethtool -k "$IFACE" | awk -F': ' '/generic-receive-offload/{print $2}' | awk '{print $1}')
    echo "{\"status\":\"ok\",\"iface\":\"$IFACE\",\"promisc\":\"on\",\"tso\":\"$TSO_ST\",\"gso\":\"$GSO_ST\",\"gro\":\"$GRO_ST\"}"
else
    echo "{\"status\":\"warn\",\"iface\":\"$IFACE\",\"message\":\"ethtool not installed; promisc enabled but hardware offloads could not be verified\"}"
fi
