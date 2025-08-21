#!/usr/bin/env bash
set -euo pipefail

# fresh namespaces
ip netns del nsA 2>/dev/null || true
ip netns del nsB 2>/dev/null || true
ip netns add nsA
ip netns add nsB

# veth pair between nsA <-> nsB
ip link add vethA type veth peer name vethB
ip link set vethA netns nsA
ip link set vethB netns nsB
ip netns exec nsA ip addr add 10.0.0.1/24 dev vethA
ip netns exec nsB ip addr add 10.0.0.2/24 dev vethB
ip netns exec nsA ip link set vethA up
ip netns exec nsB ip link set vethB up

# TAP in nsA (our stack)
ip tuntap add dev tap0 mode tap
ip link set tap0 netns nsA
ip netns exec nsA ip link set tap0 up
ip netns exec nsA ip addr add 10.0.0.1/24 dev tap0 || true

echo "Namespaces ready:"
echo " nsA: 10.0.0.1 (vethA, tap0)"
echo " nsB: 10.0.0.2 (vethB)"
echo "Run tcpdump in nsA: ip netns exec nsA tcpdump -i tap0 -nn -e -vv"
