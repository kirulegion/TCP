#!/usr/bin/env bash
set -euo pipefail
ip netns exec nsA tcpdump -i tap0 -nn -e -vv "arp or icmp or tcp port 8080"
