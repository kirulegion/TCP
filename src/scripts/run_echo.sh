#!/usr/bin/env bash
set -euo pipefail

# build
cargo build

# run stack (server) in nsA
ip netns exec nsA bash -lc "OUR_MAC=02:00:00:00:00:01 OUR_IP=10.0.0.1 PEER_IP=10.0.0.2 TAP_IF=tap0 sudo -E target/debug/tcp-stack" &
sleep 1

# client in nsB using Linux TCP
ip netns exec nsB bash -lc "echo 'hi' | nc -v 10.0.0.1 8080 -w 1"
wait
