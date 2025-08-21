#!/usr/bin/env bash
set -euo pipefail
./scripts/netns_setup.sh
./scripts/run_echo.sh
