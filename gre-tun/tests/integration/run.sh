#!/usr/bin/env bash
set -euo pipefail
# Only disposable VM with explicit marker. No guessed host/network modifications.
if [[ ! -f /etc/gre-tun-test-disposable-vm ]]; then
  echo 'NOT RUN: /etc/gre-tun-test-disposable-vm missing (disposable lab required).' >&2
  exit 77
fi
if [[ "${EUID}" -ne 0 ]]; then echo 'NOT RUN: root is required.' >&2; exit 77; fi
for cmd in ip nft tc conntrack; do command -v "$cmd" >/dev/null || { echo "NOT RUN: $cmd is missing" >&2; exit 77; }; done
echo 'NOT RUN: Two-endpoint GRE, QoS and rollback traffic harness has not passed lab acceptance.' >&2
exit 77
