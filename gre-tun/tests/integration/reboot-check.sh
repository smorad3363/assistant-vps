#!/usr/bin/env bash
set -euo pipefail
if [[ ! -f /etc/gre-tun-test-disposable-vm ]]; then
  echo 'NOT RUN: disposable VM marker missing.' >&2
  exit 77
fi
echo 'NOT RUN: automated VM snapshot/reboot acceptance is not implemented.' >&2
exit 77
