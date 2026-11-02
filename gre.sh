#!/usr/bin/env bash
# Short permanent entry point; gre-manager/install.sh remains available.
set -Eeuo pipefail
work=$(mktemp)
trap 'rm -f "$work"' EXIT
curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 \
  https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/install.sh -o "$work"
bash "$work" "$@"
