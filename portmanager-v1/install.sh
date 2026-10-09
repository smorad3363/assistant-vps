#!/usr/bin/env bash
# Alias to the original, unchanged Port Manager V1 installer.
set -Eeuo pipefail
REF="${PORTMANAGER_INSTALL_REF:-master}"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo 'Invalid source ref' >&2; exit 1; }
ORIGINAL="https://raw.githubusercontent.com/smorad3363/assistant-vps/$REF/portmanager-v1/legacy-install.sh"
if [[ $(id -u) -ne 0 ]]; then
  printf 'ERROR: run with sudo/root, just like the original V1 installer.\n' >&2
  exit 1
fi
# Original V1 manages tc root/ingress destructively. Do not install it over
# a currently owned V2 clsact rate limiter: user must remove scheduled
# limits first; never silently discard traffic-control state.
if [[ -e /var/lib/portmanager2/shaping.json || -L /var/lib/portmanager2/shaping.json ]]; then
  command -v python3 >/dev/null || { echo 'ERROR: Python required to inspect V2 tc state' >&2; exit 5; }
  python3 - <<'PY'
import json
from pathlib import Path
p=Path("/var/lib/portmanager2/shaping.json")
if p.is_symlink():
    raise SystemExit("E_CONFLICT: symlinked V2 shaping state")
try:
    value=json.loads(p.read_text())
except (OSError, ValueError):
    raise SystemExit("E_CONFLICT: unknown V2 shaping state")
if value.get("interfaces") or value.get("filters"):
    raise SystemExit("E_CONFLICT: V2 owns active tc clsact; remove schedules before installing V1")
PY
fi
command -v curl >/dev/null || { echo 'ERROR: curl is required' >&2; exit 1; }
temp="$(mktemp)" || exit 1
trap 'rm -f -- "$temp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 "$ORIGINAL" -o "$temp"
[[ -s "$temp" ]] || { echo 'ERROR: empty V1 installer' >&2; exit 1; }
bash -n "$temp"
bash "$temp"
