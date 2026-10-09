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
command -v curl >/dev/null || { echo 'ERROR: curl is required' >&2; exit 1; }
temp="$(mktemp)" || exit 1
trap 'rm -f -- "$temp"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 "$ORIGINAL" -o "$temp"
[[ -s "$temp" ]] || { echo 'ERROR: empty V1 installer' >&2; exit 1; }
bash -n "$temp"
bash "$temp"
