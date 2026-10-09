#!/usr/bin/env bash
set -euo pipefail

REPO="smorad3363/assistant-vps"
BRANCH="master"
BASE="https://raw.githubusercontent.com/$REPO/$BRANCH/portmanager-dashboard"
BIN="/usr/local/bin/portmanager"

[ "$(id -u)" -eq 0 ] || { echo "Run as root: curl ... | sudo bash"; exit 1; }

for cmd in curl base64 gzip bash install ip iptables tc crontab awk sed grep sort; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING=1
done

if [ "${MISSING:-0}" = 1 ] && command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl coreutils gzip iproute2 iptables cron gawk >/dev/null
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "[1/3] Downloading Port Manager..."
curl -fsSL "$BASE/portmanager.sh.gz.b64" | base64 -d | gzip -d > "$tmp"

echo "[2/3] Validating..."
bash -n "$tmp"
install -m 0755 "$tmp" "$BIN"

echo "[3/3] Installing rules/cron..."
"$BIN" install

echo
echo "Installed successfully."
echo "Run: portmanager"
