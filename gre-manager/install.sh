#!/usr/bin/env bash
set -e

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run with sudo/root."
  exit 1
fi

RAW="https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/gremgr.sh"

need_cmds=(ip iptables ping sha256sum curl systemctl)
missing=0
for c in "${need_cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || missing=1
done

if (( missing )); then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iptables iputils-ping coreutils curl >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute iptables iputils coreutils curl >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute iptables iputils coreutils curl >/dev/null
  else
    echo "Install required tools: iproute2/iproute, iptables, ping, sha256sum, curl, systemd"
    exit 1
  fi
fi

curl -fsSL "$RAW" -o /usr/local/sbin/gremgr
chmod 755 /usr/local/sbin/gremgr
/usr/local/sbin/gremgr --install

echo
echo "Done. Run: gremgr"
