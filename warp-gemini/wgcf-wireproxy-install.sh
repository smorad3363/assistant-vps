#!/usr/bin/env bash
# Isolated WGCF + WireProxy SOCKS5 for Gemini; no host route or Xray modifications.
set -Eeuo pipefail
umask 077
BASE="/opt/warp-gemini/wgcf-isolated"
SERVICE="/etc/systemd/system/warp-gemini-wgcf-proxy.service"
PORT="40001"
TRACE="https://www.cloudflare.com/cdn-cgi/trace"
fail() { echo "[wgcf-wireproxy] ERROR: $*" >&2; exit 1; }
info() { echo "[wgcf-wireproxy] $*"; }
health() {
  curl -4fsS --connect-timeout 5 --max-time 15 --socks5 "127.0.0.1:$PORT" "$TRACE" |
    grep -E '^(ip|loc|warp)='
}
status() {
  systemctl is-active warp-gemini-wgcf-proxy.service 2>/dev/null || :
  health || fail "WGCF proxy $PORT not healthy."
}
[[ $EUID -eq 0 ]] || fail "Run as root."
[[ "${1:-install}" == install ]] || { status; exit; }
[[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] || fail "Only Linux x86_64 is supported by this pinned build."
command -v curl >/dev/null || fail "curl required."
command -v sha256sum >/dev/null || fail "sha256sum required."
BEFORE="$(ip -4 route get 1.1.1.1 | head -1)"
mkdir -p "$BASE"
chmod 700 "$BASE"
cd "$BASE"

download() {
  local target="$1" url="$2" hash="$3"
  if [ -f "$target" ] && printf '%s  %s\n' "$hash" "$target" | sha256sum -c - >/dev/null 2>&1; then
    return
  fi
  if [ -e "$target" ]; then fail "Existing $target has unexpected checksum; refusing overwrite."; fi
  curl -fL --retry 2 --connect-timeout 10 --max-time 90 -sS "$url" -o "$target.tmp"
  printf '%s  %s\n' "$hash" "$target.tmp" | sha256sum -c - >/dev/null || fail "Checksum failed: $target"
  mv -f "$target.tmp" "$target"
}
download wgcf https://github.com/ViRb3/wgcf/releases/download/v2.3.0/wgcf_2.3.0_linux_amd64 01614e38c0eb5f3405232e71cfaf02d64d4809e4988ad8f5a8071af16d193405
download wireproxy.tar.gz https://github.com/windtf/wireproxy/releases/download/v1.1.3/wireproxy_linux_amd64.tar.gz e88c1d090740373fc606c1bafd81d9a5eadc642cce5667616e20e9d7a444f51c
chmod 700 wgcf
if [ ! -x wireproxy ]; then
  tar -xzf wireproxy.tar.gz wireproxy
  chmod 700 wireproxy
fi
if [ ! -s wgcf-account.toml ]; then
  info "Registering a new isolated Cloudflare WARP device."
  ./wgcf register --accept-tos
fi
if [ ! -s wgcf-profile.conf ]; then ./wgcf generate; fi
if [ ! -f wireproxy.conf ]; then
  printf '%s\n' 'WGConfig = /opt/warp-gemini/wgcf-isolated/wgcf-profile.conf' '' '[Socks5]' 'BindAddress = 127.0.0.1:40001' > wireproxy.conf
fi
chmod 600 wgcf-account.toml wgcf-profile.conf wireproxy.conf
./wireproxy -n -c wireproxy.conf || fail "WireProxy config invalid."
if [ ! -e "$SERVICE" ]; then
  cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Isolated WGCF WireProxy for Gemini WARP testing
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
UMask=0077
WorkingDirectory=/opt/warp-gemini/wgcf-isolated
ExecStart=/opt/warp-gemini/wgcf-isolated/wireproxy -c /opt/warp-gemini/wgcf-isolated/wireproxy.conf
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
else
  grep -q 'ExecStart=/opt/warp-gemini/wgcf-isolated/wireproxy' "$SERVICE" || fail "Existing service differs, will not overwrite."
fi
systemctl daemon-reload
systemctl enable --now warp-gemini-wgcf-proxy.service
OK=0
for i in $(seq 1 15); do
  if health 2>/dev/null | grep -q '^warp=on$'; then OK=1; break; fi
  sleep 2
done
[[ "$OK" -eq 1 ]] || fail "WGCF proxy not healthy; original WARP proxy remains unchanged."
AFTER="$(ip -4 route get 1.1.1.1 | head -1)"
[[ "$BEFORE" == "$AFTER" ]] || fail "Host route changed; investigate before using."
info "WGCF + WireProxy healthy on 127.0.0.1:$PORT"
health
info "Host direct IPv4 route preserved. No Marzban/Xray changes performed."
