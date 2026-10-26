#!/usr/bin/env bash
# WARP Local Proxy installer for Ubuntu/Debian VPS nodes.
# Does not change the default route, Xray/Marzban, GRE, firewall or Docker configuration.
set -Eeuo pipefail

ACTION="${1:-install}"
WARP_PORT="${WARP_PORT:-40000}"
TRACE_URL="https://www.cloudflare.com/cdn-cgi/trace"

say() { printf '[gemini-warp] %s\n' "$*"; }
fail() { printf '[gemini-warp] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || fail "Run with sudo/root."; }
status() {
    command -v warp-cli >/dev/null 2>&1 || fail "Cloudflare WARP is not installed."
    warp-cli --accept-tos status || true
    echo "--- SOCKS5 listener ---"
    ss -ltnp "( sport = :$WARP_PORT )" || true
    echo "--- Direct route ---"
    ip -4 route get 1.1.1.1 | head -1
    echo "--- Cloudflare trace through WARP ---"
    curl -fsS --connect-timeout 6 --max-time 20 --socks5-hostname "127.0.0.1:$WARP_PORT" "$TRACE_URL" | grep -E '^(ip|loc|colo|warp)=' || true
}
diagnose() {
    echo "=== Host ==="
    hostname; uptime; free -h; swapon --show || true
    echo "=== Xray memory (KiB RSS) ==="
    ps -C xray -o pid,stat,etime,%cpu,rss,nlwp || true
    echo "=== TCP sockets ==="
    ss -s || true
    echo "=== Top inbound established ports ==="
    ss -Htan state established | awk '{x=$3;sub(/.*:/,"",x);n[x]++}END{for(k in n)print n[k],k}' | sort -nr | head -15
    echo "=== Recent Xray OOM kills ==="
    journalctl -k --since '24 hours ago' --no-pager 2>/dev/null | grep -E 'Out of memory: Killed process.*xray|oom-kill:.*task=xray' | tail -10 || true
}
case "$ACTION" in
    status) status; exit ;;
    diagnose) diagnose; exit ;;
    install) ;;
    *) fail "Usage: bash install.sh [install|status|diagnose]" ;;
esac

require_root
[[ "$WARP_PORT" =~ ^[0-9]+$ ]] && ((WARP_PORT>=1024 && WARP_PORT<=65535)) || fail "Invalid WARP_PORT."
command -v apt-get >/dev/null || fail "Only apt-based Debian/Ubuntu is currently supported."
[ -r /etc/os-release ] || fail "/etc/os-release missing"
. /etc/os-release
[[ "$ID" == "ubuntu" || "$ID" == "debian" ]] || fail "Unsupported distribution: $ID"
CODENAME="${VERSION_CODENAME:-}"
[ -n "$CODENAME" ] || fail "OS codename unavailable."
BEFORE_ROUTE="$(ip -4 route get 1.1.1.1 | head -1)"
[ -n "$BEFORE_ROUTE" ] || fail "No direct IPv4 route available."

if command -v warp-cli >/dev/null 2>&1 && warp-cli --accept-tos registration show >/dev/null 2>&1; then
    MODE="$(warp-cli --accept-tos settings 2>/dev/null | grep -m1 'Mode:' || true)"
    if [[ "$MODE" != *"WarpProxy on port"* ]]; then
        fail "Existing registered WARP uses another mode ($MODE). Refusing to change it."
    fi
    EXISTING_PORT="$(printf '%s\n' "$MODE" | sed -nE 's/.*WarpProxy on port ([0-9]+).*/\1/p')"
    if [ -n "$EXISTING_PORT" ] && [ "$EXISTING_PORT" != "$WARP_PORT" ]; then
        fail "Existing WARP proxy uses port $EXISTING_PORT. Set WARP_PORT=$EXISTING_PORT to preserve it."
    fi
fi
if ss -Hlnpt "( sport = :$WARP_PORT )" | grep -q .; then
    ss -Hlnpt "( sport = :$WARP_PORT )" | grep -q 'warp-svc' || fail "Port $WARP_PORT is already used by another service."
fi

if ! command -v warp-cli >/dev/null 2>&1; then
    say "Installing Cloudflare's official WARP client ($ID / $CODENAME)."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg >/dev/null
    curl -fsSL --connect-timeout 10 --max-time 30 \
        https://pkg.cloudflareclient.com/pubkey.gpg -o /tmp/gemini-warp-repo-key.gpg
    gpg --batch --yes --dearmor \
        --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
        /tmp/gemini-warp-repo-key.gpg
    printf 'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ %s main\n' "$CODENAME" \
        > /etc/apt/sources.list.d/cloudflare-client.list
    apt-get update -qq
    apt-cache policy cloudflare-warp | grep -Eq 'Candidate: [0-9]' || fail "Cloudflare WARP package is unavailable for $CODENAME."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cloudflare-warp
fi

systemctl enable --now warp-svc >/dev/null
if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
    say "Registering a new free WARP client."
    warp-cli --accept-tos registration new
fi
warp-cli --accept-tos mode proxy >/dev/null
warp-cli --accept-tos proxy port "$WARP_PORT" >/dev/null
warp-cli --accept-tos connect >/dev/null
say "Waiting for WARP proxy health..."
TRACE=""
for i in $(seq 1 15); do
    if curl -fsS --connect-timeout 5 --max-time 10 --socks5-hostname \
        "127.0.0.1:$WARP_PORT" "$TRACE_URL" >/tmp/gemini-warp-last-trace 2>/dev/null; then
        TRACE="$(cat /tmp/gemini-warp-last-trace)"
        if printf '%s\n' "$TRACE" | grep -Eq '^warp=(on|plus)$'; then break; fi
    fi
    sleep 2
done
printf '%s\n' "$TRACE" | grep -Eq '^warp=(on|plus)$' || fail "WARP connected state not verified. Run: warp-cli status"
AFTER_ROUTE="$(ip -4 route get 1.1.1.1 | head -1)"
[ "$BEFORE_ROUTE" = "$AFTER_ROUTE" ] || fail "Default route changed; inspect network before production use."
say "Healthy SOCKS5 endpoint: 127.0.0.1:$WARP_PORT"
printf '%s\n' "$TRACE" | grep -E '^(ip|loc|colo|warp)='
say "Original IPv4 route preserved: $AFTER_ROUTE"
say "No Xray/Marzban configuration was changed. Use the documented SOCKS outbound on your panel."

# Install/update the operator menu. This does not enable Xray overlay or restart containers.
MENU_HOME="/opt/warp-gemini"
mkdir -p "$MENU_HOME"
for name in menu.py xray-wrapper.py; do
    curl -fsSL --connect-timeout 8 --max-time 30 \
        "https://raw.githubusercontent.com/smorad3363/assistant-vps/master/warp-gemini/$name" \
        -o "$MENU_HOME/$name.tmp"
    if [ "$name" = "menu.py" ]; then python3 -m py_compile "$MENU_HOME/$name.tmp"; fi
    mv -f "$MENU_HOME/$name.tmp" "$MENU_HOME/$name"
    chmod 755 "$MENU_HOME/$name"
done
ln -sfn "$MENU_HOME/menu.py" /usr/local/bin/warp-menu
say "Interactive manager installed. Run: sudo warp-menu"
