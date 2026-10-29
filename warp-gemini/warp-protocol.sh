#!/usr/bin/env bash
# Safe alternative WARP transport test: official WireGuard versus MASQUE.
# Keeps existing SOCKS5 (127.0.0.1:40000) and Xray routes.
set -Eeuo pipefail
export LC_ALL=C
PORT="${WARP_PORT:-40000}"
TRACE="https://www.cloudflare.com/cdn-cgi/trace"
STATE="/opt/warp-gemini/previous-warp-protocol"
LOCK="/run/lock/warp-gemini-protocol.lock"
log() { printf '[warp-protocol] %s\n' "$*"; }
die() { printf '[warp-protocol] ERROR: %s\n' "$*" >&2; exit 1; }
warp() { timeout 30 warp-cli --accept-tos "$@"; }
mode() {
  local current
  current="$(warp tunnel protocol get 2>&1)" || { log "$current"; return 1; }
  if grep -qi 'WireGuard' <<<"$current"; then printf 'WireGuard\n'
  elif grep -qi 'MASQUE' <<<"$current"; then printf 'MASQUE\n'
  else log "$current"; return 1
  fi
}
v4trace() { curl -4fsS --socks5 "127.0.0.1:$PORT" --connect-timeout 5 --max-time 18 "$TRACE"; }
healthy() {
  local t
  t="$(v4trace 2>/dev/null)" || return 1
  grep -Eq '^warp=(on|plus)$' <<<"$t" || return 1
  grep -Eq '^ip=([0-9]{1,3}\.){3}[0-9]{1,3}$' <<<"$t"
}
wait_healthy() {
  local i
  for i in $(seq 1 15); do
    if healthy; then return 0; fi
    sleep 2
  done
  return 1
}
route() { ip -4 route get 1.1.1.1 | head -1; }
rollback() {
  local old="$1"
  log "Trying to restore previous transport: $old"
  warp disconnect >/dev/null 2>&1 || :
  warp tunnel protocol set "$old" || :
  warp connect || :
  wait_healthy || log "WARP is not yet healthy after rollback; inspect: warp-cli status"
}
show() {
  printf 'Current transport: '; mode || printf 'unknown\n'
  printf 'WARP: '; warp status | tr '\n' ' '; printf '\n'
  echo '--- WARP IPv4 exit ---'
  v4trace | grep -E '^(ip|loc|colo|warp)=' || :
  echo '--- Direct IPv4 ---'
  curl -4fsS --connect-timeout 5 --max-time 15 "$TRACE" | grep -E '^(ip|loc|colo|warp)=' || :
  echo '--- Host IPv4 route ---'
  route
}
[[ $EUID == 0 ]] || die 'Run as root / sudo.'
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1024 && PORT <= 65535 )) || die 'Invalid WARP_PORT.'
command -v warp-cli >/dev/null || die 'Cloudflare WARP is not installed.'
command -v flock >/dev/null || die 'flock is required.'
exec 9>"$LOCK"
flock -n 9 || die 'Another WARP protocol operation is in progress.'
ACTION="${1:-status}"
if [[ "$ACTION" == status ]]; then show; exit 0; fi
[[ "$ACTION" == wireguard || "$ACTION" == masque || "$ACTION" == restore ]] || die 'Usage: warp-protocol [status|wireguard|masque|restore]'
MODELINE="$(warp settings 2>&1 | grep -m1 'Mode:' || true)"
[[ "$MODELINE" == *'WarpProxy on port'* ]] || die 'WARP is not in local proxy mode; will not change host routing.'
SET_PORT="$(sed -nE 's/.*WarpProxy on port ([0-9]+).*/\1/p' <<<"$MODELINE")"
[[ "$SET_PORT" == "$PORT" ]] || die "Expected proxy port $PORT, found ${SET_PORT:-unknown}"
BEFORE="$(route)"
CURRENT="$(mode)" || die 'Cannot read current WARP tunnel protocol safely.'
case "$ACTION" in
  wireguard) TARGET=WireGuard ;;
  masque) TARGET=MASQUE ;;
  restore)
    [[ -f "$STATE" ]] || die 'No previous protocol recorded.'
    TARGET="$(cat "$STATE")"
    [[ "$TARGET" == WireGuard || "$TARGET" == MASQUE ]] || die 'Invalid saved protocol.'
    ;;
esac
if [[ "$CURRENT" == "$TARGET" ]]; then
  log "Already using $TARGET. Running health check."
  wait_healthy || die 'WARP proxy is not healthy.'
  show
  exit 0
fi
if [[ "$ACTION" != restore ]]; then
  install -d -m 700 /opt/warp-gemini
  printf '%s\n' "$CURRENT" > "${STATE}.tmp"
  chmod 600 "${STATE}.tmp"
  mv -f "${STATE}.tmp" "$STATE"
fi
log "Changing WARP transport: $CURRENT -> $TARGET"
log 'WARP proxy requests may briefly fail; Xray, Docker and default route remain unchanged.'
FAILED=0
warp disconnect || FAILED=1
if [[ "$FAILED" == 0 ]]; then warp tunnel protocol set "$TARGET" || FAILED=1; fi
if [[ "$FAILED" == 0 ]]; then warp connect || FAILED=1; fi
if [[ "$FAILED" == 0 ]]; then wait_healthy || FAILED=1; fi
AFTER="$(route)"
if [[ "$BEFORE" != "$AFTER" ]]; then
  log 'Unexpected default-route difference. Restoring previous WARP transport.'
  rollback "$CURRENT"
  die 'Host route changed; inspect networking.'
fi
if [[ "$FAILED" != 0 ]]; then
  log 'New transport failed WARP SOCKS5 IPv4 health check.'
  rollback "$CURRENT"
  die 'Returned to the previous transport (check health before relying on WARP).'
fi
log "Transport $TARGET is healthy over local SOCKS5."
show
log 'Test Gemini with your existing VPN profile. If no improvement, use: sudo warp-protocol restore'
