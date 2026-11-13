#!/usr/bin/env bash
# Noninteractive restore for pre-panel legacy deployments only.
set -u
BASE_DIR="/etc/gremgr"
TUN_DIR="$BASE_DIR/tunnels"
FWD_DIR="$BASE_DIR/forwards"
LOG_FILE="/var/log/gremgr.log"

mkdirs() {
  mkdir -p "$TUN_DIR" "$FWD_DIR"
  touch "$LOG_FILE" 2>/dev/null || true
}

log() {
  local msg="$*"
  mkdirs
  printf '%s %s\n' "$(date '+%F %T')" "$msg" >> "$LOG_FILE"
  logger -t gremgr -- "$msg" 2>/dev/null || true
}

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run as root: sudo gremgr"
    exit 1
  fi
}

detect_wan() {
  local line
  line=$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true)
  WAN_IF=$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}' <<< "$line")
  WAN_IP=$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' <<< "$line")

  if [[ -z ${WAN_IF:-} ]]; then
    WAN_IF=$(ip -4 route show default | awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}')
  fi
  if [[ -z ${WAN_IP:-} && -n ${WAN_IF:-} ]]; then
    WAN_IP=$(ip -4 -o addr show dev "$WAN_IF" scope global | awk 'NR==1{split($4,a,"/");print a[1]}')
  fi

  [[ -n ${WAN_IF:-} && -n ${WAN_IP:-} ]] || {
    echo "Could not detect WAN interface/IP."
    return 1
  }
}

forward_tag() {
  printf 'gremgr:%s:%s:%s:%s' "$1" "$2" "$3" "$4"
}

ensure_forwarding() {
  printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-gremgr.conf
  sysctl -qw net.ipv4.ip_forward=1 || true
}

up_tunnel_conf() {
  local conf=$1
  # shellcheck disable=SC1090
  source "$conf"
  detect_wan || return 1
  modprobe ip_gre 2>/dev/null || true

  ip tunnel del "$NAME" 2>/dev/null || true
  if ! ip tunnel add "$NAME" mode gre remote "$REMOTE" ttl 255 dev "$WAN_IF"; then
    log "ERROR tunnel=$NAME remote=$REMOTE create_failed"
    return 1
  fi
  ip addr add "$LOCAL_TUN_IP/30" dev "$NAME"
  ip link set "$NAME" mtu "$MTU"
  ip link set "$NAME" up
  log "UP tunnel=$NAME remote=$REMOTE local_tun=$LOCAL_TUN_IP peer=$REMOTE_TUN_IP wan=$WAN_IF"
}

apply_forward_conf() {
  local conf=$1 TAG WAN_IF WAN_IP
  # shellcheck disable=SC1090
  source "$conf"
  detect_wan || return 1
  TAG=$(forward_tag "$TUNNEL" "$PROTO" "$LISTEN_PORT" "$DEST_PORT")

  iptables -w -t nat -C PREROUTING -i "$WAN_IF" -p "$PROTO" --dport "$LISTEN_PORT" \
    -m comment --comment "$TAG" -j DNAT --to-destination "$DEST_IP:$DEST_PORT" 2>/dev/null || \
  iptables -w -t nat -A PREROUTING -i "$WAN_IF" -p "$PROTO" --dport "$LISTEN_PORT" \
    -m comment --comment "$TAG" -j DNAT --to-destination "$DEST_IP:$DEST_PORT"

  iptables -w -t nat -C POSTROUTING -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null || \
  iptables -w -t nat -A POSTROUTING -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j MASQUERADE

  iptables -w -C FORWARD -i "$WAN_IF" -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j ACCEPT 2>/dev/null || \
  iptables -w -A FORWARD -i "$WAN_IF" -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j ACCEPT

  local rtag="gremgr:${TUNNEL}:return"
  iptables -w -C FORWARD -i "$TUNNEL" -o "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "$rtag" -j ACCEPT 2>/dev/null || \
  iptables -w -A FORWARD -i "$TUNNEL" -o "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "$rtag" -j ACCEPT

  log "FWD tunnel=$TUNNEL proto=$PROTO listen=$LISTEN_PORT dest=$DEST_IP:$DEST_PORT"
}

restore_all() {
  need_root
  mkdirs
  ensure_forwarding
  shopt -s nullglob
  local conf
  for conf in "$TUN_DIR"/*.conf; do
    # shellcheck disable=SC1090
    source "$conf"
    [[ ${ENABLED:-1} == 1 ]] || continue
    up_tunnel_conf "$conf" || true
  done
  for conf in "$FWD_DIR"/*.conf; do
    apply_forward_conf "$conf" || true
  done
  log "RESTORE complete"
}

restore_all
