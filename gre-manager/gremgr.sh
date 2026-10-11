#!/usr/bin/env bash
set -u

VERSION="0.1.0"
BASE_DIR="/etc/gremgr"
TUN_DIR="$BASE_DIR/tunnels"
FWD_DIR="$BASE_DIR/forwards"
LOG_FILE="/var/log/gremgr.log"
SERVICE_FILE="/etc/systemd/system/gremgr.service"
MTU_DEFAULT=1400

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

valid_ipv4() {
  local ip=$1 a b c d
  IFS=. read -r a b c d <<< "$ip" || return 1
  [[ -n ${a:-} && -n ${b:-} && -n ${c:-} && -n ${d:-} ]] || return 1
  for x in "$a" "$b" "$c" "$d"; do
    [[ $x =~ ^[0-9]+$ ]] || return 1
    (( x >= 0 && x <= 255 )) || return 1
  done
}

ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
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

pair_values() {
  local remote=$1 pair hash h val idx addr s3 s4 ln rn
  detect_wan || return 1
  pair=$(printf '%s\n%s\n' "$WAN_IP" "$remote" | sort | paste -sd-)
  hash=$(printf '%s' "$pair" | sha256sum | awk '{print $1}')
  h=${hash:0:5}
  val=$((16#$h))
  idx=$((val % 262144))
  addr=$((idx * 4))
  PAIR_O2=$((240 + addr / 65536))
  PAIR_O3=$(((addr % 65536) / 256))
  PAIR_O4=$((addr % 256))
  PAIR_NAME="gre-${hash:0:6}"

  ln=$(ip_to_int "$WAN_IP")
  rn=$(ip_to_int "$remote")
  if (( ln == rn )); then
    echo "Local and remote IP cannot be the same."
    return 1
  elif (( ln < rn )); then
    PAIR_LOCAL="10.${PAIR_O2}.${PAIR_O3}.$((PAIR_O4 + 1))"
    PAIR_REMOTE="10.${PAIR_O2}.${PAIR_O3}.$((PAIR_O4 + 2))"
  else
    PAIR_LOCAL="10.${PAIR_O2}.${PAIR_O3}.$((PAIR_O4 + 2))"
    PAIR_REMOTE="10.${PAIR_O2}.${PAIR_O3}.$((PAIR_O4 + 1))"
  fi
}

save_tunnel_conf() {
  local file=$1 name=$2 remote=$3 local_ip=$4 peer_ip=$5 mtu=$6 enabled=$7
  cat > "$file" <<CFG
NAME=$(printf '%q' "$name")
REMOTE=$(printf '%q' "$remote")
LOCAL_TUN_IP=$(printf '%q' "$local_ip")
REMOTE_TUN_IP=$(printf '%q' "$peer_ip")
MTU=$(printf '%q' "$mtu")
ENABLED=$(printf '%q' "$enabled")
CFG
  chmod 600 "$file"
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

down_tunnel_name() {
  local name=$1
  ip tunnel del "$name" 2>/dev/null || true
  log "DOWN tunnel=$name"
}

forward_tag() {
  printf 'gremgr:%s:%s:%s:%s' "$1" "$2" "$3" "$4"
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

remove_forward_conf() {
  local conf=$1 TAG WAN_IF WAN_IP
  [[ -f $conf ]] || return 0
  # shellcheck disable=SC1090
  source "$conf"
  detect_wan || return 0
  TAG=$(forward_tag "$TUNNEL" "$PROTO" "$LISTEN_PORT" "$DEST_PORT")

  while iptables -w -t nat -C PREROUTING -i "$WAN_IF" -p "$PROTO" --dport "$LISTEN_PORT" \
    -m comment --comment "$TAG" -j DNAT --to-destination "$DEST_IP:$DEST_PORT" 2>/dev/null; do
    iptables -w -t nat -D PREROUTING -i "$WAN_IF" -p "$PROTO" --dport "$LISTEN_PORT" \
      -m comment --comment "$TAG" -j DNAT --to-destination "$DEST_IP:$DEST_PORT"
  done

  while iptables -w -t nat -C POSTROUTING -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null; do
    iptables -w -t nat -D POSTROUTING -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
      -m comment --comment "$TAG" -j MASQUERADE
  done

  while iptables -w -C FORWARD -i "$WAN_IF" -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
    -m comment --comment "$TAG" -j ACCEPT 2>/dev/null; do
    iptables -w -D FORWARD -i "$WAN_IF" -o "$TUNNEL" -p "$PROTO" -d "$DEST_IP" --dport "$DEST_PORT" \
      -m comment --comment "$TAG" -j ACCEPT
  done
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

install_service() {
  need_root
  mkdirs
  ensure_forwarding
  cat > "$SERVICE_FILE" <<'UNIT'
[Unit]
Description=GRE Manager restore
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gremgr --restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable gremgr.service >/dev/null
  log "INSTALL service_enabled version=$VERSION"
  echo "GRE Manager installed. Run: gremgr"
}

test_gre() {
  local remote test_name peer_ok=0 i
  read -r -p "Remote public IP: " remote
  valid_ipv4 "$remote" || { echo "Invalid IP."; return; }
  pair_values "$remote" || return
  test_name="gt-${PAIR_NAME#gre-}"

  cleanup_test() {
    ip tunnel del "$test_name" 2>/dev/null || true
    trap - EXIT INT TERM
    echo "Temporary test cleaned."
  }
  trap cleanup_test EXIT INT TERM HUP

  modprobe ip_gre 2>/dev/null || true
  ip tunnel del "$test_name" 2>/dev/null || true
  ip tunnel add "$test_name" mode gre remote "$remote" ttl 255 dev "$WAN_IF" || { cleanup_test; return; }
  ip addr add "$PAIR_LOCAL/30" dev "$test_name"
  ip link set "$test_name" mtu "$MTU_DEFAULT"
  ip link set "$test_name" up

  echo
  echo "Temporary GRE is ready."
  echo "Local : $WAN_IP ($WAN_IF)"
  echo "Peer  : $remote"
  echo "Inside: $PAIR_LOCAL -> $PAIR_REMOTE"
  echo "Run Test GRE on the other server too. Waiting up to 120s..."

  for ((i=1; i<=120; i++)); do
    if ping -I "$test_name" -c 1 -W 1 "$PAIR_REMOTE" >/dev/null 2>&1; then
      peer_ok=1
      break
    fi
    sleep 1
  done

  if (( peer_ok == 0 )); then
    echo "Test failed: peer did not answer."
    cleanup_test
    return
  fi

  echo
  ping -I "$test_name" -c 5 -W 2 "$PAIR_REMOTE"
  if ping -I "$test_name" -M do -s 1372 -c 2 -W 2 "$PAIR_REMOTE" >/dev/null 2>&1; then
    echo "MTU 1400: OK"
  else
    echo "MTU 1400: FAILED"
  fi
  echo
  read -r -p "Press Enter to finish and clean the test..." _
  cleanup_test
}

add_tunnel() {
  local remote conf
  read -r -p "Remote public IP: " remote
  valid_ipv4 "$remote" || { echo "Invalid IP."; return; }
  pair_values "$remote" || return
  conf="$TUN_DIR/$PAIR_NAME.conf"

  if [[ -f $conf ]]; then
    echo "Tunnel already exists: $PAIR_NAME"
    return
  fi

  save_tunnel_conf "$conf" "$PAIR_NAME" "$remote" "$PAIR_LOCAL" "$PAIR_REMOTE" "$MTU_DEFAULT" 1
  ensure_forwarding
  up_tunnel_conf "$conf" || { rm -f "$conf"; return; }
  install_service >/dev/null

  echo "Created: $PAIR_NAME"
  echo "Inside : $PAIR_LOCAL -> $PAIR_REMOTE"
  if ping -I "$PAIR_NAME" -c 2 -W 2 "$PAIR_REMOTE" >/dev/null 2>&1; then
    echo "Status : UP"
  else
    echo "Status : created; peer is not answering yet"
  fi
}

get_tunnel_files() {
  shopt -s nullglob
  TUN_FILES=("$TUN_DIR"/*.conf)
}

select_tunnel() {
  local i n
  get_tunnel_files
  ((${#TUN_FILES[@]})) || { echo "No tunnels."; return 1; }
  echo
  for i in "${!TUN_FILES[@]}"; do
    # shellcheck disable=SC1090
    source "${TUN_FILES[$i]}"
    if ip link show "$NAME" >/dev/null 2>&1; then
      printf '%d) %s -> %s [UP]\n' "$((i+1))" "$NAME" "$REMOTE"
    else
      printf '%d) %s -> %s [DOWN]\n' "$((i+1))" "$NAME" "$REMOTE"
    fi
  done
  read -r -p "Select: " n
  [[ $n =~ ^[0-9]+$ ]] || return 1
  (( n >= 1 && n <= ${#TUN_FILES[@]} )) || return 1
  SELECTED_CONF=${TUN_FILES[$((n-1))]}
}

show_tunnel_status() {
  local conf=$1
  # shellcheck disable=SC1090
  source "$conf"
  echo
  echo "$NAME -> $REMOTE"
  ip -br addr show "$NAME" 2>/dev/null || echo "Tunnel is DOWN"
  if ip link show "$NAME" >/dev/null 2>&1; then
    ping -I "$NAME" -c 3 -W 2 "$REMOTE_TUN_IP" || true
  fi
}

restart_tunnel() {
  local conf=$1
  # shellcheck disable=SC1090
  source "$conf"
  down_tunnel_name "$NAME"
  if up_tunnel_conf "$conf"; then
    echo "Restarted: $NAME"
    show_tunnel_status "$conf"
  else
    echo "Restart failed: $NAME"
  fi
  echo
  echo "Recent logs:"
  tail -n 8 "$LOG_FILE" 2>/dev/null || true
}

edit_tunnel() {
  local conf=$1 old_name old_remote old_local old_peer old_mtu old_enabled choice value
  # shellcheck disable=SC1090
  source "$conf"
  old_name=$NAME; old_remote=$REMOTE; old_local=$LOCAL_TUN_IP; old_peer=$REMOTE_TUN_IP; old_mtu=$MTU; old_enabled=$ENABLED
  echo "1) Remote IP"
  echo "2) MTU"
  echo "0) Back"
  read -r -p "Select: " choice
  case "$choice" in
    1)
      read -r -p "New remote IP: " value
      valid_ipv4 "$value" || { echo "Invalid IP."; return; }
      old_remote=$value
      ;;
    2)
      read -r -p "New MTU [current $old_mtu]: " value
      [[ $value =~ ^[0-9]+$ ]] && (( value >= 576 && value <= 1500 )) || { echo "Invalid MTU."; return; }
      old_mtu=$value
      ;;
    0) return ;;
    *) return ;;
  esac
  save_tunnel_conf "$conf" "$old_name" "$old_remote" "$old_local" "$old_peer" "$old_mtu" "$old_enabled"
  restart_tunnel "$conf"
}

toggle_tunnel() {
  local conf=$1
  # shellcheck disable=SC1090
  source "$conf"
  if [[ ${ENABLED:-1} == 1 ]]; then
    save_tunnel_conf "$conf" "$NAME" "$REMOTE" "$LOCAL_TUN_IP" "$REMOTE_TUN_IP" "$MTU" 0
    down_tunnel_name "$NAME"
    echo "Disabled: $NAME"
  else
    save_tunnel_conf "$conf" "$NAME" "$REMOTE" "$LOCAL_TUN_IP" "$REMOTE_TUN_IP" "$MTU" 1
    up_tunnel_conf "$conf"
    echo "Enabled: $NAME"
  fi
}

delete_tunnel() {
  local conf=$1 answer f
  # shellcheck disable=SC1090
  source "$conf"
  read -r -p "Delete $NAME? [y/N]: " answer
  [[ $answer =~ ^[Yy]$ ]] || return

  shopt -s nullglob
  for f in "$FWD_DIR"/*.conf; do
    # shellcheck disable=SC1090
    source "$f"
    if [[ $TUNNEL == "$NAME" ]]; then
      remove_forward_conf "$f"
      rm -f "$f"
    fi
  done
  down_tunnel_name "$NAME"
  rm -f "$conf"
  echo "Deleted: $NAME"
}

manage_tunnels() {
  local c
  select_tunnel || return
  while true; do
    # shellcheck disable=SC1090
    source "$SELECTED_CONF"
    echo
    echo "$NAME -> $REMOTE"
    echo "1) Status"
    echo "2) Restart"
    echo "3) Edit"
    echo "4) Enable / Disable"
    echo "5) Delete"
    echo "0) Back"
    read -r -p "Select: " c
    case "$c" in
      1) show_tunnel_status "$SELECTED_CONF" ;;
      2) restart_tunnel "$SELECTED_CONF" ;;
      3) edit_tunnel "$SELECTED_CONF" ;;
      4) toggle_tunnel "$SELECTED_CONF" ;;
      5) delete_tunnel "$SELECTED_CONF"; return ;;
      0) return ;;
    esac
  done
}

save_forward_conf() {
  local file=$1 tunnel=$2 proto=$3 listen=$4 dest=$5 dip=$6
  cat > "$file" <<CFG
TUNNEL=$(printf '%q' "$tunnel")
PROTO=$(printf '%q' "$proto")
LISTEN_PORT=$(printf '%q' "$listen")
DEST_PORT=$(printf '%q' "$dest")
DEST_IP=$(printf '%q' "$dip")
CFG
  chmod 600 "$file"
}

add_forward_one() {
  local tunnel=$1 peer_ip=$2 proto=$3 listen=$4 dest=$5 file
  file="$FWD_DIR/${tunnel}_${proto}_${listen}.conf"
  save_forward_conf "$file" "$tunnel" "$proto" "$listen" "$dest" "$peer_ip"
  apply_forward_conf "$file"
}

add_forward() {
  local proto_choice listen dest
  select_tunnel || return
  # shellcheck disable=SC1090
  source "$SELECTED_CONF"

  echo "1) TCP"
  echo "2) UDP"
  echo "3) TCP + UDP"
  read -r -p "Protocol: " proto_choice
  read -r -p "Listen port: " listen
  [[ $listen =~ ^[0-9]+$ ]] && ((listen >= 1 && listen <= 65535)) || { echo "Invalid port."; return; }
  read -r -p "Destination port [$listen]: " dest
  dest=${dest:-$listen}
  [[ $dest =~ ^[0-9]+$ ]] && ((dest >= 1 && dest <= 65535)) || { echo "Invalid port."; return; }

  case "$proto_choice" in
    1) add_forward_one "$NAME" "$REMOTE_TUN_IP" tcp "$listen" "$dest" ;;
    2) add_forward_one "$NAME" "$REMOTE_TUN_IP" udp "$listen" "$dest" ;;
    3)
      add_forward_one "$NAME" "$REMOTE_TUN_IP" tcp "$listen" "$dest"
      add_forward_one "$NAME" "$REMOTE_TUN_IP" udp "$listen" "$dest"
      ;;
    *) return ;;
  esac
  echo "Forward added to $REMOTE_TUN_IP:$dest"
}

list_forwards() {
  local files i n answer
  shopt -s nullglob
  files=("$FWD_DIR"/*.conf)
  ((${#files[@]})) || { echo "No port forwards."; return; }
  echo
  for i in "${!files[@]}"; do
    # shellcheck disable=SC1090
    source "${files[$i]}"
    printf '%d) %s %s:%s -> %s:%s\n' "$((i+1))" "$TUNNEL" "$PROTO" "$LISTEN_PORT" "$DEST_IP" "$DEST_PORT"
  done
  read -r -p "Delete one? Number or Enter to back: " n
  [[ -n $n ]] || return
  [[ $n =~ ^[0-9]+$ ]] || return
  (( n >= 1 && n <= ${#files[@]} )) || return
  read -r -p "Delete this forward? [y/N]: " answer
  [[ $answer =~ ^[Yy]$ ]] || return
  remove_forward_conf "${files[$((n-1))]}"
  rm -f "${files[$((n-1))]}"
  echo "Forward deleted."
}

port_forward_menu() {
  local c
  while true; do
    echo
    echo "1) Add"
    echo "2) List / Delete"
    echo "0) Back"
    read -r -p "Select: " c
    case "$c" in
      1) add_forward ;;
      2) list_forwards ;;
      0) return ;;
    esac
  done
}

status_logs() {
  local conf
  echo
  echo "=== Tunnels ==="
  get_tunnel_files
  if ((${#TUN_FILES[@]} == 0)); then
    echo "No tunnels."
  else
    for conf in "${TUN_FILES[@]}"; do
      # shellcheck disable=SC1090
      source "$conf"
      if ip link show "$NAME" >/dev/null 2>&1; then
        echo "$NAME -> $REMOTE : UP"
      else
        echo "$NAME -> $REMOTE : DOWN"
      fi
    done
  fi
  echo
  echo "=== Current boot restore ==="
  journalctl -u gremgr.service -b --no-pager -n 25 2>/dev/null || true
  echo
  echo "=== Recent manager log ==="
  tail -n 25 "$LOG_FILE" 2>/dev/null || true
}

main_menu() {
  local c
  need_root
  mkdirs
  while true; do
    echo
    echo "GRE Manager v$VERSION"
    echo "1) Test GRE"
    echo "2) Add Tunnel"
    echo "3) Tunnels"
    echo "4) Port Forward"
    echo "5) Status / Logs"
    echo "0) Exit"
    read -r -p "Select: " c
    case "$c" in
      1) test_gre ;;
      2) add_tunnel ;;
      3) manae_tunnels ;;
      4) port_forward_menu ;;
      5) status_logs ;;
      0) exit 0 ;;
    esac
  done
}

case "${1:-}" in
  --restore) restore_all ;;
  --install) install_service ;;
  --version) echo "$VERSION" ;;
  --help|-h)
    echo "Usage: gremgr [--install|--restore|--version]"
    ;;
  *) main_menu ;;
esac
