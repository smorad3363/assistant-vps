#!/usr/bin/env bash
set -Eeuo pipefail

# Permanent install/update command:
# curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-link-tool.sh -o /tmp/gre-link-tool.sh && sudo install -m 755 /tmp/gre-link-tool.sh /usr/local/bin/gre-link-tool && sudo gre-link-tool

APP="gre-link-tool"
VERSION="2.1"
CONFIG="/etc/${APP}.conf"
LOG_DIR="/var/log/${APP}"
INSTALL_PATH="/usr/local/bin/${APP}"
UPDATE_URL="https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-link-tool.sh"
SERVICE="${APP}.service"
WATCHDOG_SERVICE="${APP}-watchdog.service"
WATCHDOG_TIMER="${APP}-watchdog.timer"
HELPER_UP="/usr/local/sbin/${APP}-up"
HELPER_DOWN="/usr/local/sbin/${APP}-down"
HELPER_WATCHDOG="/usr/local/sbin/${APP}-watchdog"

DEFAULT_IPERF_PORT="5202"
DEFAULT_RATE="1G"
DEFAULT_MTU="1400"
DEFAULT_IFACE="gre-wg"
DEFAULT_FORWARD_PORT="51820"
DEFAULT_WATCHDOG_INTERVAL="30"
DEFAULT_WATCHDOG_FAIL_THRESHOLD="3"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[%s] [OK] %s\n' "$(date '+%F %T')" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(date '+%F %T')" "$*"; }
err()  { printf '[%s] [ERROR] %s\n' "$(date '+%F %T')" "$*" >&2; }
die()  { err "$*"; exit 1; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "This script must be run as root."

if [[ -f "$CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG"
fi

# Backward-compatible migration from v1 config.
SITE_ROLE="${SITE_ROLE:-${ROLE:-}}"
LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-}"
PEER_PUBLIC_IP="${PEER_PUBLIC_IP:-}"
IPERF_PORT="${IPERF_PORT:-$DEFAULT_IPERF_PORT}"
TARGET_RATE="${TARGET_RATE:-$DEFAULT_RATE}"
GRE_IFACE="${GRE_IFACE:-$DEFAULT_IFACE}"
GRE_MTU="${GRE_MTU:-$DEFAULT_MTU}"
LOCAL_TUN_CIDR="${LOCAL_TUN_CIDR:-}"
PEER_TUN_IP="${PEER_TUN_IP:-}"
FORWARD_PORT="${FORWARD_PORT:-$DEFAULT_FORWARD_PORT}"
FORWARD_PROTO="${FORWARD_PROTO:-udp}"
ENABLE_FORWARD="${ENABLE_FORWARD:-yes}"
WATCHDOG_ENABLED="${WATCHDOG_ENABLED:-yes}"
WATCHDOG_INTERVAL="${WATCHDOG_INTERVAL:-$DEFAULT_WATCHDOG_INTERVAL}"
WATCHDOG_FAIL_THRESHOLD="${WATCHDOG_FAIL_THRESHOLD:-$DEFAULT_WATCHDOG_FAIL_THRESHOLD}"

save_config() {
  umask 077
  cat > "$CONFIG" <<EOF_CFG
SITE_ROLE=$(printf '%q' "$SITE_ROLE")
LOCAL_PUBLIC_IP=$(printf '%q' "$LOCAL_PUBLIC_IP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
IPERF_PORT=$(printf '%q' "$IPERF_PORT")
TARGET_RATE=$(printf '%q' "$TARGET_RATE")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
GRE_MTU=$(printf '%q' "$GRE_MTU")
LOCAL_TUN_CIDR=$(printf '%q' "$LOCAL_TUN_CIDR")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
ENABLE_FORWARD=$(printf '%q' "$ENABLE_FORWARD")
WATCHDOG_ENABLED=$(printf '%q' "$WATCHDOG_ENABLED")
WATCHDOG_INTERVAL=$(printf '%q' "$WATCHDOG_INTERVAL")
WATCHDOG_FAIL_THRESHOLD=$(printf '%q' "$WATCHDOG_FAIL_THRESHOLD")
EOF_CFG
  chmod 600 "$CONFIG"
}

valid_ipv4() {
  local ip=${1:-} IFS=. a b c d
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  read -r a b c d <<< "$ip" || return 1
  for n in "$a" "$b" "$c" "$d"; do
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    (( 10#$n >= 0 && 10#$n <= 255 )) || return 1
  done
}

valid_cidr() {
  local value=${1:-} ip prefix
  [[ "$value" == */* ]] || return 1
  ip=${value%/*}
  prefix=${value#*/}
  valid_ipv4 "$ip" || return 1
  [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
  (( 10#$prefix >= 0 && 10#$prefix <= 32 ))
}

valid_port() {
  local port=${1:-}
  [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
}

valid_iface() {
  local iface=${1:-}
  [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
}

valid_mtu() {
  local mtu=${1:-}
  [[ "$mtu" =~ ^[0-9]+$ ]] && (( 10#$mtu >= 576 && 10#$mtu <= 9000 ))
}

valid_rate() {
  local rate=${1:-}
  [[ "$rate" =~ ^[0-9]+([KkMmGgTtPp])?$ ]]
}

valid_watchdog_interval() {
  local seconds=${1:-}
  [[ "$seconds" =~ ^[0-9]+$ ]] && (( 10#$seconds >= 10 && 10#$seconds <= 3600 ))
}

valid_watchdog_threshold() {
  local count=${1:-}
  [[ "$count" =~ ^[0-9]+$ ]] && (( 10#$count >= 1 && 10#$count <= 20 ))
}

is_private_ipv4() {
  local ip=${1:-}
  valid_ipv4 "$ip" || return 1
  [[ "$ip" == 10.* || "$ip" == 192.168.* || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]
}

detect_main_ip() {
  local ip
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  printf '%s' "$ip"
}

detect_main_iface() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

auto_update_or_install() {
  [[ "${GRE_LINK_TOOL_SKIP_UPDATE:-0}" == "1" ]] && return 0

  local tmp self updated=0
  tmp="$(mktemp "/tmp/${APP}.update.XXXXXX")"
  self="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"

  if command -v curl >/dev/null 2>&1; then
    if ! curl -fsSL --connect-timeout 5 --max-time 20 "$UPDATE_URL" -o "$tmp"; then
      warn "Auto-update check failed; continuing with the installed version."
      rm -f "$tmp"
      return 0
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! wget -qO "$tmp" "$UPDATE_URL"; then
      warn "Auto-update check failed; continuing with the installed version."
      rm -f "$tmp"
      return 0
    fi
  else
    warn "curl/wget is unavailable, so the automatic update check was skipped."
    rm -f "$tmp"
    return 0
  fi

  if ! bash -n "$tmp" \
    || [[ "$(head -n 1 "$tmp")" != '#!/usr/bin/env bash' ]] \
    || ! grep -q '^APP="gre-link-tool"
install_deps() {
  local missing=()
  local command_name
  for command_name in ip ping iperf3 mtr tcpdump ss iptables awk sed grep timeout sysctl systemctl curl cmp; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done

  if (( ${#missing[@]} == 0 )); then
    ok "All required packages are already installed."
    return
  fi

  log "Installing required tools: ${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y iproute2 iputils-ping iperf3 mtr-tiny tcpdump iptables procps coreutils curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils curl
  else
    die "No supported package manager was found. Install iproute2, ping, iperf3, mtr, tcpdump, iptables, procps, coreutils and curl manually."
  fi
  ok "Dependencies installed."
}

prompt_public_ips() {
  local detected x
  detected="$(detect_main_ip)"

  if valid_ipv4 "${LOCAL_PUBLIC_IP:-}"; then
    read -r -p "Local public/source IPv4 [$LOCAL_PUBLIC_IP]: " x
    LOCAL_PUBLIC_IP="${x:-$LOCAL_PUBLIC_IP}"
  elif valid_ipv4 "$detected"; then
    read -r -p "Local public/source IPv4 [$detected]: " x
    LOCAL_PUBLIC_IP="${x:-$detected}"
  else
    read -r -p "Local public/source IPv4: " LOCAL_PUBLIC_IP
  fi
  valid_ipv4 "$LOCAL_PUBLIC_IP" || die "Invalid local IPv4 address: $LOCAL_PUBLIC_IP"

  if is_private_ipv4 "$LOCAL_PUBLIC_IP"; then
    warn "The selected local address is private. GRE will only work if this address is actually reachable from the peer or NAT is configured appropriately."
  fi

  if valid_ipv4 "${PEER_PUBLIC_IP:-}"; then
    read -r -p "Peer public IPv4 [$PEER_PUBLIC_IP]: " x
    PEER_PUBLIC_IP="${x:-$PEER_PUBLIC_IP}"
  else
    read -r -p "Peer public IPv4: " PEER_PUBLIC_IP
  fi
  valid_ipv4 "$PEER_PUBLIC_IP" || die "Invalid peer IPv4 address: $PEER_PUBLIC_IP"
}

prompt_iperf_settings() {
  local x
  read -r -p "iperf3 port [$IPERF_PORT]: " x
  IPERF_PORT="${x:-$IPERF_PORT}"
  valid_port "$IPERF_PORT" || die "Invalid iperf3 port: $IPERF_PORT"

  read -r -p "UDP target rate [$TARGET_RATE]: " x
  TARGET_RATE="${x:-$TARGET_RATE}"
  valid_rate "$TARGET_RATE" || die "Invalid iperf3 rate. Examples: 500M, 1G, 250K."

  save_config
}

show_env() {
  local iface
  iface="$(detect_main_iface)"
  log "Version: $VERSION"
  log "LocalPublic=$LOCAL_PUBLIC_IP"
  log "PeerPublic=$PEER_PUBLIC_IP"
  log "MainIface=${iface:-unknown}"
  log "iperfPort=$IPERF_PORT"
  log "TargetRate=$TARGET_RATE"
  log "Kernel=$(uname -r)"
  log "CPU=$(nproc 2>/dev/null || echo '?') core(s)"
  log "Memory=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || true)"
  ip -br addr || true
  ip route || true
}

run_ping_test() {
  log "---- Ping quality to $PEER_PUBLIC_IP ----"
  ping -n -c 20 -i 0.2 -W 1 "$PEER_PUBLIC_IP" || warn "Ping loss or timeout was detected."
}

run_mtr_test() {
  log "---- MTR to $PEER_PUBLIC_IP ----"
  mtr -rwzc 20 "$PEER_PUBLIC_IP" || warn "MTR did not complete successfully."
}

run_pmtu_test() {
  log "---- Path MTU probe ----"
  local payload found=""
  for payload in 1472 1464 1452 1440 1420 1400 1380 1360 1320 1280 1240 1200; do
    if ping -n -c 2 -W 1 -M do -s "$payload" "$PEER_PUBLIC_IP" >/dev/null 2>&1; then
      found="$payload"
      break
    fi
  done

  if [[ -n "$found" ]]; then
    ok "Largest tested ICMP payload that passed: ${found} bytes; approximate IPv4 MTU: $((found + 28))."
  else
    warn "Even a 1200-byte payload with DF set failed. PMTU discovery or ICMP filtering may be a problem."
  fi
}

IPERF_FW_TAG="${APP}-iperf"
IPERF_TCP_RULE_ADDED=0
IPERF_UDP_RULE_ADDED=0

fw_allow_iperf() {
  local tcp_rule=(-p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)
  local udp_rule=(-p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)

  if ! iptables -C INPUT "${tcp_rule[@]}" 2>/dev/null; then
    iptables -I INPUT 1 "${tcp_rule[@]}"
    IPERF_TCP_RULE_ADDED=1
  fi
  if ! iptables -C INPUT "${udp_rule[@]}" 2>/dev/null; then
    iptables -I INPUT 1 "${udp_rule[@]}"
    IPERF_UDP_RULE_ADDED=1
  fi
}

fw_cleanup_iperf() {
  local tcp_rule=(-p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)
  local udp_rule=(-p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)

  if (( IPERF_TCP_RULE_ADDED )); then
    iptables -D INPUT "${tcp_rule[@]}" 2>/dev/null || true
  fi
  if (( IPERF_UDP_RULE_ADDED )); then
    iptables -D INPUT "${udp_rule[@]}" 2>/dev/null || true
  fi
}

check_iperf_port_available() {
  if ss -ltnH "sport = :$IPERF_PORT" 2>/dev/null | grep -q .; then
    warn "TCP/$IPERF_PORT is already in use:"
    ss -ltnp "sport = :$IPERF_PORT" || true
    die "Choose another iperf3 port or stop the process using TCP/$IPERF_PORT."
  fi
}

start_iperf_listener() {
  install_deps
  prompt_public_ips
  prompt_iperf_settings
  check_iperf_port_available
  fw_allow_iperf

  trap 'exit 130' INT TERM
  trap 'fw_cleanup_iperf; log "Temporary iperf3 firewall rules removed."' EXIT

  echo
  log "iperf3 LISTENER mode is active."
  log "Peer allowed: $PEER_PUBLIC_IP"
  log "Listening on TCP/UDP port $IPERF_PORT"
  log "On the other server, choose: 'Run bidirectional sender test'."
  log "The sender will test LOCAL -> PEER and PEER -> LOCAL while this side keeps listening."
  log "Press Ctrl+C to stop the listener."
  echo

  iperf3 -s -p "$IPERF_PORT" --forceflush
}

run_iperf_case() {
  local name=$1
  shift
  local out="$LOG_DIR/iperf-${name}-$(date +%H%M%S).log"

  log "---- iperf3: $name ----"
  log "Command: iperf3 $*"
  set +e
  iperf3 "$@" 2>&1 | tee "$out"
  local rc=${PIPESTATUS[0]}
  set -e

  if (( rc != 0 )); then
    warn "$name failed with exit code $rc."
    return "$rc"
  fi

  log "Summary: $name"
  grep -E 'sender$|receiver$|SUM.*receiver$|SUM.*sender$' "$out" | tail -n 10 || tail -n 10 "$out"
}

run_bidirectional_sender_test() {
  install_deps
  prompt_public_ips
  prompt_iperf_settings
  show_env

  echo
  log "This host is the SENDER/TESTER. The peer must already be running iperf3 LISTENER mode."
  log "The normal tests send payload LOCAL -> PEER."
  log "The reverse (-R) tests send payload PEER -> LOCAL over the same control session."
  echo

  run_ping_test
  run_mtr_test
  run_pmtu_test

  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$PEER_PUBLIC_IP/$IPERF_PORT" 2>/dev/null; then
    ok "iperf3 control port $PEER_PUBLIC_IP:$IPERF_PORT is reachable."
  else
    die "Cannot reach TCP/$IPERF_PORT on $PEER_PUBLIC_IP. Start LISTENER mode on the peer and check its firewall/security group."
  fi

  run_iperf_case "tcp-local-to-peer" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20 -O 2 --get-server-output || true

  run_iperf_case "tcp-peer-to-local" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20 -O 2 -R --get-server-output || true

  run_iperf_case "udp-${TARGET_RATE}-local-to-peer" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20 -O 2 --get-server-output || true

  run_iperf_case "udp-${TARGET_RATE}-peer-to-local" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20 -O 2 -R --get-server-output || true

  log "---- Main interface counters after test ----"
  local main_iface
  main_iface="$(detect_main_iface)"
  [[ -n "$main_iface" ]] && ip -s link show dev "$main_iface" || true

  ok "Bidirectional throughput test completed."
  log "LOCAL -> PEER and PEER -> LOCAL were measured separately."
  log "If you want a literal process-role swap too, stop the current listener, start LISTENER here, and run SENDER on the other host."
}

run_path_diagnostics() {
  install_deps
  prompt_public_ips
  save_config
  show_env
  run_ping_test
  run_mtr_test
  run_pmtu_test
}

choose_site_role() {
  local x ans
  if [[ "$SITE_ROLE" == "iran" || "$SITE_ROLE" == "remote" ]]; then
    printf 'Saved GRE site role: %s\n' "$SITE_ROLE"
    read -r -p "Use the saved role? [Y/n]: " ans
    ans="${ans:-Y}"
    [[ "$ans" =~ ^[Yy]$ ]] && return
  fi

  echo
  echo "Select this server's GRE site role:"
  echo "  1) Iran gateway"
  echo "  2) Remote gateway"
  read -r -p "Selection: " x
  case "$x" in
    1) SITE_ROLE="iran" ;;
    2) SITE_ROLE="remote" ;;
    *) die "Invalid selection." ;;
  esac
}

default_tunnel_ips() {
  if [[ "$SITE_ROLE" == "iran" ]]; then
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.2/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.1"
  else
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.1/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.2"
  fi
}

validate_tunnel_settings() {
  [[ "$SITE_ROLE" == "iran" || "$SITE_ROLE" == "remote" ]] || die "GRE site role must be iran or remote."
  valid_ipv4 "$LOCAL_PUBLIC_IP" || die "Invalid local public IPv4: $LOCAL_PUBLIC_IP"
  valid_ipv4 "$PEER_PUBLIC_IP" || die "Invalid peer public IPv4: $PEER_PUBLIC_IP"
  valid_iface "$GRE_IFACE" || die "Invalid GRE interface name: $GRE_IFACE"
  valid_cidr "$LOCAL_TUN_CIDR" || die "Invalid local tunnel CIDR: $LOCAL_TUN_CIDR"
  valid_ipv4 "$PEER_TUN_IP" || die "Invalid peer tunnel IPv4: $PEER_TUN_IP"
  valid_mtu "$GRE_MTU" || die "Invalid GRE MTU: $GRE_MTU"
  valid_port "$IPERF_PORT" || die "Invalid iperf3 port: $IPERF_PORT"
  valid_rate "$TARGET_RATE" || die "Invalid iperf3 rate. Examples: 500M, 1G, 250K."
  valid_port "$FORWARD_PORT" || die "Invalid forwarding port: $FORWARD_PORT"
  [[ "$FORWARD_PROTO" == "udp" || "$FORWARD_PROTO" == "tcp" ]] || die "Forward protocol must be tcp or udp."
  [[ "$ENABLE_FORWARD" == "yes" || "$ENABLE_FORWARD" == "no" ]] || die "ENABLE_FORWARD must be yes or no."
  [[ "$WATCHDOG_ENABLED" == "yes" || "$WATCHDOG_ENABLED" == "no" ]] || die "WATCHDOG_ENABLED must be yes or no."
  valid_watchdog_interval "$WATCHDOG_INTERVAL" || die "Watchdog interval must be between 10 and 3600 seconds."
  valid_watchdog_threshold "$WATCHDOG_FAIL_THRESHOLD" || die "Watchdog failure threshold must be between 1 and 20."
}

show_saved_tunnel_config() {
  echo
  echo "Current tunnel configuration:"
  printf '  Site role:               %s\n' "${SITE_ROLE:-unset}"
  printf '  Local public IPv4:       %s\n' "${LOCAL_PUBLIC_IP:-unset}"
  printf '  Peer public IPv4:        %s\n' "${PEER_PUBLIC_IP:-unset}"
  printf '  GRE interface:           %s\n' "${GRE_IFACE:-unset}"
  printf '  Local tunnel CIDR:       %s\n' "${LOCAL_TUN_CIDR:-unset}"
  printf '  Peer tunnel IPv4:        %s\n' "${PEER_TUN_IP:-unset}"
  printf '  GRE MTU:                 %s\n' "${GRE_MTU:-unset}"
  printf '  iperf3 test port:        %s\n' "${IPERF_PORT:-unset}"
  printf '  UDP target rate:         %s\n' "${TARGET_RATE:-unset}"
  printf '  Forwarding enabled:      %s\n' "${ENABLE_FORWARD:-unset}"
  printf '  Forward protocol:        %s\n' "${FORWARD_PROTO:-unset}"
  printf '  Forward port:            %s\n' "${FORWARD_PORT:-unset}"
  printf '  Watchdog enabled:        %s\n' "${WATCHDOG_ENABLED:-unset}"
  printf '  Watchdog interval:       %ss\n' "${WATCHDOG_INTERVAL:-unset}"
  printf '  Watchdog fail threshold: %s\n' "${WATCHDOG_FAIL_THRESHOLD:-unset}"
  echo
}

prompt_watchdog_settings() {
  local x
  read -r -p "Enable automatic tunnel watchdog? [Y/n]: " x
  x="${x:-Y}"
  if [[ "$x" =~ ^[Yy]$ ]]; then
    WATCHDOG_ENABLED="yes"
    read -r -p "Watchdog check interval in seconds [$WATCHDOG_INTERVAL]: " x
    WATCHDOG_INTERVAL="${x:-$WATCHDOG_INTERVAL}"
    read -r -p "Failures before automatic repair [$WATCHDOG_FAIL_THRESHOLD]: " x
    WATCHDOG_FAIL_THRESHOLD="${x:-$WATCHDOG_FAIL_THRESHOLD}"
  else
    WATCHDOG_ENABLED="no"
  fi
}

write_gre_helpers() {
  local fwd_up="" fwd_down=""

  if [[ "$SITE_ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    fwd_up=$(cat <<'EOF_FWD_UP'
PREROUTING_RULE=(-p "$FORWARD_PROTO" -d "$LOCAL_PUBLIC_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j DNAT --to-destination "$PEER_TUN_IP:$FORWARD_PORT")
POSTROUTING_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j MASQUERADE)
FORWARD_OUT_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j ACCEPT)
FORWARD_RETURN_RULE=(-i "$GRE_IFACE" -p "$FORWARD_PROTO" -s "$PEER_TUN_IP" --sport "$FORWARD_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$FWD_TAG" -j ACCEPT)

iptables -t nat -C PREROUTING "${PREROUTING_RULE[@]}" 2>/dev/null || iptables -t nat -A PREROUTING "${PREROUTING_RULE[@]}"
iptables -t nat -C POSTROUTING "${POSTROUTING_RULE[@]}" 2>/dev/null || iptables -t nat -A POSTROUTING "${POSTROUTING_RULE[@]}"
iptables -C FORWARD "${FORWARD_OUT_RULE[@]}" 2>/dev/null || iptables -A FORWARD "${FORWARD_OUT_RULE[@]}"
iptables -C FORWARD "${FORWARD_RETURN_RULE[@]}" 2>/dev/null || iptables -A FORWARD "${FORWARD_RETURN_RULE[@]}"
EOF_FWD_UP
)

    fwd_down=$(cat <<'EOF_FWD_DOWN'
PREROUTING_RULE=(-p "$FORWARD_PROTO" -d "$LOCAL_PUBLIC_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j DNAT --to-destination "$PEER_TUN_IP:$FORWARD_PORT")
POSTROUTING_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j MASQUERADE)
FORWARD_OUT_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j ACCEPT)
FORWARD_RETURN_RULE=(-i "$GRE_IFACE" -p "$FORWARD_PROTO" -s "$PEER_TUN_IP" --sport "$FORWARD_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$FWD_TAG" -j ACCEPT)

iptables -t nat -D PREROUTING "${PREROUTING_RULE[@]}" 2>/dev/null || true
iptables -t nat -D POSTROUTING "${POSTROUTING_RULE[@]}" 2>/dev/null || true
iptables -D FORWARD "${FORWARD_OUT_RULE[@]}" 2>/dev/null || true
iptables -D FORWARD "${FORWARD_RETURN_RULE[@]}" 2>/dev/null || true
EOF_FWD_DOWN
)
  fi

  cat > "$HELPER_UP" <<EOF_UP
#!/usr/bin/env bash
set -Eeuo pipefail
APP=$(printf '%q' "$APP")
LOCAL_PUBLIC_IP=$(printf '%q' "$LOCAL_PUBLIC_IP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
GRE_MTU=$(printf '%q' "$GRE_MTU")
LOCAL_TUN_CIDR=$(printf '%q' "$LOCAL_TUN_CIDR")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
GRE_TAG="${APP}-gre"
FWD_TAG="${APP}-forward"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
GRE_INPUT_RULE=(-p gre -s "$PEER_PUBLIC_IP" -m comment --comment "\$GRE_TAG" -j ACCEPT)
iptables -C INPUT "\${GRE_INPUT_RULE[@]}" 2>/dev/null || iptables -I INPUT 1 "\${GRE_INPUT_RULE[@]}"

ip link show "$GRE_IFACE" >/dev/null 2>&1 && ip tunnel del "$GRE_IFACE" || true
ip tunnel add "$GRE_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$PEER_PUBLIC_IP" ttl 255
ip addr replace "$LOCAL_TUN_CIDR" dev "$GRE_IFACE"
ip link set dev "$GRE_IFACE" mtu "$GRE_MTU"
ip link set dev "$GRE_IFACE" txqueuelen 2000
ip link set dev "$GRE_IFACE" up
sysctl -w "net.ipv4.conf.${GRE_IFACE}.rp_filter=0" >/dev/null 2>&1 || true

$fwd_up
EOF_UP

  cat > "$HELPER_DOWN" <<EOF_DOWN
#!/usr/bin/env bash
set +e
APP=$(printf '%q' "$APP")
LOCAL_PUBLIC_IP=$(printf '%q' "$LOCAL_PUBLIC_IP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
GRE_TAG="${APP}-gre"
FWD_TAG="${APP}-forward"

$fwd_down

ip tunnel del "$GRE_IFACE" 2>/dev/null || true
GRE_INPUT_RULE=(-p gre -s "$PEER_PUBLIC_IP" -m comment --comment "\$GRE_TAG" -j ACCEPT)
iptables -D INPUT "\${GRE_INPUT_RULE[@]}" 2>/dev/null || true
EOF_DOWN

  chmod 700 "$HELPER_UP" "$HELPER_DOWN"

  cat > "/etc/systemd/system/$SERVICE" <<EOF_SERVICE
[Unit]
Description=Persistent GRE link managed by $APP
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$HELPER_UP
ExecStop=$HELPER_DOWN

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

show_tunnel_status() {
  log "---- GRE status ----"
  if ! ip link show "$GRE_IFACE" >/dev/null 2>&1; then
    warn "GRE interface $GRE_IFACE does not exist."
    systemctl --no-pager --full status "$SERVICE" 2>/dev/null || true
    return 1
  fi

  ip -d link show "$GRE_IFACE" || true
  ip -br addr show "$GRE_IFACE" || true
  ip route show dev "$GRE_IFACE" || true

  log "---- GRE peer ping: $PEER_TUN_IP ----"
  if ping -n -c 10 -i 0.2 -W 1 "$PEER_TUN_IP"; then
    ok "GRE is up and the peer tunnel IP responds."
  else
    warn "The GRE interface exists, but the peer tunnel IP does not respond."
    warn "Configure GRE on the peer too and make sure IP protocol 47 (GRE) is not blocked by the provider, host firewall, or security group."
  fi

  if [[ "$SITE_ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    log "---- Service forwarding ----"
    log "$LOCAL_PUBLIC_IP:$FORWARD_PORT/$FORWARD_PROTO -> $PEER_TUN_IP:$FORWARD_PORT through $GRE_IFACE"
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
    iptables -t nat -L POSTROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
  fi
}

configure_gre() {
  install_deps
  choose_site_role
  prompt_public_ips
  default_tunnel_ips

  local x
  read -r -p "GRE interface name [$GRE_IFACE]: " x
  GRE_IFACE="${x:-$GRE_IFACE}"

  read -r -p "Local tunnel CIDR [$LOCAL_TUN_CIDR]: " x
  LOCAL_TUN_CIDR="${x:-$LOCAL_TUN_CIDR}"

  read -r -p "Peer tunnel IPv4 [$PEER_TUN_IP]: " x
  PEER_TUN_IP="${x:-$PEER_TUN_IP}"

  read -r -p "GRE MTU [$GRE_MTU]: " x
  GRE_MTU="${x:-$GRE_MTU}"

  if [[ "$SITE_ROLE" == "iran" ]]; then
    echo
    warn "Optional forwarding DNATs one public service port on the Iran gateway to the peer's tunnel IP."
    read -r -p "Enable service forwarding from Iran to the remote gateway? [Y/n]: " x
    x="${x:-Y}"
    if [[ "$x" =~ ^[Yy]$ ]]; then
      ENABLE_FORWARD="yes"
      read -r -p "Forward protocol [${FORWARD_PROTO:-udp}]: " x
      FORWARD_PROTO="${x:-${FORWARD_PROTO:-udp}}"
      read -r -p "Forward port [$FORWARD_PORT]: " x
      FORWARD_PORT="${x:-$FORWARD_PORT}"
    else
      ENABLE_FORWARD="no"
    fi
  else
    ENABLE_FORWARD="no"
  fi

  validate_tunnel_settings
  save_config
  show_env

  log "GRE itself is not encrypted. If you carry WireGuard inside GRE, the WireGuard payload remains encrypted by WireGuard."

  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    log "Stopping the existing GRE service before applying the new configuration."
    systemctl stop "$SERVICE" || true
  fi

  write_gre_helpers
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  sleep 1
  systemctl --no-pager --full status "$SERVICE" || true
  show_tunnel_status || true
  ok "Persistent GRE configuration applied. It will start automatically after reboot."
}

show_saved_gre_status() {
  install_deps
  [[ -n "$GRE_IFACE" ]] || die "No GRE interface is configured."
  [[ -n "$PEER_TUN_IP" ]] || die "No peer tunnel IP is configured."
  show_tunnel_status || true
}

remove_gre() {
  install_deps
  log "Stopping and disabling $SERVICE."
  systemctl disable --now "$SERVICE" 2>/dev/null || true

  if [[ -x "$HELPER_DOWN" ]]; then
    "$HELPER_DOWN" || true
  else
    ip tunnel del "$GRE_IFACE" 2>/dev/null || true
  fi

  rm -f "/etc/systemd/system/$SERVICE" "$HELPER_UP" "$HELPER_DOWN"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  ok "GRE service and helper files removed. Saved configuration was kept in $CONFIG."
}

print_header() {
  echo "============================================================"
  echo " GRE Link Tool v$VERSION"
  echo " Log: $LOG_FILE"
  echo "============================================================"
}

main_menu() {
  print_header
  echo
  echo "  1) Start iperf3 listener"
  echo "  2) Run bidirectional iperf3 sender test"
  echo "  3) Run path diagnostics only"
  echo "  4) Configure persistent GRE tunnel"
  echo "  5) Show GRE tunnel status"
  echo "  6) Remove GRE tunnel service"
  echo

  local mode
  read -r -p "Selection [1-6]: " mode
  case "$mode" in
    1) start_iperf_listener ;;
    2) run_bidirectional_sender_test ;;
    3) run_path_diagnostics ;;
    4) configure_gre ;;
    5) show_saved_gre_status ;;
    6) remove_gre ;;
    *) die "Invalid selection." ;;
  esac
}

main_menu
log "Log saved: $LOG_FILE"
 "$tmp"; then
    warn "Downloaded update failed validation; keeping the current version."
    rm -f "$tmp"
    return 0
  fi

  if [[ ! -f "$INSTALL_PATH" ]] || ! cmp -s "$tmp" "$INSTALL_PATH"; then
    install -m 755 "$tmp" "$INSTALL_PATH"
    updated=1
    ok "Installed the latest version from GitHub to $INSTALL_PATH."
  fi
  rm -f "$tmp"

  if (( updated )) || [[ "$self" != "$INSTALL_PATH" ]]; then
    exec env GRE_LINK_TOOL_SKIP_UPDATE=1 "$INSTALL_PATH" "$@"
  fi
}

install_deps() {
  local missing=()
  local command_name
  for command_name in ip ping iperf3 mtr tcpdump ss iptables awk sed grep timeout sysctl systemctl; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done

  if (( ${#missing[@]} == 0 )); then
    ok "All required packages are already installed."
    return
  fi

  log "Installing required tools: ${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y iproute2 iputils-ping iperf3 mtr-tiny tcpdump iptables procps coreutils
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils
  else
    die "No supported package manager was found. Install iproute2, ping, iperf3, mtr, tcpdump, iptables, procps and coreutils manually."
  fi
  ok "Dependencies installed."
}

prompt_public_ips() {
  local detected x
  detected="$(detect_main_ip)"

  if valid_ipv4 "${LOCAL_PUBLIC_IP:-}"; then
    read -r -p "Local public/source IPv4 [$LOCAL_PUBLIC_IP]: " x
    LOCAL_PUBLIC_IP="${x:-$LOCAL_PUBLIC_IP}"
  elif valid_ipv4 "$detected"; then
    read -r -p "Local public/source IPv4 [$detected]: " x
    LOCAL_PUBLIC_IP="${x:-$detected}"
  else
    read -r -p "Local public/source IPv4: " LOCAL_PUBLIC_IP
  fi
  valid_ipv4 "$LOCAL_PUBLIC_IP" || die "Invalid local IPv4 address: $LOCAL_PUBLIC_IP"

  if is_private_ipv4 "$LOCAL_PUBLIC_IP"; then
    warn "The selected local address is private. GRE will only work if this address is actually reachable from the peer or NAT is configured appropriately."
  fi

  if valid_ipv4 "${PEER_PUBLIC_IP:-}"; then
    read -r -p "Peer public IPv4 [$PEER_PUBLIC_IP]: " x
    PEER_PUBLIC_IP="${x:-$PEER_PUBLIC_IP}"
  else
    read -r -p "Peer public IPv4: " PEER_PUBLIC_IP
  fi
  valid_ipv4 "$PEER_PUBLIC_IP" || die "Invalid peer IPv4 address: $PEER_PUBLIC_IP"
}

prompt_iperf_settings() {
  local x
  read -r -p "iperf3 port [$IPERF_PORT]: " x
  IPERF_PORT="${x:-$IPERF_PORT}"
  valid_port "$IPERF_PORT" || die "Invalid iperf3 port: $IPERF_PORT"

  read -r -p "UDP target rate [$TARGET_RATE]: " x
  TARGET_RATE="${x:-$TARGET_RATE}"
  valid_rate "$TARGET_RATE" || die "Invalid iperf3 rate. Examples: 500M, 1G, 250K."

  save_config
}

show_env() {
  local iface
  iface="$(detect_main_iface)"
  log "Version: $VERSION"
  log "LocalPublic=$LOCAL_PUBLIC_IP"
  log "PeerPublic=$PEER_PUBLIC_IP"
  log "MainIface=${iface:-unknown}"
  log "iperfPort=$IPERF_PORT"
  log "TargetRate=$TARGET_RATE"
  log "Kernel=$(uname -r)"
  log "CPU=$(nproc 2>/dev/null || echo '?') core(s)"
  log "Memory=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || true)"
  ip -br addr || true
  ip route || true
}

run_ping_test() {
  log "---- Ping quality to $PEER_PUBLIC_IP ----"
  ping -n -c 20 -i 0.2 -W 1 "$PEER_PUBLIC_IP" || warn "Ping loss or timeout was detected."
}

run_mtr_test() {
  log "---- MTR to $PEER_PUBLIC_IP ----"
  mtr -rwzc 20 "$PEER_PUBLIC_IP" || warn "MTR did not complete successfully."
}

run_pmtu_test() {
  log "---- Path MTU probe ----"
  local payload found=""
  for payload in 1472 1464 1452 1440 1420 1400 1380 1360 1320 1280 1240 1200; do
    if ping -n -c 2 -W 1 -M do -s "$payload" "$PEER_PUBLIC_IP" >/dev/null 2>&1; then
      found="$payload"
      break
    fi
  done

  if [[ -n "$found" ]]; then
    ok "Largest tested ICMP payload that passed: ${found} bytes; approximate IPv4 MTU: $((found + 28))."
  else
    warn "Even a 1200-byte payload with DF set failed. PMTU discovery or ICMP filtering may be a problem."
  fi
}

IPERF_FW_TAG="${APP}-iperf"
IPERF_TCP_RULE_ADDED=0
IPERF_UDP_RULE_ADDED=0

fw_allow_iperf() {
  local tcp_rule=(-p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)
  local udp_rule=(-p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)

  if ! iptables -C INPUT "${tcp_rule[@]}" 2>/dev/null; then
    iptables -I INPUT 1 "${tcp_rule[@]}"
    IPERF_TCP_RULE_ADDED=1
  fi
  if ! iptables -C INPUT "${udp_rule[@]}" 2>/dev/null; then
    iptables -I INPUT 1 "${udp_rule[@]}"
    IPERF_UDP_RULE_ADDED=1
  fi
}

fw_cleanup_iperf() {
  local tcp_rule=(-p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)
  local udp_rule=(-p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -m comment --comment "$IPERF_FW_TAG" -j ACCEPT)

  if (( IPERF_TCP_RULE_ADDED )); then
    iptables -D INPUT "${tcp_rule[@]}" 2>/dev/null || true
  fi
  if (( IPERF_UDP_RULE_ADDED )); then
    iptables -D INPUT "${udp_rule[@]}" 2>/dev/null || true
  fi
}

check_iperf_port_available() {
  if ss -ltnH "sport = :$IPERF_PORT" 2>/dev/null | grep -q .; then
    warn "TCP/$IPERF_PORT is already in use:"
    ss -ltnp "sport = :$IPERF_PORT" || true
    die "Choose another iperf3 port or stop the process using TCP/$IPERF_PORT."
  fi
}

start_iperf_listener() {
  install_deps
  prompt_public_ips
  prompt_iperf_settings
  check_iperf_port_available
  fw_allow_iperf

  trap 'exit 130' INT TERM
  trap 'fw_cleanup_iperf; log "Temporary iperf3 firewall rules removed."' EXIT

  echo
  log "iperf3 LISTENER mode is active."
  log "Peer allowed: $PEER_PUBLIC_IP"
  log "Listening on TCP/UDP port $IPERF_PORT"
  log "On the other server, choose: 'Run bidirectional sender test'."
  log "The sender will test LOCAL -> PEER and PEER -> LOCAL while this side keeps listening."
  log "Press Ctrl+C to stop the listener."
  echo

  iperf3 -s -p "$IPERF_PORT" --forceflush
}

run_iperf_case() {
  local name=$1
  shift
  local out="$LOG_DIR/iperf-${name}-$(date +%H%M%S).log"

  log "---- iperf3: $name ----"
  log "Command: iperf3 $*"
  set +e
  iperf3 "$@" 2>&1 | tee "$out"
  local rc=${PIPESTATUS[0]}
  set -e

  if (( rc != 0 )); then
    warn "$name failed with exit code $rc."
    return "$rc"
  fi

  log "Summary: $name"
  grep -E 'sender$|receiver$|SUM.*receiver$|SUM.*sender$' "$out" | tail -n 10 || tail -n 10 "$out"
}

run_bidirectional_sender_test() {
  install_deps
  prompt_public_ips
  prompt_iperf_settings
  show_env

  echo
  log "This host is the SENDER/TESTER. The peer must already be running iperf3 LISTENER mode."
  log "The normal tests send payload LOCAL -> PEER."
  log "The reverse (-R) tests send payload PEER -> LOCAL over the same control session."
  echo

  run_ping_test
  run_mtr_test
  run_pmtu_test

  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$PEER_PUBLIC_IP/$IPERF_PORT" 2>/dev/null; then
    ok "iperf3 control port $PEER_PUBLIC_IP:$IPERF_PORT is reachable."
  else
    die "Cannot reach TCP/$IPERF_PORT on $PEER_PUBLIC_IP. Start LISTENER mode on the peer and check its firewall/security group."
  fi

  run_iperf_case "tcp-local-to-peer" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20 -O 2 --get-server-output || true

  run_iperf_case "tcp-peer-to-local" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20 -O 2 -R --get-server-output || true

  run_iperf_case "udp-${TARGET_RATE}-local-to-peer" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20 -O 2 --get-server-output || true

  run_iperf_case "udp-${TARGET_RATE}-peer-to-local" \
    -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20 -O 2 -R --get-server-output || true

  log "---- Main interface counters after test ----"
  local main_iface
  main_iface="$(detect_main_iface)"
  [[ -n "$main_iface" ]] && ip -s link show dev "$main_iface" || true

  ok "Bidirectional throughput test completed."
  log "LOCAL -> PEER and PEER -> LOCAL were measured separately."
  log "If you want a literal process-role swap too, stop the current listener, start LISTENER here, and run SENDER on the other host."
}

run_path_diagnostics() {
  install_deps
  prompt_public_ips
  save_config
  show_env
  run_ping_test
  run_mtr_test
  run_pmtu_test
}

choose_site_role() {
  local x ans
  if [[ "$SITE_ROLE" == "iran" || "$SITE_ROLE" == "remote" ]]; then
    printf 'Saved GRE site role: %s\n' "$SITE_ROLE"
    read -r -p "Use the saved role? [Y/n]: " ans
    ans="${ans:-Y}"
    [[ "$ans" =~ ^[Yy]$ ]] && return
  fi

  echo
  echo "Select this server's GRE site role:"
  echo "  1) Iran gateway"
  echo "  2) Remote gateway"
  read -r -p "Selection: " x
  case "$x" in
    1) SITE_ROLE="iran" ;;
    2) SITE_ROLE="remote" ;;
    *) die "Invalid selection." ;;
  esac
}

default_tunnel_ips() {
  if [[ "$SITE_ROLE" == "iran" ]]; then
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.2/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.1"
  else
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.1/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.2"
  fi
}

validate_tunnel_settings() {
  valid_iface "$GRE_IFACE" || die "Invalid GRE interface name: $GRE_IFACE"
  valid_cidr "$LOCAL_TUN_CIDR" || die "Invalid local tunnel CIDR: $LOCAL_TUN_CIDR"
  valid_ipv4 "$PEER_TUN_IP" || die "Invalid peer tunnel IPv4: $PEER_TUN_IP"
  valid_mtu "$GRE_MTU" || die "Invalid GRE MTU: $GRE_MTU"
  valid_port "$FORWARD_PORT" || die "Invalid forwarding port: $FORWARD_PORT"
  [[ "$FORWARD_PROTO" == "udp" || "$FORWARD_PROTO" == "tcp" ]] || die "Forward protocol must be tcp or udp."
}

write_gre_helpers() {
  local fwd_up="" fwd_down=""

  if [[ "$SITE_ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    fwd_up=$(cat <<'EOF_FWD_UP'
PREROUTING_RULE=(-p "$FORWARD_PROTO" -d "$LOCAL_PUBLIC_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j DNAT --to-destination "$PEER_TUN_IP:$FORWARD_PORT")
POSTROUTING_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j MASQUERADE)
FORWARD_OUT_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j ACCEPT)
FORWARD_RETURN_RULE=(-i "$GRE_IFACE" -p "$FORWARD_PROTO" -s "$PEER_TUN_IP" --sport "$FORWARD_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$FWD_TAG" -j ACCEPT)

iptables -t nat -C PREROUTING "${PREROUTING_RULE[@]}" 2>/dev/null || iptables -t nat -A PREROUTING "${PREROUTING_RULE[@]}"
iptables -t nat -C POSTROUTING "${POSTROUTING_RULE[@]}" 2>/dev/null || iptables -t nat -A POSTROUTING "${POSTROUTING_RULE[@]}"
iptables -C FORWARD "${FORWARD_OUT_RULE[@]}" 2>/dev/null || iptables -A FORWARD "${FORWARD_OUT_RULE[@]}"
iptables -C FORWARD "${FORWARD_RETURN_RULE[@]}" 2>/dev/null || iptables -A FORWARD "${FORWARD_RETURN_RULE[@]}"
EOF_FWD_UP
)

    fwd_down=$(cat <<'EOF_FWD_DOWN'
PREROUTING_RULE=(-p "$FORWARD_PROTO" -d "$LOCAL_PUBLIC_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j DNAT --to-destination "$PEER_TUN_IP:$FORWARD_PORT")
POSTROUTING_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j MASQUERADE)
FORWARD_OUT_RULE=(-o "$GRE_IFACE" -p "$FORWARD_PROTO" -d "$PEER_TUN_IP" --dport "$FORWARD_PORT" -m comment --comment "$FWD_TAG" -j ACCEPT)
FORWARD_RETURN_RULE=(-i "$GRE_IFACE" -p "$FORWARD_PROTO" -s "$PEER_TUN_IP" --sport "$FORWARD_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$FWD_TAG" -j ACCEPT)

iptables -t nat -D PREROUTING "${PREROUTING_RULE[@]}" 2>/dev/null || true
iptables -t nat -D POSTROUTING "${POSTROUTING_RULE[@]}" 2>/dev/null || true
iptables -D FORWARD "${FORWARD_OUT_RULE[@]}" 2>/dev/null || true
iptables -D FORWARD "${FORWARD_RETURN_RULE[@]}" 2>/dev/null || true
EOF_FWD_DOWN
)
  fi

  cat > "$HELPER_UP" <<EOF_UP
#!/usr/bin/env bash
set -Eeuo pipefail
APP=$(printf '%q' "$APP")
LOCAL_PUBLIC_IP=$(printf '%q' "$LOCAL_PUBLIC_IP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
GRE_MTU=$(printf '%q' "$GRE_MTU")
LOCAL_TUN_CIDR=$(printf '%q' "$LOCAL_TUN_CIDR")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
GRE_TAG="${APP}-gre"
FWD_TAG="${APP}-forward"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
GRE_INPUT_RULE=(-p gre -s "$PEER_PUBLIC_IP" -m comment --comment "\$GRE_TAG" -j ACCEPT)
iptables -C INPUT "\${GRE_INPUT_RULE[@]}" 2>/dev/null || iptables -I INPUT 1 "\${GRE_INPUT_RULE[@]}"

ip link show "$GRE_IFACE" >/dev/null 2>&1 && ip tunnel del "$GRE_IFACE" || true
ip tunnel add "$GRE_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$PEER_PUBLIC_IP" ttl 255
ip addr replace "$LOCAL_TUN_CIDR" dev "$GRE_IFACE"
ip link set dev "$GRE_IFACE" mtu "$GRE_MTU"
ip link set dev "$GRE_IFACE" txqueuelen 2000
ip link set dev "$GRE_IFACE" up
sysctl -w "net.ipv4.conf.${GRE_IFACE}.rp_filter=0" >/dev/null 2>&1 || true

$fwd_up
EOF_UP

  cat > "$HELPER_DOWN" <<EOF_DOWN
#!/usr/bin/env bash
set +e
APP=$(printf '%q' "$APP")
LOCAL_PUBLIC_IP=$(printf '%q' "$LOCAL_PUBLIC_IP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
GRE_TAG="${APP}-gre"
FWD_TAG="${APP}-forward"

$fwd_down

ip tunnel del "$GRE_IFACE" 2>/dev/null || true
GRE_INPUT_RULE=(-p gre -s "$PEER_PUBLIC_IP" -m comment --comment "\$GRE_TAG" -j ACCEPT)
iptables -D INPUT "\${GRE_INPUT_RULE[@]}" 2>/dev/null || true
EOF_DOWN

  chmod 700 "$HELPER_UP" "$HELPER_DOWN"

  cat > "/etc/systemd/system/$SERVICE" <<EOF_SERVICE
[Unit]
Description=Persistent GRE link managed by $APP
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$HELPER_UP
ExecStop=$HELPER_DOWN

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

show_tunnel_status() {
  log "---- GRE status ----"
  if ! ip link show "$GRE_IFACE" >/dev/null 2>&1; then
    warn "GRE interface $GRE_IFACE does not exist."
    systemctl --no-pager --full status "$SERVICE" 2>/dev/null || true
    return 1
  fi

  ip -d link show "$GRE_IFACE" || true
  ip -br addr show "$GRE_IFACE" || true
  ip route show dev "$GRE_IFACE" || true

  log "---- GRE peer ping: $PEER_TUN_IP ----"
  if ping -n -c 10 -i 0.2 -W 1 "$PEER_TUN_IP"; then
    ok "GRE is up and the peer tunnel IP responds."
  else
    warn "The GRE interface exists, but the peer tunnel IP does not respond."
    warn "Configure GRE on the peer too and make sure IP protocol 47 (GRE) is not blocked by the provider, host firewall, or security group."
  fi

  if [[ "$SITE_ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    log "---- Service forwarding ----"
    log "$LOCAL_PUBLIC_IP:$FORWARD_PORT/$FORWARD_PROTO -> $PEER_TUN_IP:$FORWARD_PORT through $GRE_IFACE"
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
    iptables -t nat -L POSTROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
  fi
}

configure_gre() {
  install_deps
  choose_site_role
  prompt_public_ips
  default_tunnel_ips

  local x
  read -r -p "GRE interface name [$GRE_IFACE]: " x
  GRE_IFACE="${x:-$GRE_IFACE}"

  read -r -p "Local tunnel CIDR [$LOCAL_TUN_CIDR]: " x
  LOCAL_TUN_CIDR="${x:-$LOCAL_TUN_CIDR}"

  read -r -p "Peer tunnel IPv4 [$PEER_TUN_IP]: " x
  PEER_TUN_IP="${x:-$PEER_TUN_IP}"

  read -r -p "GRE MTU [$GRE_MTU]: " x
  GRE_MTU="${x:-$GRE_MTU}"

  if [[ "$SITE_ROLE" == "iran" ]]; then
    echo
    warn "Optional forwarding DNATs one public service port on the Iran gateway to the peer's tunnel IP."
    read -r -p "Enable service forwarding from Iran to the remote gateway? [Y/n]: " x
    x="${x:-Y}"
    if [[ "$x" =~ ^[Yy]$ ]]; then
      ENABLE_FORWARD="yes"
      read -r -p "Forward protocol [${FORWARD_PROTO:-udp}]: " x
      FORWARD_PROTO="${x:-${FORWARD_PROTO:-udp}}"
      read -r -p "Forward port [$FORWARD_PORT]: " x
      FORWARD_PORT="${x:-$FORWARD_PORT}"
    else
      ENABLE_FORWARD="no"
    fi
  else
    ENABLE_FORWARD="no"
  fi

  validate_tunnel_settings
  save_config
  show_env

  log "GRE itself is not encrypted. If you carry WireGuard inside GRE, the WireGuard payload remains encrypted by WireGuard."

  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    log "Stopping the existing GRE service before applying the new configuration."
    systemctl stop "$SERVICE" || true
  fi

  write_gre_helpers
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  sleep 1
  systemctl --no-pager --full status "$SERVICE" || true
  show_tunnel_status || true
  ok "Persistent GRE configuration applied. It will start automatically after reboot."
}

show_saved_gre_status() {
  install_deps
  [[ -n "$GRE_IFACE" ]] || die "No GRE interface is configured."
  [[ -n "$PEER_TUN_IP" ]] || die "No peer tunnel IP is configured."
  show_tunnel_status || true
}

remove_gre() {
  install_deps
  log "Stopping and disabling $SERVICE."
  systemctl disable --now "$SERVICE" 2>/dev/null || true

  if [[ -x "$HELPER_DOWN" ]]; then
    "$HELPER_DOWN" || true
  else
    ip tunnel del "$GRE_IFACE" 2>/dev/null || true
  fi

  rm -f "/etc/systemd/system/$SERVICE" "$HELPER_UP" "$HELPER_DOWN"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" 2>/dev/null || true
  ok "GRE service and helper files removed. Saved configuration was kept in $CONFIG."
}

print_header() {
  echo "============================================================"
  echo " GRE Link Tool v$VERSION"
  echo " Log: $LOG_FILE"
  echo "============================================================"
}

main_menu() {
  print_header
  echo
  echo "  1) Start iperf3 listener"
  echo "  2) Run bidirectional iperf3 sender test"
  echo "  3) Run path diagnostics only"
  echo "  4) Configure persistent GRE tunnel"
  echo "  5) Show GRE tunnel status"
  echo "  6) Remove GRE tunnel service"
  echo

  local mode
  read -r -p "Selection [1-6]: " mode
  case "$mode" in
    1) start_iperf_listener ;;
    2) run_bidirectional_sender_test ;;
    3) run_path_diagnostics ;;
    4) configure_gre ;;
    5) show_saved_gre_status ;;
    6) remove_gre ;;
    *) die "Invalid selection." ;;
  esac
}

main_menu
log "Log saved: $LOG_FILE"
