#!/usr/bin/env bash
set -Eeuo pipefail

# Permanent install/update command:
# curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-link-tool.sh -o /tmp/gre-link-tool.sh && sudo install -m 755 /tmp/gre-link-tool.sh /usr/local/bin/gre-link-tool && sudo gre-link-tool

APP="gre-link-tool"
VERSION="2.2"
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
    || ! grep -Fqx 'APP="gre-link-tool"' "$tmp"; then
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
    apt-get install -y iproute2 iputils-ping iperf3 mtr-tiny tcpdump iptables procps coreutils diffutils curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils diffutils curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng coreutils diffutils curl
  else
    die "No supported package manager was found. Install iproute2, ping, iperf3, mtr, tcpdump, iptables, procps, coreutils, diffutils and curl manually."
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
GRE_ICMP_TAG="${APP}-gre-health"
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

GRE_ICMP_RULE=(-i "$GRE_IFACE" -p icmp -s "$PEER_TUN_IP" -m comment --comment "\$GRE_ICMP_TAG" -j ACCEPT)
iptables -C INPUT "\${GRE_ICMP_RULE[@]}" 2>/dev/null || iptables -I INPUT 1 "\${GRE_ICMP_RULE[@]}"

$fwd_up
EOF_UP

  cat > "$HELPER_DOWN" <<EOF_DOWN
#!/usr/bin/env bash
set +e
APP=$(printf '%q' "$APP")
PEER_PUBLIC_IP=$(printf '%q' "$PEER_PUBLIC_IP")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FORWARD_PORT=$(printf '%q' "$FORWARD_PORT")
FORWARD_PROTO=$(printf '%q' "$FORWARD_PROTO")
GRE_TAG="${APP}-gre"
GRE_ICMP_TAG="${APP}-gre-health"
FWD_TAG="${APP}-forward"

$fwd_down

GRE_ICMP_RULE=(-i "$GRE_IFACE" -p icmp -s "$PEER_TUN_IP" -m comment --comment "\$GRE_ICMP_TAG" -j ACCEPT)
iptables -D INPUT "\${GRE_ICMP_RULE[@]}" 2>/dev/null || true
ip tunnel del "$GRE_IFACE" 2>/dev/null || true
GRE_INPUT_RULE=(-p gre -s "$PEER_PUBLIC_IP" -m comment --comment "\$GRE_TAG" -j ACCEPT)
iptables -D INPUT "\${GRE_INPUT_RULE[@]}" 2>/dev/null || true
EOF_DOWN

  {
    cat <<EOF_WATCHDOG_VARS
#!/usr/bin/env bash
set -u
APP=$(printf '%q' "$APP")
SERVICE=$(printf '%q' "$SERVICE")
GRE_IFACE=$(printf '%q' "$GRE_IFACE")
PEER_TUN_IP=$(printf '%q' "$PEER_TUN_IP")
FAIL_THRESHOLD=$(printf '%q' "$WATCHDOG_FAIL_THRESHOLD")
EOF_WATCHDOG_VARS
    cat <<'EOF_WATCHDOG_BODY'
STATE_FILE="/run/${APP}-watchdog.failures"

wd_log() {
  logger -t "${APP}-watchdog" -- "$*" 2>/dev/null || true
}

healthy=1
reason="healthy"
if ! systemctl is-active --quiet "$SERVICE"; then
  healthy=0
  reason="GRE service is not active"
elif ! ip link show "$GRE_IFACE" >/dev/null 2>&1; then
  healthy=0
  reason="GRE interface is missing"
elif ! ip -4 addr show dev "$GRE_IFACE" | grep -q 'inet '; then
  healthy=0
  reason="GRE interface has no IPv4 address"
elif ! ping -I "$GRE_IFACE" -n -c 2 -W 2 "$PEER_TUN_IP" >/dev/null 2>&1; then
  healthy=0
  reason="GRE peer tunnel IP is not responding"
fi

if (( healthy )); then
  printf '0\n' > "$STATE_FILE"
  exit 0
fi

failures=0
[[ -r "$STATE_FILE" ]] && read -r failures < "$STATE_FILE" || true
[[ "$failures" =~ ^[0-9]+$ ]] || failures=0
failures=$((failures + 1))
printf '%s\n' "$failures" > "$STATE_FILE"
wd_log "Health check failed ($failures/$FAIL_THRESHOLD): $reason"

if (( failures < FAIL_THRESHOLD )); then
  exit 0
fi

wd_log "Failure threshold reached; restarting $SERVICE automatically."
systemctl restart "$SERVICE" || true
sleep 3

if systemctl is-active --quiet "$SERVICE" \
  && ip link show "$GRE_IFACE" >/dev/null 2>&1 \
  && ping -I "$GRE_IFACE" -n -c 2 -W 2 "$PEER_TUN_IP" >/dev/null 2>&1; then
  printf '0\n' > "$STATE_FILE"
  wd_log "Automatic GRE repair succeeded."
else
  printf '%s\n' "$FAIL_THRESHOLD" > "$STATE_FILE"
  wd_log "GRE is still unhealthy after automatic restart; the watchdog will retry on the next interval."
fi
exit 0
EOF_WATCHDOG_BODY
  } > "$HELPER_WATCHDOG"

  chmod 700 "$HELPER_UP" "$HELPER_DOWN" "$HELPER_WATCHDOG"

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
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF_SERVICE

  cat > "/etc/systemd/system/$WATCHDOG_SERVICE" <<EOF_WD_SERVICE
[Unit]
Description=GRE health check and automatic repair for $APP
After=$SERVICE
Wants=$SERVICE

[Service]
Type=oneshot
ExecStart=$HELPER_WATCHDOG
EOF_WD_SERVICE

  cat > "/etc/systemd/system/$WATCHDOG_TIMER" <<EOF_WD_TIMER
[Unit]
Description=Periodic GRE watchdog for $APP

[Timer]
OnActiveSec=15s
OnUnitActiveSec=${WATCHDOG_INTERVAL}s
AccuracySec=3s
Persistent=true
Unit=$WATCHDOG_SERVICE

[Install]
WantedBy=timers.target
EOF_WD_TIMER
}

apply_gre_configuration() {
  log "Applying GRE configuration and watchdog units."
  systemctl disable --now "$WATCHDOG_TIMER" 2>/dev/null || true
  systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true
  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    systemctl stop "$SERVICE" || true
  fi

  write_gre_helpers
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"

  if [[ "$WATCHDOG_ENABLED" == "yes" ]]; then
    systemctl enable --now "$WATCHDOG_TIMER"
    ok "Watchdog enabled: every ${WATCHDOG_INTERVAL}s, repair after ${WATCHDOG_FAIL_THRESHOLD} consecutive failures."
  else
    systemctl disable --now "$WATCHDOG_TIMER" 2>/dev/null || true
    log "Watchdog is disabled by configuration."
  fi
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
  if ping -I "$GRE_IFACE" -n -c 5 -i 0.2 -W 1 "$PEER_TUN_IP"; then
    ok "GRE is up and the peer tunnel IP responds."
  else
    warn "The GRE interface exists, but the peer tunnel IP does not respond."
    warn "The watchdog will attempt automatic recovery when enabled. Also verify GRE/IP protocol 47 is allowed end-to-end."
  fi

  if [[ "$WATCHDOG_ENABLED" == "yes" ]]; then
    if systemctl is-active --quiet "$WATCHDOG_TIMER" 2>/dev/null; then
      ok "Watchdog timer is active (${WATCHDOG_INTERVAL}s interval, threshold $WATCHDOG_FAIL_THRESHOLD)."
    else
      warn "Watchdog is enabled in config but its timer is not active. Re-apply or edit the tunnel configuration."
    fi
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

  echo
  prompt_watchdog_settings
  validate_tunnel_settings
  save_config
  show_env
  show_saved_tunnel_config

  log "GRE itself is not encrypted. If you carry WireGuard inside GRE, the WireGuard payload remains encrypted by WireGuard."
  apply_gre_configuration
  sleep 1
  systemctl --no-pager --full status "$SERVICE" || true
  show_tunnel_status || true
  ok "Persistent GRE configuration applied. Tunnel startup and watchdog are automatic after reboot."
}

edit_gre_configuration() {
  install_deps
  [[ -f "$CONFIG" ]] || die "No saved configuration exists. Configure the GRE tunnel first."

  show_saved_tunnel_config
  local x

  read -r -p "Site role (iran/remote) [$SITE_ROLE]: " x
  SITE_ROLE="${x:-$SITE_ROLE}"
  read -r -p "Local public IPv4 [$LOCAL_PUBLIC_IP]: " x
  LOCAL_PUBLIC_IP="${x:-$LOCAL_PUBLIC_IP}"
  read -r -p "Peer public IPv4 [$PEER_PUBLIC_IP]: " x
  PEER_PUBLIC_IP="${x:-$PEER_PUBLIC_IP}"
  read -r -p "GRE interface name [$GRE_IFACE]: " x
  GRE_IFACE="${x:-$GRE_IFACE}"
  read -r -p "Local tunnel CIDR [$LOCAL_TUN_CIDR]: " x
  LOCAL_TUN_CIDR="${x:-$LOCAL_TUN_CIDR}"
  read -r -p "Peer tunnel IPv4 [$PEER_TUN_IP]: " x
  PEER_TUN_IP="${x:-$PEER_TUN_IP}"
  read -r -p "GRE MTU [$GRE_MTU]: " x
  GRE_MTU="${x:-$GRE_MTU}"
  read -r -p "iperf3 test port [$IPERF_PORT]: " x
  IPERF_PORT="${x:-$IPERF_PORT}"
  read -r -p "UDP target rate [$TARGET_RATE]: " x
  TARGET_RATE="${x:-$TARGET_RATE}"

  if [[ "$SITE_ROLE" == "iran" ]]; then
    read -r -p "Enable forwarding? [$ENABLE_FORWARD] (yes/no): " x
    ENABLE_FORWARD="${x:-$ENABLE_FORWARD}"
    if [[ "$ENABLE_FORWARD" == "yes" ]]; then
      read -r -p "Forward protocol [$FORWARD_PROTO] (tcp/udp): " x
      FORWARD_PROTO="${x:-$FORWARD_PROTO}"
      read -r -p "Forward port [$FORWARD_PORT]: " x
      FORWARD_PORT="${x:-$FORWARD_PORT}"
    fi
  else
    ENABLE_FORWARD="no"
  fi

  read -r -p "Enable watchdog? [$WATCHDOG_ENABLED] (yes/no): " x
  WATCHDOG_ENABLED="${x:-$WATCHDOG_ENABLED}"
  if [[ "$WATCHDOG_ENABLED" == "yes" ]]; then
    read -r -p "Watchdog interval seconds [$WATCHDOG_INTERVAL]: " x
    WATCHDOG_INTERVAL="${x:-$WATCHDOG_INTERVAL}"
    read -r -p "Watchdog failure threshold [$WATCHDOG_FAIL_THRESHOLD]: " x
    WATCHDOG_FAIL_THRESHOLD="${x:-$WATCHDOG_FAIL_THRESHOLD}"
  fi

  validate_tunnel_settings
  save_config
  show_saved_tunnel_config
  apply_gre_configuration
  sleep 1
  show_tunnel_status || true
  ok "Saved tunnel configuration was updated and applied automatically."
}

show_saved_gre_status() {
  install_deps
  [[ -n "$GRE_IFACE" ]] || die "No GRE interface is configured."
  [[ -n "$PEER_TUN_IP" ]] || die "No peer tunnel IP is configured."
  show_saved_tunnel_config
  show_tunnel_status || true
}

remove_gre() {
  install_deps
  log "Stopping and disabling GRE tunnel and watchdog services."
  systemctl disable --now "$WATCHDOG_TIMER" 2>/dev/null || true
  systemctl stop "$WATCHDOG_SERVICE" 2>/dev/null || true
  systemctl disable --now "$SERVICE" 2>/dev/null || true

  if [[ -x "$HELPER_DOWN" ]]; then
    "$HELPER_DOWN" || true
  else
    ip tunnel del "$GRE_IFACE" 2>/dev/null || true
  fi

  rm -f "/etc/systemd/system/$SERVICE" \
        "/etc/systemd/system/$WATCHDOG_SERVICE" \
        "/etc/systemd/system/$WATCHDOG_TIMER" \
        "$HELPER_UP" "$HELPER_DOWN" "$HELPER_WATCHDOG" \
        "/run/${APP}-watchdog.failures"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE" "$WATCHDOG_SERVICE" 2>/dev/null || true
  ok "GRE service, watchdog, and helper files removed. Saved configuration was kept in $CONFIG."
}


debug_cmd() {
  local report=$1 title=$2
  shift 2
  local rc
  {
    printf '\n================================================================\n%s\n================================================================\n' "$title"
    printf 'Command:'; printf ' %q' "$@"; printf '\n'
  } >> "$report"
  set +e
  "$@" >> "$report" 2>&1
  rc=$?
  set -e
  printf '\n[exit_code=%s]\n' "$rc" >> "$report"
}

debug_shell() {
  local report=$1 title=$2 cmd=$3 rc
  {
    printf '\n================================================================\n%s\n================================================================\n' "$title"
    printf 'Shell: %s\n' "$cmd"
  } >> "$report"
  set +e
  bash -o pipefail -c "$cmd" >> "$report" 2>&1
  rc=$?
  set -e
  printf '\n[exit_code=%s]\n' "$rc" >> "$report"
}

generate_debug_report() {
  local stamp report main_iface cmd
  stamp="$(date '+%Y%m%d-%H%M%S')"
  report="$LOG_DIR/debug-$stamp.txt"
  main_iface="$(detect_main_iface || true)"
  umask 077
  : > "$report"
  chmod 600 "$report"

  {
    echo "GRE Link Tool - Full Troubleshooting Report"
    echo "Generated: $(date -Is 2>/dev/null || date)"
    echo "Generated UTC: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Tool version: $VERSION"
    echo "Installed path: $INSTALL_PATH"
    echo
    echo "This report contains network addresses, routes, ports, firewall/NAT rules,"
    echo "service status and recent GRE Link Tool logs."
    echo "It intentionally avoids shell history, environment dumps, passwords,"
    echo "tokens, SSH/WireGuard private keys and full packet payloads."
    echo
    echo "---- Saved GRE Link Tool settings ----"
    printf 'SITE_ROLE=%q\n' "$SITE_ROLE"
    printf 'LOCAL_PUBLIC_IP=%q\n' "$LOCAL_PUBLIC_IP"
    printf 'PEER_PUBLIC_IP=%q\n' "$PEER_PUBLIC_IP"
    printf 'GRE_IFACE=%q\n' "$GRE_IFACE"
    printf 'LOCAL_TUN_CIDR=%q\n' "$LOCAL_TUN_CIDR"
    printf 'PEER_TUN_IP=%q\n' "$PEER_TUN_IP"
    printf 'GRE_MTU=%q\n' "$GRE_MTU"
    printf 'IPERF_PORT=%q\n' "$IPERF_PORT"
    printf 'TARGET_RATE=%q\n' "$TARGET_RATE"
    printf 'ENABLE_FORWARD=%q\n' "$ENABLE_FORWARD"
    printf 'FORWARD_PROTO=%q\n' "$FORWARD_PROTO"
    printf 'FORWARD_PORT=%q\n' "$FORWARD_PORT"
    printf 'WATCHDOG_ENABLED=%q\n' "$WATCHDOG_ENABLED"
    printf 'WATCHDOG_INTERVAL=%q\n' "$WATCHDOG_INTERVAL"
    printf 'WATCHDOG_FAIL_THRESHOLD=%q\n' "$WATCHDOG_FAIL_THRESHOLD"
  } >> "$report"

  debug_shell "$report" "SCRIPT / CONFIG FILE METADATA" \
    "ls -l $(printf '%q' "$INSTALL_PATH") $(printf '%q' "$CONFIG") 2>&1 || true; sha256sum $(printf '%q' "$INSTALL_PATH") 2>/dev/null || true"
  debug_shell "$report" "OS / KERNEL / UPTIME / RESOURCES" \
    'cat /etc/os-release 2>/dev/null || true; echo; uname -a; echo; uptime; echo; systemd-detect-virt 2>/dev/null || true; echo; free -h 2>/dev/null || true; echo; df -hT / 2>/dev/null || true'
  debug_shell "$report" "NETWORK TOOL VERSIONS" \
    'for c in ip iptables nft ping iperf3 mtr tcpdump curl systemctl journalctl sysctl ethtool; do echo "--- $c ---"; command -v "$c" 2>/dev/null || echo MISSING; case "$c" in ip) ip -Version 2>&1;; iptables) iptables --version 2>&1;; nft) nft --version 2>&1;; ping) ping -V 2>&1 | head -n 2;; iperf3) iperf3 --version 2>&1 | head -n 4;; mtr) mtr --version 2>&1 | head -n 2;; tcpdump) tcpdump --version 2>&1 | head -n 2;; curl) curl --version 2>&1 | head -n 3;; systemctl|journalctl) "$c" --version 2>&1 | head -n 4;; sysctl) sysctl --version 2>&1 | head -n 2;; ethtool) ethtool --version 2>&1 | head -n 2;; esac; echo; done'

  debug_cmd "$report" "GRE SERVICE STATUS" systemctl --no-pager --full status "$SERVICE"
  debug_cmd "$report" "WATCHDOG SERVICE STATUS" systemctl --no-pager --full status "$WATCHDOG_SERVICE"
  debug_cmd "$report" "WATCHDOG TIMER STATUS" systemctl --no-pager --full status "$WATCHDOG_TIMER"
  debug_shell "$report" "SYSTEMD UNIT DEFINITIONS / ENABLE STATES" \
    "for u in $(printf '%q' "$SERVICE") $(printf '%q' "$WATCHDOG_SERVICE") $(printf '%q' "$WATCHDOG_TIMER"); do echo \"===== \$u =====\"; systemctl is-enabled \"\$u\" 2>&1 || true; systemctl is-active \"\$u\" 2>&1 || true; systemctl show \"\$u\" -p LoadState -p ActiveState -p SubState -p Result -p ExecMainStatus -p FragmentPath -p UnitFileState 2>&1 || true; systemctl cat \"\$u\" 2>&1 || true; echo; done; systemctl list-timers --all --no-pager $(printf '%q' "$WATCHDOG_TIMER") 2>&1 || true; echo; cat /run/$APP-watchdog.failures 2>/dev/null || echo 'No watchdog failure state file.'"

  debug_cmd "$report" "GRE SERVICE JOURNAL - LAST 24H" journalctl -u "$SERVICE" --since "-24 hours" -n 500 --no-pager -o short-iso
  debug_cmd "$report" "WATCHDOG SERVICE JOURNAL - LAST 24H" journalctl -u "$WATCHDOG_SERVICE" --since "-24 hours" -n 500 --no-pager -o short-iso
  debug_cmd "$report" "WATCHDOG LOGGER JOURNAL - LAST 24H" journalctl -t "$APP-watchdog" --since "-24 hours" -n 500 --no-pager -o short-iso

  debug_shell "$report" "GENERATED GRE HELPERS" \
    "for f in $(printf '%q' "$HELPER_UP") $(printf '%q' "$HELPER_DOWN") $(printf '%q' "$HELPER_WATCHDOG"); do echo \"===== \$f =====\"; if [[ -r \"\$f\" ]]; then sed -n '1,320p' \"\$f\"; else echo MISSING; fi; echo; done"

  debug_cmd "$report" "INTERFACE SUMMARY" ip -br addr
  debug_cmd "$report" "LINK DETAILS / COUNTERS" ip -d -s link show
  debug_cmd "$report" "IPv4 ADDRESSES" ip -4 addr show
  debug_shell "$report" "GRE TUNNELS" 'ip -d tunnel show 2>&1 || true; echo; ip -s tunnel show 2>&1 || true'
  debug_cmd "$report" "ROUTING TABLES" ip -4 route show table all
  debug_cmd "$report" "IP RULES" ip -4 rule show
  debug_cmd "$report" "NEIGHBORS" ip neigh show
  debug_cmd "$report" "SOCKET SUMMARY" ss -s
  debug_cmd "$report" "LISTENING SOCKETS" ss -lntup

  if valid_ipv4 "$PEER_PUBLIC_IP"; then
    debug_cmd "$report" "ROUTE TO PEER PUBLIC IP" ip -4 route get "$PEER_PUBLIC_IP"
    debug_cmd "$report" "PING PEER PUBLIC IP" ping -n -c 5 -W 1 "$PEER_PUBLIC_IP"
    command -v mtr >/dev/null 2>&1 && debug_cmd "$report" "MTR PEER PUBLIC IP" mtr -rwzc 10 "$PEER_PUBLIC_IP"
    cmd="for s in 1472 1464 1452 1440 1420 1400 1380 1360 1320 1280 1240 1200; do printf 'payload=%s: ' \"\$s\"; ping -n -c 1 -W 1 -M do -s \"\$s\" $(printf '%q' "$PEER_PUBLIC_IP") >/dev/null 2>&1 && echo PASS || echo FAIL; done"
    debug_shell "$report" "PUBLIC PATH MTU MATRIX" "$cmd"
  fi

  if valid_ipv4 "$PEER_TUN_IP"; then
    debug_cmd "$report" "ROUTE TO PEER TUNNEL IP" ip -4 route get "$PEER_TUN_IP"
    if valid_iface "$GRE_IFACE" && ip link show "$GRE_IFACE" >/dev/null 2>&1; then
      debug_cmd "$report" "GRE INTERFACE DETAIL" ip -d -s link show dev "$GRE_IFACE"
      debug_cmd "$report" "PING PEER TUNNEL IP THROUGH GRE" ping -I "$GRE_IFACE" -n -c 8 -W 1 "$PEER_TUN_IP"
      cmd="for s in 1372 1360 1340 1320 1300 1280 1240 1200; do printf 'payload=%s: ' \"\$s\"; ping -I $(printf '%q' "$GRE_IFACE") -n -c 1 -W 1 -M do -s \"\$s\" $(printf '%q' "$PEER_TUN_IP") >/dev/null 2>&1 && echo PASS || echo FAIL; done"
      debug_shell "$report" "GRE PATH MTU MATRIX" "$cmd"
    fi
  fi

  debug_shell "$report" "RELEVANT SYSCTLS / GRE MODULES" \
    "sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects 2>&1 || true; [[ -n $(printf '%q' "$main_iface") ]] && sysctl net.ipv4.conf.$main_iface.rp_filter 2>&1 || true; [[ -n $(printf '%q' "$GRE_IFACE") ]] && sysctl net.ipv4.conf.$GRE_IFACE.rp_filter 2>&1 || true; echo; lsmod 2>/dev/null | grep -E '^(ip_gre|gre|ip_tunnel)' || true"

  debug_cmd "$report" "IPTABLES FILTER RULES / COUNTERS" iptables -L -n -v --line-numbers
  debug_cmd "$report" "IPTABLES FILTER RULE SPEC" iptables -S
  debug_cmd "$report" "IPTABLES NAT RULES / COUNTERS" iptables -t nat -L -n -v --line-numbers
  debug_cmd "$report" "IPTABLES NAT RULE SPEC" iptables -t nat -S
  debug_cmd "$report" "IPTABLES MANGLE RULE SPEC" iptables -t mangle -S
  command -v nft >/dev/null 2>&1 && debug_shell "$report" "NFTABLES RULESET - FIRST 2500 LINES" "nft list ruleset 2>&1 | sed -n '1,2500p'"
  [[ -n "$main_iface" ]] && command -v ethtool >/dev/null 2>&1 && debug_cmd "$report" "MAIN NIC OFFLOAD FEATURES" ethtool -k "$main_iface"
  command -v dmesg >/dev/null 2>&1 && debug_shell "$report" "RELEVANT KERNEL MESSAGES" "dmesg -T 2>&1 | grep -Ei 'gre|ip_tunnel|network|link|route|mtu|icmp|martian|rp_filter|netfilter' | tail -n 300"

  if command -v tcpdump >/dev/null 2>&1 && valid_ipv4 "$PEER_PUBLIC_IP"; then
    cmd="tmp=\$(mktemp /tmp/$APP.tcpdump.XXXXXX); timeout 8 tcpdump -ni any -nn -s 64 -c 80 -tttt 'proto 47 or icmp' >\"\$tmp\" 2>&1 & cap=\$!; sleep 1; ping -n -c 3 -W 1 $(printf '%q' "$PEER_PUBLIC_IP") >/dev/null 2>&1 || true;"
    if valid_ipv4 "$PEER_TUN_IP" && valid_iface "$GRE_IFACE"; then
      cmd+=" ip link show $(printf '%q' "$GRE_IFACE") >/dev/null 2>&1 && ping -I $(printf '%q' "$GRE_IFACE") -n -c 4 -W 1 $(printf '%q' "$PEER_TUN_IP") >/dev/null 2>&1 || true;"
    fi
    cmd+=" wait \"\$cap\" 2>/dev/null || true; cat \"\$tmp\"; rm -f \"\$tmp\""
    debug_shell "$report" "SHORT GRE/ICMP PACKET-HEADER PROBE - 8 SECONDS" "$cmd"
  fi

  debug_shell "$report" "RECENT GRE LINK TOOL LOGS - 5 FILES / 350 LINES EACH" \
    "count=0; while IFS= read -r f; do echo \"===== \$f =====\"; tail -n 350 \"\$f\" 2>&1 || true; echo; count=\$((count+1)); (( count >= 5 )) && break; done < <(find $(printf '%q' "$LOG_DIR") -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -nr | cut -d' ' -f2-)"

  {
    echo
    echo "================================================================"
    echo "END OF REPORT"
    echo "================================================================"
    echo "Report path: $report"
    echo "Generated: $(date -Is 2>/dev/null || date)"
  } >> "$report"

  ok "Full debug report created: $report"
  log "Send this single file for troubleshooting."
  warn "It contains IPs, routes, ports and firewall details; keep it within a trusted support context."
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
  echo "  4) Configure persistent GRE tunnel + watchdog"
  echo "  5) Edit saved tunnel/ports/watchdog configuration"
  echo "  6) Show GRE tunnel status"
  echo "  7) Remove GRE tunnel service + watchdog"
  echo "  8) Generate full debug report for troubleshooting"
  echo

  local mode
  read -r -p "Selection [1-8]: " mode
  case "$mode" in
    1) start_iperf_listener ;;
    2) run_bidirectional_sender_test ;;
    3) run_path_diagnostics ;;
    4) configure_gre ;;
    5) edit_gre_configuration ;;
    6) show_saved_gre_status ;;
    7) remove_gre ;;
    8) generate_debug_report ;;
    *) die "Invalid selection." ;;
  esac
}

auto_update_or_install "$@"

case "${1:-}" in
  --debug|--debug-report|debug)
    generate_debug_report
    exit 0
    ;;
esac

main_menu
log "Log saved: $LOG_FILE"
