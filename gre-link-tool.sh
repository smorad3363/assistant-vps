#!/usr/bin/env bash
set -Eeuo pipefail

APP="gre-link-tool"
VERSION="1.0"
CONFIG="/etc/${APP}.conf"
LOG_DIR="/var/log/${APP}"
DEFAULT_IPERF_PORT="5202"
DEFAULT_RATE="1G"
DEFAULT_MTU="1400"
DEFAULT_IFACE="gre-wg"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
ok()   { printf '[%s] [OK] %s\n' "$(date '+%F %T')" "$*"; }
warn() { printf '[%s] [WARN] %s\n' "$(date '+%F %T')" "$*"; }
err()  { printf '[%s] [ERR] %s\n' "$(date '+%F %T')" "$*" >&2; }

die() { err "$*"; exit 1; }

[[ ${EUID:-$(id -u)} -eq 0 ]] || die "این اسکریپت باید با root اجرا شود."

if [[ -f "$CONFIG" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG"
fi

ROLE="${ROLE:-}"
LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-}"
PEER_PUBLIC_IP="${PEER_PUBLIC_IP:-}"
IPERF_PORT="${IPERF_PORT:-$DEFAULT_IPERF_PORT}"
TARGET_RATE="${TARGET_RATE:-$DEFAULT_RATE}"
GRE_IFACE="${GRE_IFACE:-$DEFAULT_IFACE}"
GRE_MTU="${GRE_MTU:-$DEFAULT_MTU}"
LOCAL_TUN_CIDR="${LOCAL_TUN_CIDR:-}"
PEER_TUN_IP="${PEER_TUN_IP:-}"
FORWARD_PORT="${FORWARD_PORT:-51820}"
FORWARD_PROTO="${FORWARD_PROTO:-udp}"
ENABLE_FORWARD="${ENABLE_FORWARD:-yes}"

save_config() {
  umask 077
  cat > "$CONFIG" <<EOF
ROLE=$(printf '%q' "$ROLE")
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
EOF
}

valid_ipv4() {
  local ip=$1 IFS=. a b c d
  read -r a b c d <<< "$ip" || return 1
  [[ -n ${a:-} && -n ${b:-} && -n ${c:-} && -n ${d:-} ]] || return 1
  for n in "$a" "$b" "$c" "$d"; do
    [[ "$n" =~ ^[0-9]+$ ]] || return 1
    (( n >= 0 && n <= 255 )) || return 1
  done
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

install_deps() {
  local missing=()
  for c in ip ping iperf3 mtr tcpdump ss iptables awk sed grep timeout; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if (( ${#missing[@]} == 0 )); then
    ok "همه پیش‌نیازها نصب هستند."
    return
  fi

  log "پیش‌نیازهای لازم نصب می‌شوند: ${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y iproute2 iputils-ping iperf3 mtr-tiny tcpdump iptables procps
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng
  elif command -v yum >/dev/null 2>&1; then
    yum install -y iproute iputils iperf3 mtr tcpdump iptables procps-ng
  else
    die "Package manager پشتیبانی‌شده پیدا نشد. iproute2/ping/iperf3/mtr/tcpdump/iptables را نصب کن."
  fi
  ok "پیش‌نیازها نصب شدند."
}

choose_role() {
  if [[ "$ROLE" == "iran" || "$ROLE" == "kharej" ]]; then
    printf 'نقش ذخیره‌شده: %s\n' "$ROLE"
    read -r -p "همین نقش استفاده شود؟ [Y/n]: " ans
    ans="${ans:-Y}"
    [[ "$ans" =~ ^[Yy]$ ]] && return
  fi

  echo
  echo "این سرور کدام سمت است؟"
  echo "  1) Iran"
  echo "  2) Kharej"
  read -r -p "انتخاب: " x
  case "$x" in
    1) ROLE="iran" ;;
    2) ROLE="kharej" ;;
    *) die "انتخاب نامعتبر." ;;
  esac
}

resolve_public_ips() {
  local detected
  detected="$(detect_main_ip)"
  if valid_ipv4 "$detected"; then
    log "IP اصلی شناسایی‌شده: $detected"
    read -r -p "IP اصلی همین است؟ [$detected]: " x
    LOCAL_PUBLIC_IP="${x:-$detected}"
  else
    warn "IP اصلی به‌طور مطمئن تشخیص داده نشد."
    read -r -p "IP اصلی این سرور: " LOCAL_PUBLIC_IP
  fi
  valid_ipv4 "$LOCAL_PUBLIC_IP" || die "IP اصلی نامعتبر است: $LOCAL_PUBLIC_IP"

  if valid_ipv4 "${PEER_PUBLIC_IP:-}"; then
    read -r -p "IP سمت مقابل [$PEER_PUBLIC_IP]: " x
    PEER_PUBLIC_IP="${x:-$PEER_PUBLIC_IP}"
  else
    read -r -p "IP عمومی سمت مقابل: " PEER_PUBLIC_IP
  fi
  valid_ipv4 "$PEER_PUBLIC_IP" || die "IP سمت مقابل نامعتبر است: $PEER_PUBLIC_IP"

  read -r -p "پورت تست iperf3 [$IPERF_PORT]: " x
  IPERF_PORT="${x:-$IPERF_PORT}"
  [[ "$IPERF_PORT" =~ ^[0-9]+$ ]] && ((IPERF_PORT > 0 && IPERF_PORT < 65536)) || die "پورت نامعتبر."

  read -r -p "سرعت هدف تست UDP [$TARGET_RATE]: " x
  TARGET_RATE="${x:-$TARGET_RATE}"

  save_config
}

show_env() {
  local iface
  iface="$(detect_main_iface)"
  log "نسخه: $VERSION"
  log "Role=$ROLE"
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

test_ping() {
  log "---- Ping quality: $PEER_PUBLIC_IP ----"
  ping -n -c 50 -i 0.2 -W 1 "$PEER_PUBLIC_IP" || warn "Ping loss/timeout دیده شد."
}

test_mtr() {
  log "---- MTR: $PEER_PUBLIC_IP ----"
  mtr -rwzc 30 "$PEER_PUBLIC_IP" || warn "MTR کامل نشد."
}

test_pmtu() {
  log "---- Path MTU probe ----"
  local payload found=""
  for payload in 1472 1464 1452 1440 1420 1400 1380 1360 1320 1280 1240 1200; do
    if ping -n -c 2 -W 1 -M do -s "$payload" "$PEER_PUBLIC_IP" >/dev/null 2>&1; then
      found="$payload"
      break
    fi
  done
  if [[ -n "$found" ]]; then
    ok "بزرگ‌ترین payload تست‌شده که عبور کرد: $found bytes => IPv4 MTU تقریبی $((found+28))"
  else
    warn "حتی payload=1200 با DF عبور نکرد؛ احتمال PMTU/ICMP filtering وجود دارد."
  fi
}

FW_TCP_ADDED=0
FW_UDP_ADDED=0
FW_GRE_ADDED=0

fw_allow_test() {
  if ! iptables -C INPUT -p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT
    FW_TCP_ADDED=1
  fi
  if ! iptables -C INPUT -p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 1 -p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT
    FW_UDP_ADDED=1
  fi
}

fw_cleanup_test() {
  if (( FW_TCP_ADDED )); then
    iptables -D INPUT -p tcp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT 2>/dev/null || true
  fi
  if (( FW_UDP_ADDED )); then
    iptables -D INPUT -p udp -s "$PEER_PUBLIC_IP" --dport "$IPERF_PORT" -j ACCEPT 2>/dev/null || true
  fi
}

choose_free_iperf_port() {
  if ss -ltnH "sport = :$IPERF_PORT" 2>/dev/null | grep -q .; then
    warn "TCP/$IPERF_PORT در حال استفاده است:"
    ss -ltnp "sport = :$IPERF_PORT" || true
    read -r -p "پورت دیگر برای iperf3 [5209]: " x
    IPERF_PORT="${x:-5209}"
    save_config
  fi
}

test_server() {
  choose_free_iperf_port
  fw_allow_test
  trap 'fw_cleanup_test; log "قوانین موقت فایروال پاک شدند."' EXIT INT TERM

  log "Kharej test server آماده است."
  log "روی سرور Iran همین اسکریپت را اجرا کن: Test -> Iran"
  log "Listening: TCP/UDP $IPERF_PORT"
  log "برای توقف Ctrl+C بزن."
  iperf3 -s -p "$IPERF_PORT"
}

run_iperf_case() {
  local name=$1; shift
  local out="$LOG_DIR/iperf-${name}-$(date +%H%M%S).log"
  log "---- iperf3 $name ----"
  log "Command: iperf3 $*"
  set +e
  iperf3 "$@" 2>&1 | tee "$out"
  local rc=${PIPESTATUS[0]}
  set -e
  if (( rc != 0 )); then
    warn "$name شکست خورد (exit=$rc)."
    return "$rc"
  fi
  log "Summary ($name):"
  grep -E 'sender$|receiver$|SUM.*receiver$|SUM.*sender$' "$out" | tail -n 8 || tail -n 8 "$out"
}

test_client() {
  log "ابتدا raw path تست می‌شود؛ هیچ GRE یا Backpack برای این تست لازم نیست."
  if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$PEER_PUBLIC_IP/$IPERF_PORT" 2>/dev/null; then
    ok "TCP control port $PEER_PUBLIC_IP:$IPERF_PORT قابل دسترسی است."
  else
    warn "پورت $IPERF_PORT جواب نداد. مطمئن شو سمت Kharej Test را اجرا کرده و در حالت Server منتظر است."
  fi

  run_iperf_case "tcp-forward" -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20
  run_iperf_case "tcp-reverse" -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -P 4 -t 20 -R
  run_iperf_case "udp-${TARGET_RATE}-forward" -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20
  run_iperf_case "udp-${TARGET_RATE}-reverse" -c "$PEER_PUBLIC_IP" -p "$IPERF_PORT" -u -b "$TARGET_RATE" -l 1200 -t 20 -R

  log "---- Interface counters after test ----"
  ip -s link show dev "$(detect_main_iface)" || true
  ok "تست تمام شد. اگر receiver bitrate از $TARGET_RATE کمتر باشد یا Lost/Total بالا باشد، سقف/افت مسیر را همین خروجی نشان می‌دهد."
}

do_test() {
  install_deps
  choose_role
  resolve_public_ips
  show_env
  test_ping
  test_mtr
  test_pmtu
  if [[ "$ROLE" == "kharej" ]]; then
    test_server
  else
    test_client
  fi
}

default_tunnel_ips() {
  if [[ "$ROLE" == "iran" ]]; then
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.2/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.1"
  else
    [[ -n "$LOCAL_TUN_CIDR" ]] || LOCAL_TUN_CIDR="10.10.183.1/30"
    [[ -n "$PEER_TUN_IP" ]] || PEER_TUN_IP="10.10.183.2"
  fi
}

write_gre_helper() {
  local helper="/usr/local/sbin/${APP}-up"
  local down="/usr/local/sbin/${APP}-down"
  local fwd_block=""
  local fwd_down=""

  if [[ "$ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    fwd_block=$(cat <<EOF
iptables -t nat -C PREROUTING -p $FORWARD_PROTO -d $LOCAL_PUBLIC_IP --dport $FORWARD_PORT -j DNAT --to-destination $PEER_TUN_IP:$FORWARD_PORT 2>/dev/null || \
iptables -t nat -A PREROUTING -p $FORWARD_PROTO -d $LOCAL_PUBLIC_IP --dport $FORWARD_PORT -j DNAT --to-destination $PEER_TUN_IP:$FORWARD_PORT
iptables -t nat -C POSTROUTING -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j MASQUERADE
iptables -C FORWARD -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j ACCEPT
iptables -C FORWARD -p $FORWARD_PROTO -s $PEER_TUN_IP --sport $FORWARD_PORT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -p $FORWARD_PROTO -s $PEER_TUN_IP --sport $FORWARD_PORT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
EOF
)
    fwd_down=$(cat <<EOF
iptables -t nat -D PREROUTING -p $FORWARD_PROTO -d $LOCAL_PUBLIC_IP --dport $FORWARD_PORT -j DNAT --to-destination $PEER_TUN_IP:$FORWARD_PORT 2>/dev/null || true
iptables -t nat -D POSTROUTING -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -p $FORWARD_PROTO -d $PEER_TUN_IP --dport $FORWARD_PORT -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -p $FORWARD_PROTO -s $PEER_TUN_IP --sport $FORWARD_PORT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
EOF
)
  fi

  cat > "$helper" <<EOF
#!/usr/bin/env bash
set -e
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -C INPUT -p gre -s $PEER_PUBLIC_IP -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p gre -s $PEER_PUBLIC_IP -j ACCEPT
ip link show $GRE_IFACE >/dev/null 2>&1 && ip tunnel del $GRE_IFACE || true
ip tunnel add $GRE_IFACE mode gre local $LOCAL_PUBLIC_IP remote $PEER_PUBLIC_IP ttl 255
ip addr add $LOCAL_TUN_CIDR dev $GRE_IFACE
ip link set dev $GRE_IFACE mtu $GRE_MTU
ip link set dev $GRE_IFACE txqueuelen 2000
ip link set dev $GRE_IFACE up
$fwd_block
EOF

  cat > "$down" <<EOF
#!/usr/bin/env bash
set +e
$fwd_down
ip tunnel del $GRE_IFACE 2>/dev/null || true
iptables -D INPUT -p gre -s $PEER_PUBLIC_IP -j ACCEPT 2>/dev/null || true
EOF

  chmod 700 "$helper" "$down"

  cat > "/etc/systemd/system/${APP}.service" <<EOF
[Unit]
Description=Persistent GRE link managed by $APP
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$helper
ExecStop=$down

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP}.service"
}

show_tunnel_status() {
  log "---- GRE link status ----"
  ip -d link show "$GRE_IFACE" || true
  ip -br addr show "$GRE_IFACE" || true
  ip route show dev "$GRE_IFACE" || true
  log "---- GRE peer ping: $PEER_TUN_IP ----"
  if ping -n -c 20 -i 0.2 -W 1 "$PEER_TUN_IP"; then
    ok "GRE برقرار است و peer tunnel IP پاسخ می‌دهد."
  else
    warn "GRE interface ساخته شده ولی peer tunnel IP پاسخ نمی‌دهد."
    warn "سمت مقابل را هم با گزینه Tunnel اجرا کن و مطمئن شو Protocol 47/GRE در دیتاسنتر یا فایروال بلاک نیست."
  fi

  if [[ "$ROLE" == "iran" && "$ENABLE_FORWARD" == "yes" ]]; then
    log "---- Forwarding ----"
    log "$LOCAL_PUBLIC_IP:$FORWARD_PORT/$FORWARD_PROTO -> $PEER_TUN_IP:$FORWARD_PORT از طریق $GRE_IFACE"
    iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
    iptables -t nat -L POSTROUTING -n -v --line-numbers | grep -E "$FORWARD_PORT|Chain" || true
  fi
}

do_tunnel() {
  install_deps
  choose_role
  resolve_public_ips
  default_tunnel_ips

  read -r -p "نام interface GRE [$GRE_IFACE]: " x
  GRE_IFACE="${x:-$GRE_IFACE}"
  read -r -p "IP داخلی این سمت [$LOCAL_TUN_CIDR]: " x
  LOCAL_TUN_CIDR="${x:-$LOCAL_TUN_CIDR}"
  read -r -p "IP داخلی سمت مقابل [$PEER_TUN_IP]: " x
  PEER_TUN_IP="${x:-$PEER_TUN_IP}"
  read -r -p "GRE MTU [$GRE_MTU]: " x
  GRE_MTU="${x:-$GRE_MTU}"

  if [[ "$ROLE" == "iran" ]]; then
    echo
    warn "اگر Forward را فعال کنی، ترافیک ورودی همان پورت از IP ایران به GRE منتقل می‌شود."
    read -r -p "فوروارد سرویس از ایران به Kharej فعال شود؟ [Y/n]: " x
    x="${x:-Y}"
    if [[ "$x" =~ ^[Yy]$ ]]; then
      ENABLE_FORWARD="yes"
      read -r -p "پروتکل [udp]: " x
      FORWARD_PROTO="${x:-udp}"
      [[ "$FORWARD_PROTO" == "udp" || "$FORWARD_PROTO" == "tcp" ]] || die "Protocol باید udp یا tcp باشد."
      read -r -p "پورت [51820]: " x
      FORWARD_PORT="${x:-51820}"
    else
      ENABLE_FORWARD="no"
    fi
  else
    ENABLE_FORWARD="no"
  fi

  save_config
  show_env
  log "GRE هیچ رمزنگاری ندارد. اگر داخلش WireGuard حمل می‌کنی، payload خود WireGuard رمزنگاری‌شده است."

  write_gre_helper
  sleep 1
  systemctl --no-pager --full status "${APP}.service" || true
  show_tunnel_status
  ok "پیکربندی persistent شد و بعد از reboot هم بالا می‌آید."
}

echo "============================================================"
echo " GRE Link Tool v$VERSION"
echo " Log: $LOG_FILE"
echo "============================================================"
echo
echo "  1) Test    کیفیت مسیر + ping/mtr/MTU + TCP/UDP iperf (پیش‌فرض 1G)"
echo "  2) Tunnel  ساخت GRE persistent + تست + فوروارد اختیاری سرویس"
echo
read -r -p "انتخاب [1/2]: " MODE

case "$MODE" in
  1) do_test ;;
  2) do_tunnel ;;
  *) die "انتخاب نامعتبر." ;;
esac

log "Log saved: $LOG_FILE"