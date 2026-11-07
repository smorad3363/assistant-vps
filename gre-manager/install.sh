#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID:-$(id -u)} == 0 ]] || { echo 'Run with sudo/root.' >&2; exit 1; }

# Keep configuration and histories outside application files.
SOURCE_REV="c3e1f40706d24567d35feb751b7de0969b270fc6"
RAW="https://raw.githubusercontent.com/smorad3363/assistant-vps/$SOURCE_REV/gre-manager"
for command_name in ip iptables ping python3 sha256sum curl systemctl modprobe sysctl flock; do
  if ! command -v "$command_name" >/dev/null; then
    if command -v apt-get >/dev/null; then
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iproute2 iptables iputils-ping python3 coreutils curl kmod procps util-linux >/dev/null
    elif command -v dnf >/dev/null; then
      dnf install -y -q iproute iptables iputils python3 coreutils curl kmod procps-ng util-linux
    elif command -v yum >/dev/null; then
      yum install -y -q iproute iptables iputils python3 coreutils curl kmod procps-ng util-linux
    else
      echo "Missing dependency: $command_name. Install Linux/systemd networking tools first." >&2
      exit 1
    fi
    break
  fi
done
[[ -d /run/systemd/system ]] || { echo 'A running systemd host is required.' >&2; exit 1; }
exec 9>/run/lock/gremgr-install.lock
flock -x 9
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for file in gremgr.sh pair.py gremgr-pair@.service gremgr-docker-sync.service gremgr-docker-sync.timer; do
  curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 "$RAW/$file" -o "$work/$file"
done
(cd "$work" && sha256sum -c <<'SUMS'
c9700fbec098f13cdc0a94e280ea7c1985603fcb1775722493b6200df7cf7d2a  gremgr.sh
0dd5c0ebcfbb19ea44044bbb52273ad4886987c1fcc4ff20180bc4d2bc385ae6  pair.py
e443deb74e913d519bfb0cc430cf5149eb60984b2f136e792e85d73234b0388b  gremgr-pair@.service
f8f5c2ee1df2acc9cf7b203e2d90f7e72aafb9d919a2b3060623f3de1383b32c  gremgr-docker-sync.service
9e2540abaa0d77aa6db77a0e2085149f90be7e0c97298dfc7ca5e50622f4cdd4  gremgr-docker-sync.timer
SUMS
)
bash -n "$work/gremgr.sh"
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$work/pair.py"
backup="/etc/gremgr/backups/install-$(date +%Y%m%d-%H%M%S)-$$"
install -d -m 700 "$backup"
targets=(/usr/local/sbin/gremgr /usr/local/sbin/gremgr-pair /etc/systemd/system/gremgr-pair@.service /etc/systemd/system/gremgr-docker-sync.service /etc/systemd/system/gremgr-docker-sync.timer)
files=(gremgr.sh pair.py gremgr-pair@.service gremgr-docker-sync.service gremgr-docker-sync.timer)
modes=(755 755 644 644 644)
for i in "${!targets[@]}"; do
  [[ ! -e ${targets[$i]} ]] || cp -a "${targets[$i]}" "$backup/${files[$i]}"
done
rollback_install() {
  local i
  for i in "${!targets[@]}"; do
    if [[ -f "$backup/${files[$i]}" ]]; then
      cp -a "$backup/${files[$i]}" "${targets[$i]}"
    else
      rm -f "${targets[$i]}"
    fi
  done
  systemctl daemon-reload || true
  echo "Installation failed; prior program files restored. Backup: $backup" >&2
}
trap 'rollback_install' ERR
for i in "${!targets[@]}"; do
  install -m "${modes[$i]}" "$work/${files[$i]}" "${targets[$i]}.new"
  mv -f "${targets[$i]}.new" "${targets[$i]}"
done
systemctl daemon-reload
systemctl enable --now gremgr-docker-sync.timer
/usr/local/sbin/gremgr-pair docker-sync-all
trap - ERR
flock -u 9
exec 9>&-
echo 'GRE Manager installed/updated. Configuration and history preserved.'
if [[ ${1:-} != --no-wizard ]]; then
  /usr/local/sbin/gremgr-pair wizard
fi
