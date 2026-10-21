#!/usr/bin/env bash
# Stable entry point for first installation and all future updates.
# Development build 0.2.2-dev: inert install; live GRE requires isolated lab gate.
set -euo pipefail
umask 077
OWNER='smorad3363'
REPO='assistant-vps'
BRANCH='master'
FOLDER='gre-tun'
APP='/opt/gre-tun'
LAUNCH='/usr/local/bin/gre-tun'
UNIT='/etc/systemd/system/gre-tun.service'
OWN_MARK='.gre-tun-owned'
LOCAL_SOURCE=''
STAGE=''
BACKUP=''
HAD_EXISTING=0
PREVIOUS_LAUNCH=''
PREVIOUS_UNIT=''

log() { printf '[gre-tun] %s\n' "$*"; }
die() { printf '[gre-tun] Error: %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ -n "$STAGE" && -e "$STAGE" ]]; then rm -rf -- "$STAGE"; fi
  if [[ -n "$LOCAL_SOURCE" && -d "$LOCAL_SOURCE" && "${REMOVE_LOCAL_SOURCE:-0}" == 1 ]]; then rm -rf -- "$LOCAL_SOURCE"; fi
}
trap cleanup EXIT

[[ "${EUID}" == '0' ]] || die 'Run as root using sudo.'
command -v flock >/dev/null || die 'flock is required.'
exec 9>/run/gre-tun-installer.lock
flock -n 9 || die 'Another GRE Tunnel Manager installation is running.'
[[ -f /etc/os-release ]] || die 'Linux OS release file is missing.'
# shellcheck disable=SC1091
. /etc/os-release
[[ "$ID" == 'ubuntu' && ( "$VERSION_ID" == '22.04' || "$VERSION_ID" == '24.04' ) ]] || die 'Supported: Ubuntu 22.04 or 24.04.'
[[ -d /run/systemd/system ]] || die 'systemd is required.'
for existing in "$APP" "$LAUNCH" "$UNIT"; do
  if [[ -e "$existing" || -L "$existing" ]]; then
    [[ -f "$APP/$OWN_MARK" ]] || die "Non-owned installation conflict: $existing"
  fi
done
if [[ -e "$APP" ]]; then HAD_EXISTING=1; fi

if [[ "${1:-}" == '--local' ]]; then
  [[ $# -eq 2 && -d "$2" ]] || die 'Usage: install.sh --local /path/to/gre-tun'
  SRC="$(cd "$2" && pwd -P)"
else
  if ! command -v git >/dev/null; then
    log 'Installing git from official Ubuntu repositories.'
    export DEBIAN_FRONTEND=noninteractive
    timeout 180 apt-get update -qq || die 'Package index update failed.'
    timeout 240 apt-get install -y -qq git || die 'Git installation failed.'
  fi
  LOCAL_SOURCE="$(mktemp -d /tmp/gre-tun-source.XXXXXXXX)"
  REMOVE_LOCAL_SOURCE=1
  log 'Downloading source from the pinned repository and branch.'
  timeout 90 git clone --quiet --depth 1 --single-branch --branch "$BRANCH" \
    "https://github.com/$OWNER/$REPO.git" "$LOCAL_SOURCE/source" || die 'Git download failed.'
  SRC="$LOCAL_SOURCE/source/$FOLDER"
fi
[[ -f "$SRC/src/gre_tun/cli.py" && -f "$SRC/src/gre_tun/contract.py" && -f "$SRC/templates/gre-tun" ]] || die 'Incomplete or unready source; existing installation is unchanged.'
command -v python3 >/dev/null || die 'python3 must be installed from Ubuntu repositories.'
python3 - "$SRC" <<'PY' || die 'Source integrity validation failed.'
import ast
import hashlib
import json
import pathlib
import sys
base=pathlib.Path(sys.argv[1]).resolve()
manifest=base/'SHA256SUMS'
if not manifest.is_file(): raise SystemExit('Missing source checksum manifest.')
declared=set()
for line in manifest.read_text(encoding='utf-8').splitlines():
    digest, relative=line.split('  ',1)
    candidate=base/relative
    target=candidate.resolve()
    if not target.is_relative_to(base) or not candidate.is_file() or candidate.is_symlink():
        raise SystemExit('Unsafe source manifest entry.')
    if hashlib.sha256(candidate.read_bytes()).hexdigest()!=digest:
        raise SystemExit('Source file checksum mismatch.')
    declared.add(relative)
actual={q.relative_to(base).as_posix() for q in base.rglob('*')
        if q.is_file() and '.git' not in q.parts and '__pycache__' not in q.parts
        and q.name!='SHA256SUMS'}
if declared!=actual: raise SystemExit('Source inventory mismatch.')
for path in (base/'src/gre_tun').rglob('*.py'):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
for name in ('contracts/menus.json','contracts/ui.en.json'):
    json.loads((base/name).read_text(encoding='utf-8'))
print('[gre-tun] Source hashes, Python syntax and JSON validated.')
PY
log 'Running offline source tests before activating files.'
(
  cd "$SRC"
  PYTHONPATH="$SRC/src" python3 -m unittest discover -s tests -q
) || die 'Offline source tests failed; existing installation unchanged.'
missing=()
for req in 'ip:iproute2' 'tc:iproute2' 'ss:iproute2' 'nft:nftables' 'conntrack:conntrack' 'ping:iputils-ping' 'modprobe:kmod'; do
  bin="${req%%:*}"; pkg="${req#*:}"
  command -v "$bin" >/dev/null || missing+=("$pkg")
done
if (( ${#missing[@]} )); then
  export DEBIAN_FRONTEND=noninteractive
  log 'Installing missing official Ubuntu dependencies.'
  timeout 180 apt-get update -qq || die 'Dependency index refresh failed; no application files replaced.'
  timeout 240 apt-get install -y -qq "${missing[@]}" || die 'Dependency install failed; no application files replaced.'
fi
STAGE="$(mktemp -d /opt/.gre-tun-stage.XXXXXXXX)"
cp -a -- "$SRC/." "$STAGE/"
printf 'managed by gre-tun installer\n' > "$STAGE/$OWN_MARK"
chmod 600 "$STAGE/$OWN_MARK"
# Save a compact snapshot for rollback; only the application code is swapped.
if [[ $HAD_EXISTING == 1 ]]; then
  BACKUP="$(mktemp -d /opt/.gre-tun-previous.XXXXXXXX)"
  rmdir -- "$BACKUP"
  mv -- "$APP" "$BACKUP"
fi
if ! mv -- "$STAGE" "$APP"; then
  [[ -z "$BACKUP" ]] || mv -- "$BACKUP" "$APP"
  die 'Failed to activate application code.'
fi
STAGE=''
if [[ $HAD_EXISTING == 1 ]]; then
  PREVIOUS_LAUNCH="$(mktemp /tmp/gre-tun-launch.XXXXXXXX)"
  PREVIOUS_UNIT="$(mktemp /tmp/gre-tun-unit.XXXXXXXX)"
  cp -a "$LAUNCH" "$PREVIOUS_LAUNCH"
  cp -a "$UNIT" "$PREVIOUS_UNIT"
fi
if ! install -m 0755 "$APP/templates/gre-tun" "$LAUNCH" || ! install -m 0644 "$APP/templates/gre-tun.service" "$UNIT"; then
  rm -rf -- "$APP"
  [[ -z "$BACKUP" ]] || mv -- "$BACKUP" "$APP"
  if [[ -n "$PREVIOUS_LAUNCH" ]]; then cp -a "$PREVIOUS_LAUNCH" "$LAUNCH"; fi
  if [[ -n "$PREVIOUS_UNIT" ]]; then cp -a "$PREVIOUS_UNIT" "$UNIT"; fi
  die 'Failed to install the launcher or service.' 
fi
mkdir -p /etc/gre-tun /var/lib/gre-tun/state /var/log/gre-tun /run/gre-tun
chmod 700 /etc/gre-tun /var/lib/gre-tun/state /var/log/gre-tun /run/gre-tun
systemctl daemon-reload
if ! systemctl enable --now gre-tun.service >/dev/null; then
  log 'Warning: the statistics service did not start (inspect journalctl -u gre-tun).'
else
  systemctl try-restart gre-tun.service >/dev/null || log 'Warning: statistics service restart failed.'
fi
if [[ -n "$BACKUP" ]]; then rm -rf -- "$BACKUP"; fi
if [[ -n "$PREVIOUS_LAUNCH" ]]; then rm -f -- "$PREVIOUS_LAUNCH"; fi
if [[ -n "$PREVIOUS_UNIT" ]]; then rm -f -- "$PREVIOUS_UNIT"; fi
log 'Installed development build 0.2.2-dev. Existing config and traffic data were preserved.'
log 'Network activation is locked to a disposable lab pending VM acceptance tests.'
log 'Run: sudo gre-tun'
