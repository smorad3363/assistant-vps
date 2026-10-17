#!/usr/bin/env bash
# Permanent GRE Tunnel Manager install/update bootstrap.
# Safe to run repeatedly. Refuses incomplete or unverified releases.
set -euo pipefail
umask 077

OWNER='smorad3363'
REPO='assistant-vps'
BRANCH='master'
FOLDER='gre-tun'
APP='/opt/gre-tun'
LAUNCH='/usr/local/bin/gre-tun'
UNIT='/etc/systemd/system/gre-tun.service'
SOURCE_URL='https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-tun/src/gre_tun/cli.py'
TMP=''
STAGE=''
OLD=''

log() { printf '[gre-tun] %s\n' "$*"; }
die() { printf '[gre-tun] Error: %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ -n "$TMP" && -d "$TMP" ]]; then rm -rf -- "$TMP"; fi
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then rm -rf -- "$STAGE"; fi
}
trap cleanup EXIT
[[ "$EUID" -eq 0 ]] || die 'Root privileges required.'
command -v curl >/dev/null || die 'curl is required.'
# The bootstrap becomes live only after all app sources have been published.
if ! curl -fsSIL --connect-timeout 5 --max-time 12 "$SOURCE_URL" >/dev/null; then
  die 'Release source is not published yet. No host changes were made.'
fi
[[ -f /etc/os-release ]] || die 'Unknown operating system.'
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == 22.04 || "$VERSION_ID" == 24.04 ) ]] || die 'Ubuntu 22.04/24.04 required.'
[[ -d /run/systemd/system ]] || die 'systemd is required.'
for item in "$APP" "$LAUNCH" "$UNIT"; do
  if [[ -e "$item" || -L "$item" ]]; then
    [[ -f "$APP/.gre-tun-owned" ]] || die "Foreign installation at $item; refusing overwrite."
  fi
done
command -v git >/dev/null || die 'git is required (apt-get install git).'
command -v python3 >/dev/null || die 'python3 is required.'
TMP="$(mktemp -d /tmp/gre-tun-install.XXXXXXXX)"
timeout 90 git clone -q --depth 1 --single-branch --branch "$BRANCH" \
  "https://github.com/$OWNER/$REPO.git" "$TMP/source" || die 'Repository download failed.'
SRC="$TMP/source/$FOLDER"
for f in src/gre_tun/cli.py src/gre_tun/contract.py \
  templates/gre-tun templates/gre-tun.service contracts/menus.json \
  contracts/ui.en.json SHA256SUMS; do
  [[ -f "$SRC/$f" ]] || die "Release missing $f. No host changes made."
done
python3 - "$SRC" <<'PY' || die 'Release manifest validation failed.'
import ast, hashlib, json, pathlib, sys
r=pathlib.Path(sys.argv[1])
declared=set()
for line in (r/'SHA256SUMS').read_text().splitlines():
    digest, name=line.split('  ',1)
    p=(r/name).resolve()
    if not p.is_relative_to(r.resolve()) or not p.is_file():
        raise SystemExit('Unsafe source manifest entry')
    if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:
        raise SystemExit('Source checksum mismatch')
    declared.add(name)
actual={p.relative_to(r).as_posix() for p in r.rglob('*') if p.is_file()
        and '.git' not in p.parts and '__pycache__' not in p.parts
        and p.name!='SHA256SUMS'}
if actual != declared: raise SystemExit('Source file inventory mismatch')
for p in (r/'src/gre_tun').glob('*.py'):
    ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
for name in ('contracts/menus.json','contracts/ui.en.json'):
    json.loads((r/name).read_text())
print('[gre-tun] Source validated.')
PY
STAGE="$(mktemp -d /opt/.gre-tun-stage.XXXXXXXX)"
cp -a "$SRC/." "$STAGE/"
printf 'managed by gre-tun installer\n' > "$STAGE/.gre-tun-owned"
chmod 600 "$STAGE/.gre-tun-owned"
if [[ -d "$APP" ]]; then
  OLD="$(mktemp -d /opt/.gre-tun-prev.XXXXXXXX)"
  rmdir "$OLD"
  mv "$APP" "$OLD"
fi
if ! mv "$STAGE" "$APP"; then
  if [[ -n "$OLD" ]]; then mv "$OLD" "$APP"; fi
  die 'Unable to install source.'
fi
STAGE=''
if ! install -m 755 "$APP/templates/gre-tun" "$LAUNCH"; then
  die 'Could not install launcher. Manual recovery required.'
fi
if ! install -m 644 "$APP/templates/gre-tun.service" "$UNIT"; then
  die 'Could not install service. Manual recovery required.'
fi
mkdir -p /etc/gre-tun /var/lib/gre-tun/state /var/log/gre-tun /run/gre-tun
chmod 700 /etc/gre-tun /var/lib/gre-tun/state /var/log/gre-tun /run/gre-tun
systemctl daemon-reload
systemctl enable gre-tun.service >/dev/null
[[ -z "$OLD" ]] || rm -rf "$OLD"
log 'Installation/update finished. Saved settings and statistics were preserved.'
log 'Run: sudo gre-tun'
